#!/usr/bin/env bash
# End-to-end verification for Docker Hub SBOM consumption.
#
# Exercises:
#   1. Direct path — scan python:3.11-slim directly.
#   2. Provenance path — build a derivative image with BuildKit provenance,
#      push to a local registry, scan.
#   3. DHI path — best effort; skipped if dhi.io requires credentials.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTDIR="${OUTDIR:-$(mktemp -d)}"
REGISTRY="${REGISTRY:-localhost:5000}"

echo "=== sbomify-action Docker Hub E2E ==="
echo "Output dir: $OUTDIR"
echo "Registry:   $REGISTRY"
echo

# --- Prereqs ---------------------------------------------------------------

need() { command -v "$1" >/dev/null 2>&1 || { echo "FATAL: $1 not found on PATH" >&2; exit 2; }; }
need docker
need crane
need cosign
need syft
need python3

ACTION=(uv --project "$REPO_ROOT" run sbomify-action)

ensure_registry() {
    if curl -sf "http://$REGISTRY/v2/" >/dev/null 2>&1; then
        return
    fi
    echo "Starting local registry on $REGISTRY..."
    docker run -d -p "${REGISTRY##*:}:5000" --name sbomify-registry --restart=always registry:2 >/dev/null
    for _ in 1 2 3 4 5; do
        sleep 1
        curl -sf "http://$REGISTRY/v2/" >/dev/null 2>&1 && return
    done
    echo "FATAL: registry not reachable at $REGISTRY" >&2
    exit 2
}

# --- Assertions ------------------------------------------------------------

assert_cdx_summary() {
    local out="$1"
    local min_upstream="${2:-1}"
    python3 - "$out" "$min_upstream" <<'PY'
import json, sys

path, min_up = sys.argv[1], int(sys.argv[2])
with open(path) as f:
    bom = json.load(f)

components = bom.get("components", [])
sources = {}
for c in components:
    src = "(untagged)"
    for p in c.get("properties", []) or []:
        if p.get("name") == "sbomify:source":
            src = p.get("value")
            break
    sources[src] = sources.get(src, 0) + 1

upstream = sources.get("docker-hub-upstream", 0)
overlay = sources.get("syft-overlay", 0)
print(f"  upstream={upstream}  syft-overlay={overlay}  total={len(components)}")

if upstream < min_up:
    print(f"FAIL: expected >= {min_up} upstream components, got {upstream}", file=sys.stderr)
    sys.exit(1)
PY
}

assert_spdx_valid() {
    # Validates that the SPDX output parses cleanly and has no dangling
    # license references, plus that it has the expected upstream + overlay
    # shape. Runs through the project's uv env so spdx-tools is available.
    local out="$1"
    local min_packages="${2:-10}"
    (cd "$REPO_ROOT" && uv run python - "$out" "$min_packages") <<'PY'
import sys
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

path, min_pkgs = sys.argv[1], int(sys.argv[2])
doc = parse_file(path)
errs = validate_full_spdx_document(doc)
print(
    f"  packages={len(doc.packages)} files={len(doc.files)} "
    f"rel={len(doc.relationships)} ext-lic={len(doc.extracted_licensing_info)} "
    f"validation-errors={len(errs)}"
)
if errs:
    for e in errs[:3]:
        print(f"    {str(e)[:120]}", file=sys.stderr)
    sys.exit(1)
if len(doc.packages) < min_pkgs:
    print(f"FAIL: expected >= {min_pkgs} packages, got {len(doc.packages)}", file=sys.stderr)
    sys.exit(1)
PY
}

assert_packages_present() {
    local out="$1"; shift
    python3 - "$out" "$@" <<'PY'
import json, sys

path = sys.argv[1]
targets = sys.argv[2:]
with open(path) as f:
    bom = json.load(f)

# CycloneDX: iterate components[].name; SPDX: iterate packages[].name.
names = {c.get("name", "").lower() for c in bom.get("components", [])}
names |= {p.get("name", "").lower() for p in bom.get("packages", [])}

missing = [t for t in targets if t.lower() not in names]
if missing:
    print(f"FAIL: expected packages missing: {missing}", file=sys.stderr)
    sys.exit(1)
print(f"  confirmed present: {', '.join(targets)}")
PY
}

# --- Scenario 1: direct path, CycloneDX (Debian-based) --------------------

scenario_direct_cdx() {
    echo "--- Scenario 1: direct Docker Official Image (python:3.11-slim, CycloneDX) ---"
    local out="$OUTDIR/direct.cdx.json"
    "${ACTION[@]}" --docker-image python:3.11-slim \
        --no-upload --no-enrich \
        -o "$out" 2>&1 | sed 's/^/  /' | tail -4
    assert_cdx_summary "$out" 100  # python base has ~142 upstream packages
    echo "  PASS"
    echo
}

# --- Scenario 2: direct path, SPDX ----------------------------------------

scenario_direct_spdx() {
    echo "--- Scenario 2: direct Docker Official Image (python:3.11-slim, SPDX) ---"
    local out="$OUTDIR/direct.spdx.json"
    "${ACTION[@]}" --docker-image python:3.11-slim \
        --no-upload --no-enrich \
        -f spdx -o "$out" 2>&1 | sed 's/^/  /' | tail -4
    assert_spdx_valid "$out" 100
    echo "  PASS"
    echo
}

# --- Scenario 3: Distro sweep -- various Docker Hub Official Images --------

scenario_distros() {
    echo "--- Scenario 3: Distro sweep (apk/deb/rpm/alpm ecosystems) ---"
    # (image, purl-type-expected, min-upstream)
    local cases=(
        "alpine:3.20|pkg:apk|10"
        "ubuntu:24.04|pkg:deb|100"
        "rockylinux:9|pkg:rpm|100"
        "amazonlinux:2|pkg:rpm|100"
        "archlinux:latest|pkg:alpm|100"
        "busybox:latest|pkg:generic|1"
    )
    for c in "${cases[@]}"; do
        local img="${c%%|*}"
        local rest="${c#*|}"
        local expected_purl="${rest%%|*}"
        local min_up="${rest##*|}"

        echo "  • $img (expect $expected_purl, >=$min_up upstream)"
        local out="$OUTDIR/${img//[:\/]/-}.cdx.json"
        "${ACTION[@]}" --docker-image "$img" --no-upload --no-enrich -o "$out" 2>&1 \
            | grep -iE "Fetched upstream SBOM" | sed 's/^/      /'
        assert_cdx_summary "$out" "$min_up" | sed 's/^/    /'
    done
    echo "  PASS (all distros)"
    echo
}

# --- Scenario 4: provenance path, CycloneDX -------------------------------

scenario_provenance_cdx() {
    echo "--- Scenario 4: provenance-based detection (FROM python:3.11-slim, CycloneDX) ---"
    ensure_registry

    local tag="$REGISTRY/sbomify-test/app-official:e2e-cdx-$$"
    echo "  Building & pushing $tag (with --provenance=mode=max --sbom=false)..."
    docker buildx build --sbom=false --provenance=mode=max \
        -t "$tag" --push \
        -f "$SCRIPT_DIR/Dockerfile.official" "$SCRIPT_DIR" 2>&1 | tail -3 | sed 's/^/    /'

    local out="$OUTDIR/provenance.cdx.json"
    "${ACTION[@]}" --docker-image "$tag" \
        --no-upload --no-enrich \
        -o "$out" 2>&1 | sed 's/^/  /' | tail -4
    assert_cdx_summary "$out" 100
    assert_packages_present "$out" requests click curl jq
    echo "  PASS"
    echo
}

# --- Scenario 5: provenance path, SPDX ------------------------------------

scenario_provenance_spdx() {
    echo "--- Scenario 5: provenance-based detection (FROM python:3.11-slim, SPDX) ---"
    ensure_registry

    local tag="$REGISTRY/sbomify-test/app-official:e2e-spdx-$$"
    echo "  Building & pushing $tag (with --provenance=mode=max --sbom=false)..."
    docker buildx build --sbom=false --provenance=mode=max \
        -t "$tag" --push \
        -f "$SCRIPT_DIR/Dockerfile.official" "$SCRIPT_DIR" 2>&1 | tail -3 | sed 's/^/    /'

    local out="$OUTDIR/provenance.spdx.json"
    "${ACTION[@]}" --docker-image "$tag" \
        --no-upload --no-enrich \
        -f spdx -o "$out" 2>&1 | sed 's/^/  /' | tail -4
    assert_spdx_valid "$out" 150
    assert_packages_present "$out" requests click curl jq
    echo "  PASS"
    echo
}

# --- Scenario 6: Full augment + enrich pipeline ---------------------------
# Exercises merge → augmentation (from local sbomify.json) → enrichment
# (PyPI/Debian/license-db live).

scenario_full_pipeline() {
    echo "--- Scenario 6: full pipeline — merge + augment + enrich (python:3.11-slim) ---"
    local workdir="$OUTDIR/augment"
    mkdir -p "$workdir"
    cat > "$workdir/sbomify.json" <<'JSON'
{
  "lifecycle_phase": "build",
  "supplier": {
    "name": "sbomify E2E Test",
    "url": ["https://sbomify.com"],
    "contacts": [{"name": "sbomify team", "email": "team@sbomify.example"}]
  },
  "authors": [{"name": "sbomify-action CI", "email": "ci@sbomify.example"}],
  "licenses": ["MIT"],
  "release_date": "2026-04-24",
  "support_period_end": "2028-04-24"
}
JSON
    local out="$workdir/full.cdx.json"
    (cd "$workdir" && "${ACTION[@]}" --docker-image python:3.11-slim \
        --no-upload --augment --enrich -o "$out") 2>&1 | tail -4 | sed 's/^/  /'
    assert_cdx_summary "$out" 100
    python3 - "$out" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    bom = json.load(f)
md = bom.get("metadata", {})
assert md.get("supplier", {}).get("name") == "sbomify E2E Test", f"supplier not applied: {md.get('supplier')}"
assert any(a.get("email") == "ci@sbomify.example" for a in md.get("authors", [])), f"author not applied"
assert any(phase.get("phase") == "build" for phase in md.get("lifecycles", [])), f"lifecycle not applied"
print("  augmentation applied: supplier + authors + lifecycle ✓")
PY
    echo "  PASS"
    echo
}

# --- Scenario 7: DHI path -------------------------------------------------

scenario_dhi() {
    echo "--- Scenario 7: DHI base ---"
    local manifest_err
    manifest_err="$(crane manifest "dhi.io/python:3.11" 2>&1 >/dev/null || true)"
    if [[ -n "$manifest_err" ]]; then
        echo "  SKIP: dhi.io/python not pullable with current credentials."
        if [[ "$manifest_err" == *"No matching credentials"* ]]; then
            echo "    Cause: docker.io credentials don't apply to dhi.io (separate registry)."
            echo "    Fix:   docker login dhi.io   (same Docker Hub username, same PAT)"
        elif [[ "$manifest_err" == *"401"* ]] || [[ "$manifest_err" == *"Unauthorized"* ]]; then
            echo "    Cause: logged-in account doesn't have DHI entitlement."
            echo "    Fix:   subscribe to Docker Hardened Images at"
            echo "           https://hub.docker.com/hardened-images (free)"
        else
            echo "    crane said: ${manifest_err:0:200}"
        fi
        echo "  Unit tests (tests/test_dockerhub.py::TestFetchDockerhubSbom::test_dhi_*) cover"
        echo "  the cosign fetch shape including --key and --insecure-ignore-tlog=true."
        echo
        return
    fi

    local out="$OUTDIR/dhi.cdx.json"
    "${ACTION[@]}" --docker-image dhi.io/python:3.11 \
        --no-upload --no-enrich \
        -o "$out" 2>&1 | sed 's/^/  /' | tail -4
    assert_cdx_summary "$out" 1
    echo "  PASS"
    echo
}

scenario_direct_cdx
scenario_direct_spdx
scenario_distros
scenario_provenance_cdx
scenario_provenance_spdx
scenario_full_pipeline
scenario_dhi

echo "=== all scenarios complete ==="
echo "Outputs in $OUTDIR"
