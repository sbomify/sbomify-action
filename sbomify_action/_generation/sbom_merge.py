"""Merge an authoritative upstream SBOM with a local Syft scan.

Used when consuming Docker Hub upstream SBOMs: the publisher's signed SBOM is
authoritative for base-image packages, but Syft is needed to catch anything
the user's Dockerfile added on top (``pip install``, ``apt-get install``, etc.).

Merge policy (confirmed with user):

* **Upstream wins on conflict.** Upstream component metadata is never
  overwritten by Syft.
* **Syft fills gaps.** For a PURL present in both, any *empty* upstream field
  (description, licenses, supplier, hashes, ...) is filled from Syft.
* **Syft adds overlay.** For a PURL only in Syft's scan, the component is
  appended to upstream and tagged ``sbomify:source=syft-overlay``.
* Upstream components are tagged ``sbomify:source=docker-hub-upstream``.

Works on parsed JSON dicts rather than ``cyclonedx-python-lib`` /
``spdx-tools`` objects — simpler and avoids round-trip serialization cost.
"""

from __future__ import annotations

from typing import Any

from packageurl import PackageURL

SBOMIFY_SOURCE_PROP = "sbomify:source"
SOURCE_DOCKERHUB = "docker-hub-upstream"
SOURCE_SYFT = "syft-overlay"


def _purl_identity(purl_str: str | None) -> tuple[str, str, str, str] | None:
    """Return a PURL's core identity (type, namespace, name, version).

    Qualifiers are intentionally ignored so that the same package emitted by
    different generators matches — e.g., Docker's BuildKit SBOM emits
    ``pkg:deb/debian/acl@2.3.2?os_distro=trixie&os_name=debian`` while Syft
    emits ``pkg:deb/debian/acl@2.3.2?arch=amd64&distro=debian-13``. They're
    the same package; dedup should collapse them.

    Returns ``None`` if the PURL is missing, malformed, or lacks a version
    (falling back to string-equality dedup would over-merge in that case).
    """
    if not purl_str:
        return None
    try:
        parsed = PackageURL.from_string(purl_str)
    except ValueError:
        return None
    if not parsed.type or not parsed.name or not parsed.version:
        return None
    return (parsed.type, parsed.namespace or "", parsed.name, parsed.version)


def _purl_identity_loose(purl_str: str | None) -> tuple[str, str, str] | None:
    """Return a looser PURL identity (type, name, version), dropping namespace.

    Used as a second-pass fallback when the strict identity doesn't match.
    Needed because some generators disagree on the ``namespace`` portion of OS
    package PURLs — e.g., Amazon Linux's upstream SBOM uses
    ``pkg:rpm/amazonlinux/bash`` while Syft emits ``pkg:rpm/amzn/bash``.

    Safe because the merge runs over *one image at a time*: upstream and Syft
    are describing the same artifact, so two components with the same type,
    name, and version in different namespaces are overwhelmingly the same
    package rather than a collision across distros.
    """
    if not purl_str:
        return None
    try:
        parsed = PackageURL.from_string(purl_str)
    except ValueError:
        return None
    if not parsed.type or not parsed.name or not parsed.version:
        return None
    return (parsed.type, parsed.name, parsed.version)


# ---------------------------------------------------------------------------
# CycloneDX merge
# ---------------------------------------------------------------------------


def _cdx_purl(comp: dict[str, Any]) -> str | None:
    purl = comp.get("purl")
    return purl if purl else None


def _cdx_identity(comp: dict[str, Any]) -> tuple[str, str, str, str] | None:
    return _purl_identity(_cdx_purl(comp))


def _cdx_identity_loose(comp: dict[str, Any]) -> tuple[str, str, str] | None:
    return _purl_identity_loose(_cdx_purl(comp))


def _cdx_set_source(comp: dict[str, Any], source: str) -> None:
    """Set the ``sbomify:source`` property on a CycloneDX component."""
    props = [p for p in comp.get("properties", []) if p.get("name") != SBOMIFY_SOURCE_PROP]
    props.append({"name": SBOMIFY_SOURCE_PROP, "value": source})
    comp["properties"] = props


def _cdx_fill_empty(upstream: dict[str, Any], syft: dict[str, Any]) -> None:
    """Copy Syft fields into upstream only where upstream is empty/missing."""
    for field in ("description", "author", "publisher", "cpe", "group"):
        if not upstream.get(field) and syft.get(field):
            upstream[field] = syft[field]

    for field in ("supplier", "licenses", "hashes"):
        if not upstream.get(field) and syft.get(field):
            upstream[field] = syft[field]

    existing_urls = {r.get("url") for r in upstream.get("externalReferences", [])}
    for ref in syft.get("externalReferences", []):
        if ref.get("url") and ref.get("url") not in existing_urls:
            upstream.setdefault("externalReferences", []).append(ref)
            existing_urls.add(ref.get("url"))


def _collect_cdx_bom_refs(bom: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    meta_ref = bom.get("metadata", {}).get("component", {}).get("bom-ref")
    if meta_ref:
        refs.add(meta_ref)
    for c in bom.get("components", []):
        ref = c.get("bom-ref")
        if ref:
            refs.add(ref)
    return refs


def _unique_bom_ref(candidate: str, taken: set[str]) -> str:
    if candidate not in taken:
        return candidate
    n = 1
    while True:
        new = f"{candidate}-syft-{n}"
        if new not in taken:
            return new
        n += 1


def merge_cyclonedx(upstream: dict[str, Any], syft: dict[str, Any]) -> dict[str, Any]:
    """Merge ``syft`` (CycloneDX dict) into ``upstream`` (CycloneDX dict).

    Mutates and returns ``upstream``. Upstream wins on conflict; Syft-only
    components are appended with the ``syft-overlay`` source tag.

    Dedup is two-pass:

    1. **Strict** — match on ``(type, namespace, name, version)``, ignoring
       qualifiers. Handles different qualifier conventions across generators.
    2. **Loose fallback** — match on ``(type, name, version)``, ignoring
       namespace. Handles cases where upstream and Syft disagree on the
       namespace portion (e.g., upstream ``pkg:rpm/amazonlinux/bash`` vs
       Syft ``pkg:rpm/amzn/bash``).
    """
    components = upstream.setdefault("components", [])

    by_identity: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    by_loose: dict[tuple[str, str, str], dict[str, Any]] = {}
    for comp in components:
        _cdx_set_source(comp, SOURCE_DOCKERHUB)
        identity = _cdx_identity(comp)
        if identity is not None:
            by_identity[identity] = comp
        loose = _cdx_identity_loose(comp)
        if loose is not None:
            # First upstream component with this loose key wins the index
            # slot (upstream's ordering is preserved, so this gives us
            # deterministic behavior if upstream has multiple entries
            # sharing a loose key).
            by_loose.setdefault(loose, comp)

    taken_refs = _collect_cdx_bom_refs(upstream)

    for syft_comp in syft.get("components", []):
        identity = _cdx_identity(syft_comp)
        if identity is not None and identity in by_identity:
            _cdx_fill_empty(by_identity[identity], syft_comp)
            continue

        loose = _cdx_identity_loose(syft_comp)
        if loose is not None and loose in by_loose:
            _cdx_fill_empty(by_loose[loose], syft_comp)
            continue

        # New component. Ensure bom-ref uniqueness.
        original = syft_comp.get("bom-ref")
        if original:
            new_ref = _unique_bom_ref(original, taken_refs)
            if new_ref != original:
                syft_comp["bom-ref"] = new_ref
            taken_refs.add(new_ref)

        _cdx_set_source(syft_comp, SOURCE_SYFT)
        components.append(syft_comp)

    return upstream


# ---------------------------------------------------------------------------
# SPDX 2.x merge
# ---------------------------------------------------------------------------


def _spdx_purl(pkg: dict[str, Any]) -> str | None:
    for ref in pkg.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            locator = ref.get("referenceLocator")
            if locator:
                return str(locator)
    return None


def _spdx_identity(pkg: dict[str, Any]) -> tuple[str, str, str, str] | None:
    return _purl_identity(_spdx_purl(pkg))


def _spdx_identity_loose(pkg: dict[str, Any]) -> tuple[str, str, str] | None:
    return _purl_identity_loose(_spdx_purl(pkg))


def _spdx_fill_empty(upstream: dict[str, Any], syft: dict[str, Any]) -> None:
    for field in (
        "description",
        "summary",
        "supplier",
        "originator",
        "licenseDeclared",
        "licenseConcluded",
        "copyrightText",
        "homepage",
        "sourceInfo",
    ):
        up_val = upstream.get(field)
        if (not up_val or up_val == "NOASSERTION") and syft.get(field) and syft[field] != "NOASSERTION":
            upstream[field] = syft[field]

    if not upstream.get("checksums") and syft.get("checksums"):
        upstream["checksums"] = syft["checksums"]

    existing_ext = {
        (r.get("referenceCategory"), r.get("referenceType"), r.get("referenceLocator"))
        for r in upstream.get("externalRefs", [])
    }
    for ref in syft.get("externalRefs", []):
        key = (ref.get("referenceCategory"), ref.get("referenceType"), ref.get("referenceLocator"))
        if key not in existing_ext:
            upstream.setdefault("externalRefs", []).append(ref)
            existing_ext.add(key)


def _collect_spdx_ids(doc: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    root_id = doc.get("SPDXID")
    if root_id:
        ids.add(root_id)
    for pkg in doc.get("packages", []):
        pid = pkg.get("SPDXID")
        if pid:
            ids.add(pid)
    for f in doc.get("files", []):
        fid = f.get("SPDXID")
        if fid:
            ids.add(fid)
    return ids


def _unique_spdx_id(candidate: str, taken: set[str]) -> str:
    if candidate not in taken:
        return candidate
    n = 1
    while True:
        new = f"{candidate}-syft-{n}"
        if new not in taken:
            return new
        n += 1


def merge_spdx(upstream: dict[str, Any], syft: dict[str, Any]) -> dict[str, Any]:
    """Merge ``syft`` (SPDX 2.x dict) into ``upstream`` (SPDX 2.x dict).

    Mutates and returns ``upstream``. Syft packages whose PURL is already
    present in upstream are dropped after their non-empty fields fill any
    upstream gaps. Syft packages with new PURLs (or no PURL at all) are
    appended; their SPDX IDs and relationships are rewritten to avoid
    collisions with upstream IDs.
    """
    upstream_packages = upstream.setdefault("packages", [])

    by_identity: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    by_loose: dict[tuple[str, str, str], dict[str, Any]] = {}
    for pkg in upstream_packages:
        identity = _spdx_identity(pkg)
        if identity is not None:
            by_identity[identity] = pkg
        loose = _spdx_identity_loose(pkg)
        if loose is not None:
            by_loose.setdefault(loose, pkg)

    taken_ids = _collect_spdx_ids(upstream)

    # Build remap table so relationships referencing Syft's IDs can be rewritten.
    id_remap: dict[str, str] = {}
    upstream_root = upstream.get("SPDXID", "SPDXRef-DOCUMENT")
    syft_root = syft.get("SPDXID", "SPDXRef-DOCUMENT")
    id_remap[syft_root] = upstream_root

    new_packages: list[dict[str, Any]] = []

    for syft_pkg in syft.get("packages", []):
        identity = _spdx_identity(syft_pkg)
        original_id = syft_pkg.get("SPDXID", "")

        matched = None
        if identity is not None and identity in by_identity:
            matched = by_identity[identity]
        else:
            loose = _spdx_identity_loose(syft_pkg)
            if loose is not None and loose in by_loose:
                matched = by_loose[loose]

        if matched is not None:
            _spdx_fill_empty(matched, syft_pkg)
            if original_id:
                id_remap[original_id] = matched.get("SPDXID", original_id)
            continue

        if original_id:
            new_id = _unique_spdx_id(original_id, taken_ids)
            if new_id != original_id:
                syft_pkg["SPDXID"] = new_id
            taken_ids.add(new_id)
            id_remap[original_id] = new_id

        new_packages.append(syft_pkg)

    upstream_packages.extend(new_packages)

    # Carry over Syft files, rewriting IDs if needed.
    upstream_files = upstream.setdefault("files", [])
    for syft_file in syft.get("files", []):
        original_id = syft_file.get("SPDXID", "")
        if original_id:
            new_id = _unique_spdx_id(original_id, taken_ids)
            if new_id != original_id:
                syft_file["SPDXID"] = new_id
            taken_ids.add(new_id)
            id_remap[original_id] = new_id
        upstream_files.append(syft_file)

    # Carry over Syft relationships with remapped IDs, deduping by the triple.
    upstream_rels = upstream.setdefault("relationships", [])
    existing_rels = {
        (r.get("spdxElementId"), r.get("relationshipType"), r.get("relatedSpdxElement")) for r in upstream_rels
    }

    for rel in syft.get("relationships", []):
        new_rel = dict(rel)
        for key in ("spdxElementId", "relatedSpdxElement"):
            val = new_rel.get(key)
            if val in id_remap:
                new_rel[key] = id_remap[val]

        triple = (new_rel.get("spdxElementId"), new_rel.get("relationshipType"), new_rel.get("relatedSpdxElement"))
        if triple in existing_rels:
            continue
        existing_rels.add(triple)
        upstream_rels.append(new_rel)

    # Carry over hasExtractedLicensingInfos from both docs. Packages may refer
    # to LicenseRef-* identifiers defined here — dropping this section produces
    # invalid SPDX with dangling license references.
    upstream_extracted = upstream.setdefault("hasExtractedLicensingInfos", [])
    seen_license_ids = {e.get("licenseId") for e in upstream_extracted if e.get("licenseId")}
    for entry in syft.get("hasExtractedLicensingInfos", []):
        lid = entry.get("licenseId")
        if lid and lid not in seen_license_ids:
            upstream_extracted.append(entry)
            seen_license_ids.add(lid)

    return upstream
