"""Tests for ci_emitter (workflow YAML generation) and apply.apply_plan."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import requests

from sbomify_action.cli.wizard import apply as apply_mod
from sbomify_action.cli.wizard import ci_emitter
from sbomify_action.cli.wizard.ci_emitter import (
    ACTION_REPO,
    HEADER_SENTINEL,
    _action_version,
    _build_action_ref,
    _resolve_latest_release_tag,
    _resolve_tag_sha,
    emit_workflow,
)
from sbomify_action.cli.wizard.options import WizardOptions
from sbomify_action.cli.wizard.state import (
    DiscoveredLockfile,
    Plan,
    PlannedComponent,
    RepoFacts,
    WizardState,
    WorkspaceSnapshot,
)


def _facts(repo_root: Path, *, branch: str = "main", tags: bool = False) -> RepoFacts:
    return RepoFacts(
        repo_root=repo_root,
        is_git=True,
        remote_url="git@github.com:acme/widget.git",
        suggested_repo_name="widget",
        default_branch=branch,
        current_branch=branch,
        has_release_tags=tags,
        owner_repo_slug="acme/widget",
    )


def _python_lockfile(tmp_path: Path) -> DiscoveredLockfile:
    return DiscoveredLockfile(
        path=tmp_path / "uv.lock",
        rel_path=Path("uv.lock"),
        ecosystem="python",
        suggested_name="widget-py",
    )


# ----------------------------------------------------------------------
# emit_workflow


def test_emit_trunk_oidc_default(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")

    assert HEADER_SENTINEL in yaml
    # The sentinel line carries the generating build's actual version,
    # not a hard-coded "v1".
    assert f"{HEADER_SENTINEL} {_action_version()}\n" in yaml
    assert "name: sboms\n" in yaml
    assert "branches: [main]" in yaml
    assert "id-token: write" in yaml  # OIDC default
    assert "TOKEN: ${{ secrets.SBOMIFY_TOKEN }}" not in yaml
    assert "AUGMENT: 'false'" in yaml  # skip default
    assert "REPLACE_WITH_COMPONENT_ID" in yaml  # no component_ids passed
    # No action_ref passed: emitter falls back to the tag-pinned ref (no
    # network, no SHA).
    assert f"      - uses: {ACTION_REPO}@{_action_version()}\n" in yaml
    # Trunk uses short-SHA versioning, NOT tag-stripping.
    assert "git rev-parse --short HEAD" in yaml


def test_emit_token_mode_drops_id_token_and_adds_secret(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        credential_mode="token",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "id-token: write" not in yaml
    assert "TOKEN: ${{ secrets.SBOMIFY_TOKEN }}" in yaml


def test_emit_tag_strategy_uses_tag_versioning(tmp_path: Path) -> None:
    facts = _facts(tmp_path, tags=True)
    plan = Plan(
        use_product_id="prod-1",
        release_strategy="tag",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    # Both v-prefixed (v1.2.3) and bare-numeric (1.2.3 / CalVer 2026.7.1)
    # version tags must fire the workflow.
    assert "tags: ['v*', '[0-9]*']" in yaml
    # The tag-strategy version step now wraps the strip in a bash if/else so
    # workflow_dispatch from a branch falls back to the short SHA instead of
    # emitting refs/heads/<branch> (which contains slashes and breaks
    # downstream component-version parsing).
    assert "refs/tags/*" in yaml
    assert "GITHUB_REF#refs/tags/" in yaml
    assert "git rev-parse --short HEAD" in yaml
    # PRODUCT_RELEASE must be a JSON array string — cli/main.py runs
    # json.loads on it and rejects scalar shapes. The wizard previously
    # emitted "PRODUCT_RELEASE: 'pid:ver'" which failed at runtime.
    assert "PRODUCT_RELEASE: '[\"prod-1:${{ steps.ver.outputs.v }}\"]'" in yaml


def test_emit_manual_only_workflow_dispatch(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        release_strategy="manual",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "workflow_dispatch:" in yaml
    assert "push:" not in yaml


def test_emit_profile_augmentation_flips_env_flag(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        augmentation="profile",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "AUGMENT: 'true'" in yaml


def test_emit_matrix_includes_each_lockfile(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    py = _python_lockfile(tmp_path)
    js = DiscoveredLockfile(
        path=tmp_path / "package.json",
        rel_path=Path("package.json"),
        ecosystem="javascript",
        suggested_name="widget-js",
    )
    plan = Plan(
        use_product_id="prod-1",
        create_components=[
            PlannedComponent(lockfile=py, name="widget-py"),
            PlannedComponent(lockfile=js, name="widget-js"),
        ],
    )
    component_ids = {"uv.lock": "comp-1", "package.json": "comp-2"}
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com", component_ids=component_ids)
    assert "name: widget-py" in yaml
    assert "component_id: comp-1" in yaml
    assert "lockfile: uv.lock" in yaml
    assert "name: widget-js" in yaml
    assert "component_id: comp-2" in yaml
    assert "lockfile: package.json" in yaml
    assert "component_name: widget-py" in yaml
    assert "component_name: widget-js" in yaml


def test_emit_custom_api_base_url(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://stage.sbomify.com")
    assert "API_BASE_URL: https://stage.sbomify.com" in yaml


def test_emit_default_format_is_cyclonedx_only(tmp_path: Path) -> None:
    """Default plan emits one matrix row per lockfile, in cyclonedx format."""
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert yaml.count("sbom_format:") == 1
    assert "sbom_format: cyclonedx" in yaml
    assert "sbom_format: spdx" not in yaml
    assert "output_file: widget-py.cdx.json" in yaml


def test_emit_both_formats_emits_two_rows_per_lockfile(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        sbom_formats=["cyclonedx", "spdx"],
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "name: widget-py-cyclonedx" in yaml
    assert "name: widget-py-spdx" in yaml
    assert "sbom_format: cyclonedx" in yaml
    assert "sbom_format: spdx" in yaml
    assert "output_file: widget-py.cdx.json" in yaml
    assert "output_file: widget-py.spdx.json" in yaml


def test_emit_spdx_only(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        sbom_formats=["spdx"],
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "sbom_format: spdx" in yaml
    assert "sbom_format: cyclonedx" not in yaml
    assert "output_file: widget-py.spdx.json" in yaml


def test_emit_attestation_adds_step_and_permission(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        attestation=True,
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "attestations: write" in yaml
    assert "attest-build-provenance" in yaml
    assert "subject-path: '${{ github.workspace }}/${{ matrix.output_file }}'" in yaml


def test_emit_attestation_carries_support_matrix_annotation(tmp_path: Path) -> None:
    """The attest step must be preceded by the four-condition support
    annotation so anyone reading the generated workflow knows the
    GHEC / GHES gating without leaving the file."""
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        attestation=True,
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "Public repository on any GitHub plan" in yaml
    assert "Private / internal repository on GitHub Enterprise Cloud" in yaml
    assert "Private / internal repository on GitHub Free, Pro, or Team" in yaml
    assert "GitHub Enterprise Server" in yaml
    assert "github.com/actions/attest-build-provenance" in yaml


def test_emit_no_attestation_by_default(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "attestations: write" not in yaml
    assert "attest-build-provenance" not in yaml
    # The per-row attest flag only exists when attestation is enabled.
    assert "attest:" not in yaml


def test_emit_attestation_gates_rows_and_step(tmp_path: Path) -> None:
    """Every matrix row carries an ``attest`` boolean and the attest step
    is conditioned on it, so submodule rows can opt out per-entry."""
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        attestation=True,
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "            attest: true\n" in yaml
    assert "        if: ${{ matrix.attest }}\n" in yaml


def test_emit_attestation_skips_nested_repo_lockfiles(tmp_path: Path) -> None:
    """SBOMs for submodule / vendored lockfiles must NOT be attested: the
    Sigstore identity would be this repo's workflow, but the code belongs
    to another repository, so the attestation would fail verification
    against the repo the code actually comes from."""
    facts = _facts(tmp_path)
    sub = DiscoveredLockfile(
        path=tmp_path / "extern" / "lib" / "Cargo.lock",
        rel_path=Path("extern") / "lib" / "Cargo.lock",
        ecosystem="rust",
        suggested_name="widget-rust",
        nested_repo="extern/lib",
        nested_repo_kind="submodule",
    )
    plan = Plan(
        use_product_id="prod-1",
        attestation=True,
        create_components=[
            PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py"),
            PlannedComponent(lockfile=sub, name="widget-rust"),
        ],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "            attest: true\n" in yaml  # own lockfile still attests
    assert "            attest: false\n" in yaml  # submodule row opts out
    assert "        if: ${{ matrix.attest }}\n" in yaml
    # The opt-out must be self-documenting in the YAML: an explicit
    # "deliberately not signed" annotation naming the nested repo.
    assert "Deliberately NOT signed: extern/lib is a submodule" in yaml
    # The row-level flag order must match the component order: widget-py
    # (attest: true) before widget-rust (attest: false).
    assert yaml.index("attest: true") < yaml.index("attest: false")


def test_emit_cache_step_always_present(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "actions/cache@" in yaml
    assert "path: .sbomify-cache" in yaml
    assert "SBOMIFY_CACHE_DIR: ${{ github.workspace }}/.sbomify-cache" in yaml
    assert "SYFT_CACHE_DIR: ${{ github.workspace }}/.sbomify-cache/syft" in yaml


def test_emit_component_name_env_uses_matrix(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="My Widget Py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "COMPONENT_NAME: ${{ matrix.component_name }}" in yaml
    assert "component_name: My Widget Py" in yaml


def test_emit_token_mode_with_attestation_permissions(tmp_path: Path) -> None:
    """Token + attestation needs a permissions block (no id-token, but attestations: write)."""
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        credential_mode="token",
        attestation=True,
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "id-token: write" not in yaml
    assert "attestations: write" in yaml
    assert "TOKEN: ${{ secrets.SBOMIFY_TOKEN }}" in yaml


def test_emit_token_mode_no_attestation_no_permissions_block(tmp_path: Path) -> None:
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        credential_mode="token",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com")
    assert "permissions:" not in yaml
    assert "TOKEN: ${{ secrets.SBOMIFY_TOKEN }}" in yaml


def test_emit_uses_supplied_action_ref(tmp_path: Path) -> None:
    """An explicit action_ref (as apply/review pass) is emitted verbatim."""
    facts = _facts(tmp_path)
    plan = Plan(
        use_product_id="prod-1",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    ref = f"{ACTION_REPO}@{'a' * 40}  # v9.9.9"
    yaml = emit_workflow(plan, facts=facts, api_base_url="https://app.sbomify.com", action_ref=ref)
    assert f"      - uses: {ref}\n" in yaml


# ----------------------------------------------------------------------
# resolve_action_ref (runtime pin resolution)


def test_resolve_tag_sha_online_returns_commit(mocker) -> None:
    sha = "b" * 40
    response = MagicMock(status_code=200)
    response.json.return_value = {"sha": sha}
    mocker.patch.object(ci_emitter.requests, "get", return_value=response)

    assert _resolve_tag_sha("v26.2.0") == sha


def test_resolve_tag_sha_offline_returns_none(mocker) -> None:
    mocker.patch.object(ci_emitter.requests, "get", side_effect=requests.RequestException("offline"))
    assert _resolve_tag_sha("v26.2.0") is None


def test_resolve_tag_sha_non_200_returns_none(mocker) -> None:
    response = MagicMock(status_code=404)
    mocker.patch.object(ci_emitter.requests, "get", return_value=response)
    assert _resolve_tag_sha("v0.0.0") is None


def test_resolve_tag_sha_invalid_json_returns_none(mocker) -> None:
    response = MagicMock(status_code=200)
    response.json.side_effect = ValueError("not json")
    mocker.patch.object(ci_emitter.requests, "get", return_value=response)
    assert _resolve_tag_sha("v26.2.0") is None


def test_resolve_tag_sha_non_dict_json_returns_none(mocker) -> None:
    # A proxy/error page can hand back well-formed JSON that isn't an object
    # (list/string). ``.get`` would then raise AttributeError — assert we
    # degrade to None instead, keeping the never-raise contract.
    response = MagicMock(status_code=200)
    response.json.return_value = ["not", "a", "dict"]
    mocker.patch.object(ci_emitter.requests, "get", return_value=response)
    assert _resolve_tag_sha("v26.2.0") is None


def test_resolve_tag_sha_rejects_malformed_sha(mocker) -> None:
    response = MagicMock(status_code=200)
    response.json.return_value = {"sha": "not-a-real-sha"}
    mocker.patch.object(ci_emitter.requests, "get", return_value=response)
    assert _resolve_tag_sha("v26.2.0") is None


def test_build_action_ref_sha_pinned_when_known() -> None:
    sha = "c" * 40
    assert _build_action_ref("v26.2.0", sha) == f"{ACTION_REPO}@{sha}  # v26.2.0"


def test_build_action_ref_tag_pinned_when_offline() -> None:
    # Offline fallback: still pinned to the version, just no SHA comment.
    assert _build_action_ref("v26.2.0", None) == f"{ACTION_REPO}@v26.2.0"


def test_action_version_falls_back_to_pyproject_when_unknown(monkeypatch) -> None:
    # Metadata-less dev checkout: read the version from pyproject.toml rather
    # than a hard-coded constant, so the emitted pin can't drift.
    monkeypatch.setattr(ci_emitter, "_PACKAGE_VERSION", "unknown")
    pyproject_version = ci_emitter._version_from_pyproject()
    assert pyproject_version
    assert _action_version() == f"v{pyproject_version}"


def test_action_version_unknown_when_no_source(monkeypatch) -> None:
    # Neither installed metadata nor a readable pyproject.toml.
    monkeypatch.setattr(ci_emitter, "_PACKAGE_VERSION", "unknown")
    monkeypatch.setattr(ci_emitter, "_version_from_pyproject", lambda: None)
    assert _action_version() == "unknown"


def test_action_version_prefixes_v(monkeypatch) -> None:
    monkeypatch.setattr(ci_emitter, "_PACKAGE_VERSION", "26.2.0")
    assert _action_version() == "v26.2.0"


def test_action_version_strips_local_version_segment(monkeypatch) -> None:
    # Dev/Docker builds report PEP 440 local versions like 26.7.0+ad3dc1d.
    # The +… build metadata is not part of any release tag and must never
    # reach an emitted `uses:` ref.
    monkeypatch.setattr(ci_emitter, "_PACKAGE_VERSION", "26.7.0+ad3dc1d")
    assert _action_version() == "v26.7.0"


def test_resolve_latest_release_tag_online(mocker) -> None:
    response = MagicMock(status_code=200)
    response.json.return_value = {"tag_name": "v27.1.0"}
    mocker.patch.object(ci_emitter.requests, "get", return_value=response)
    assert _resolve_latest_release_tag() == "v27.1.0"


def test_resolve_latest_release_tag_offline_returns_none(mocker) -> None:
    mocker.patch.object(ci_emitter.requests, "get", side_effect=requests.RequestException("offline"))
    assert _resolve_latest_release_tag() is None


def test_resolve_latest_release_tag_non_200_returns_none(mocker) -> None:
    response = MagicMock(status_code=404)
    mocker.patch.object(ci_emitter.requests, "get", return_value=response)
    assert _resolve_latest_release_tag() is None


def test_resolve_latest_release_tag_invalid_json_returns_none(mocker) -> None:
    response = MagicMock(status_code=200)
    response.json.side_effect = ValueError("not json")
    mocker.patch.object(ci_emitter.requests, "get", return_value=response)
    assert _resolve_latest_release_tag() is None


def test_resolve_latest_release_tag_non_dict_json_returns_none(mocker) -> None:
    response = MagicMock(status_code=200)
    response.json.return_value = ["not", "a", "dict"]
    mocker.patch.object(ci_emitter.requests, "get", return_value=response)
    assert _resolve_latest_release_tag() is None


def test_resolve_latest_release_tag_rejects_unsafe_tag(mocker) -> None:
    # A tag lands verbatim in emitted YAML — reject anything outside plain
    # tag characters (whitespace, quotes, comment markers).
    response = MagicMock(status_code=200)
    response.json.return_value = {"tag_name": "v1.0 # evil"}
    mocker.patch.object(ci_emitter.requests, "get", return_value=response)
    assert _resolve_latest_release_tag() is None


def test_resolve_action_ref_pins_latest_release_sha(monkeypatch) -> None:
    # Online: the emitted pin is the latest published release resolved to its
    # commit SHA — not the running build's version, which may not exist as a
    # tag (e.g. a dev build's 26.7.0+ad3dc1d).
    sha = "f" * 40
    ci_emitter.resolve_action_ref.cache_clear()
    monkeypatch.setattr(ci_emitter, "_PACKAGE_VERSION", "26.7.0+ad3dc1d")
    monkeypatch.setattr(ci_emitter, "_resolve_latest_release_tag", lambda: "v27.1.0")
    monkeypatch.setattr(ci_emitter, "_resolve_tag_sha", lambda version: sha if version == "v27.1.0" else None)
    assert ci_emitter.resolve_action_ref() == f"{ACTION_REPO}@{sha}  # v27.1.0"
    ci_emitter.resolve_action_ref.cache_clear()


def test_resolve_action_ref_online_includes_sha(monkeypatch) -> None:
    # Release lookup fails (autouse fixture stubs it to None) but the tag
    # lookup succeeds: pin the build-version tag's SHA.
    sha = "d" * 40
    ci_emitter.resolve_action_ref.cache_clear()
    monkeypatch.setattr(ci_emitter, "_resolve_tag_sha", lambda version: sha)
    assert ci_emitter.resolve_action_ref() == f"{ACTION_REPO}@{sha}  # {_action_version()}"
    ci_emitter.resolve_action_ref.cache_clear()


def test_resolve_action_ref_offline_is_tag_pinned() -> None:
    # The autouse offline_action_pin fixture forces both GitHub lookups ->
    # None: default to the version we built, tag-pinned.
    ci_emitter.resolve_action_ref.cache_clear()
    ref = ci_emitter.resolve_action_ref()
    assert ref == f"{ACTION_REPO}@{_action_version()}"
    assert "  # " not in ref  # tag-pinned, no SHA comment


def test_resolve_action_ref_is_single_flight_across_threads(monkeypatch) -> None:
    # The review worker and the apply worker can call this concurrently. Even
    # with lru_cache, two threads could both miss the empty cache and each fire
    # a GitHub request. The single-flight lock must collapse concurrent callers
    # to exactly one underlying _resolve_tag_sha call so they pin the same ref.
    import threading
    import time

    ci_emitter.resolve_action_ref.cache_clear()
    sha = "e" * 40
    call_count = 0
    count_lock = threading.Lock()

    def _slow_resolve(_version: str) -> str:
        nonlocal call_count
        with count_lock:
            call_count += 1
        # Widen the race window: without the single-flight lock the other
        # threads would all enter here before the first caller populates the
        # cache, driving call_count above 1.
        time.sleep(0.1)
        return sha

    monkeypatch.setattr(ci_emitter, "_resolve_tag_sha", _slow_resolve)

    results: list[str] = []
    results_lock = threading.Lock()

    def _worker() -> None:
        ref = ci_emitter.resolve_action_ref()
        with results_lock:
            results.append(ref)

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    # Exactly one network resolution, and every thread saw the identical pin.
    assert call_count == 1
    assert results == [f"{ACTION_REPO}@{sha}  # {_action_version()}"] * 8
    ci_emitter.resolve_action_ref.cache_clear()


# ----------------------------------------------------------------------
# apply_plan


def _state(tmp_path: Path) -> WizardState:
    state = WizardState(facts=_facts(tmp_path))
    state.workspace = WorkspaceSnapshot(products=[{"id": "prod-existing", "name": "Existing"}])
    state.api = MagicMock()
    return state


def test_apply_plan_creates_components_and_attaches(tmp_path: Path) -> None:
    state = _state(tmp_path)
    api = state.api  # MagicMock
    assert api is not None
    api.get_or_create_component.side_effect = [("comp-1", True), ("comp-2", False)]

    py = _python_lockfile(tmp_path)
    js = DiscoveredLockfile(
        path=tmp_path / "package.json",
        rel_path=Path("package.json"),
        ecosystem="javascript",
        suggested_name="widget-js",
    )
    state.plan = Plan(
        use_product_id="prod-existing",
        create_components=[
            PlannedComponent(lockfile=py, name="widget-py"),
            PlannedComponent(lockfile=js, name="widget-js"),
        ],
    )

    opts = WizardOptions(
        token="t",
        api_base_url="https://app.sbomify.com",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=False,
    )

    logs: list[tuple[str, str]] = []
    apply_mod.apply_plan(state, opts, log=lambda kind, msg: logs.append((kind, msg)))

    # Both components went through get-or-create.
    assert api.get_or_create_component.call_count == 2
    # Single attach call with both IDs (set-union).
    api.attach_components_to_product.assert_called_once()
    args = api.attach_components_to_product.call_args.args
    assert args[0] == "prod-existing"
    assert set(args[1]) == {"comp-1", "comp-2"}

    # Workflow written, ID map populated.
    workflow = tmp_path / ".github" / "workflows" / "sboms.yml"
    assert workflow.exists()
    content = workflow.read_text(encoding="utf-8")
    assert "comp-1" in content
    assert "comp-2" in content
    assert workflow in state.written_files


def test_apply_plan_reuses_existing_component_without_create(tmp_path: Path) -> None:
    """When the user picked an existing component on the Components screen,
    apply_plan must skip the create_component API call and use the stored
    id directly."""
    state = _state(tmp_path)
    api = state.api
    assert api is not None
    # Sentinel — should never be called for the existing-id path.
    api.get_or_create_component.side_effect = AssertionError(
        "get_or_create_component must not run for existing-id components"
    )

    lockfile = _python_lockfile(tmp_path)
    state.plan = Plan(
        use_product_id="prod-existing",
        create_components=[
            PlannedComponent(lockfile=lockfile, name="widget-py", existing_id="comp-existing"),
        ],
    )

    opts = WizardOptions(
        token="t",
        api_base_url="https://app.sbomify.com",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=False,
    )
    apply_mod.apply_plan(state, opts)

    # Existing id was used as-is.
    assert state.component_ids[lockfile.rel_path] == "comp-existing"
    # The product attach call still fires, and the existing id is in the set.
    api.attach_components_to_product.assert_called_once()
    args = api.attach_components_to_product.call_args.args
    assert args[1] == ["comp-existing"]
    # Workflow file reflects the existing id.
    workflow = tmp_path / ".github" / "workflows" / "sboms.yml"
    assert "comp-existing" in workflow.read_text(encoding="utf-8")


def test_apply_plan_create_new_product(tmp_path: Path) -> None:
    state = _state(tmp_path)
    api = state.api
    assert api is not None
    api.create_product.return_value = {"id": "prod-new", "name": "Widget"}
    api.get_or_create_component.return_value = ("comp-1", True)

    state.plan = Plan(
        create_product="Widget",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )

    opts = WizardOptions(
        token="t",
        api_base_url="https://app.sbomify.com",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=False,
    )
    apply_mod.apply_plan(state, opts)

    api.create_product.assert_called_once_with("Widget")
    assert state.created_product_id == "prod-new"


def test_apply_plan_dry_run_skips_api_mutations_and_writes(tmp_path: Path) -> None:
    """Dry-run must NOT call any mutating API method and must NOT write files.

    The previous contract still made API calls and only suppressed
    writes; the Copilot review (correctly) flagged that as misleading
    given the help text claims "no API calls". The new contract: dry-
    run is a pure preview — auth + workspace prefetch (read-only) ran
    on the Authenticate screen, but apply itself stays silent.
    """
    state = _state(tmp_path)
    api = state.api
    assert api is not None

    state.plan = Plan(
        use_product_id="prod-existing",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )

    opts = WizardOptions(
        token="t",
        api_base_url="https://app.sbomify.com",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=True,
    )
    apply_mod.apply_plan(state, opts)

    # No workflow file written.
    assert not (tmp_path / ".github" / "workflows" / "sboms.yml").exists()
    # No API mutations: no component create, no product create, no
    # attach, no patch, no OIDC binding.
    api.get_or_create_component.assert_not_called()
    api.create_product.assert_not_called()
    api.attach_components_to_product.assert_not_called()
    api.patch_component.assert_not_called()
    api.create_oidc_binding.assert_not_called()
    # But the state is still populated with synthetic markers so the
    # Done screen can render a meaningful summary.
    assert state.component_ids  # one synthetic id per planned component
    assert any("would" in line.lower() for line in state.applied)


def test_apply_plan_overwrites_existing_sentinel_file_without_bak(tmp_path: Path) -> None:
    """When the target exists with the sentinel, apply overwrites in place — git
    is the source of truth for the previous version, no .bak files."""
    state = _state(tmp_path)
    api = state.api
    assert api is not None
    api.get_or_create_component.return_value = ("comp-1", True)

    workflow = tmp_path / ".github" / "workflows" / "sboms.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(f"# old\n{HEADER_SENTINEL}\nname: sboms\n", encoding="utf-8")

    state.plan = Plan(
        use_product_id="prod-existing",
        create_components=[PlannedComponent(lockfile=_python_lockfile(tmp_path), name="widget-py")],
    )
    opts = WizardOptions(
        token="t",
        api_base_url="https://app.sbomify.com",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=False,
    )
    apply_mod.apply_plan(state, opts)

    # File was overwritten in place.
    assert workflow.read_text(encoding="utf-8").startswith("# Generated by")
    # No .bak created — git tracks the previous version.
    assert not (tmp_path / ".github" / "workflows" / "sboms.yml.bak").exists()
