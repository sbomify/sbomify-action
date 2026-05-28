"""Tests for ci_emitter (workflow YAML generation) and apply.apply_plan."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from sbomify_action.cli.wizard import apply as apply_mod
from sbomify_action.cli.wizard.ci_emitter import (
    HEADER_SENTINEL,
    PINNED_ACTION_SHA,
    PINNED_ACTION_VERSION,
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
    assert "name: sboms\n" in yaml
    assert "branches: [main]" in yaml
    assert "id-token: write" in yaml  # OIDC default
    assert "TOKEN: ${{ secrets.SBOMIFY_TOKEN }}" not in yaml
    assert "AUGMENT: 'false'" in yaml  # skip default
    assert "REPLACE_WITH_COMPONENT_ID" in yaml  # no component_ids passed
    assert f"sbomify/sbomify-action@{PINNED_ACTION_SHA}  # {PINNED_ACTION_VERSION}" in yaml
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
    assert "tags: ['v*']" in yaml
    assert "GITHUB_REF#refs/tags/" in yaml
    assert "PRODUCT_RELEASE: 'prod-1:${{ steps.ver.outputs.v }}'" in yaml


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


def test_apply_plan_dry_run_skips_write(tmp_path: Path) -> None:
    state = _state(tmp_path)
    api = state.api
    assert api is not None
    api.get_or_create_component.return_value = ("comp-1", True)

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

    assert not (tmp_path / ".github" / "workflows" / "sboms.yml").exists()
    # Components still created — only the disk write is suppressed.
    api.get_or_create_component.assert_called_once()


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
