"""Unit tests for the wizard's apply_plan function."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sbomify_action.cli.wizard.client import SbomifyAPIError
from sbomify_action.cli.wizard.state import (
    DiscoveredLockfile,
    Plan,
    PlannedComponent,
    RepoFacts,
    WizardState,
    WorkspaceSnapshot,
)
from sbomify_action.cli.wizard.wizard_runner import WizardOptions, apply_plan


def _planned(
    name: str,
    rel: str = "backend/poetry.lock",
    *,
    repo_root: Path | None = None,
    augmentation: str = "skip",
    profile_id: str | None = None,
    sbomify_json: dict | None = None,
    release_strategy: str = "latest",
) -> PlannedComponent:
    rel_path = Path(rel)
    base = repo_root or Path("/repo")
    return PlannedComponent(
        lockfile=DiscoveredLockfile(
            path=base / rel_path,
            rel_path=rel_path,
            ecosystem="python",
            suggested_name=name,
        ),
        name=name,
        augmentation=augmentation,  # type: ignore[arg-type]
        profile_id=profile_id,
        sbomify_json=sbomify_json,
        release_strategy=release_strategy,  # type: ignore[arg-type]
    )


def _state(tmp_path: Path, plan: Plan, *, products=None) -> WizardState:
    facts = RepoFacts(
        repo_root=tmp_path,
        is_git=True,
        remote_url="https://github.com/acme/repo",
        suggested_repo_name="repo",
        default_branch="main",
        current_branch="feat",
        has_release_tags=False,
    )
    api = MagicMock()
    api.create_product.return_value = {"id": "prod_new", "name": plan.create_product or "demo"}
    api.ensure_default_project.return_value = {"id": "proj_default", "name": "demo-default"}
    api.create_component.side_effect = [
        {"id": f"comp_{i}", "name": planned.name} for i, planned in enumerate(plan.create_components, start=1)
    ]
    api.create_release.return_value = {"id": "rel_1", "name": "v0.0.0"}
    workspace = WorkspaceSnapshot(user={}, products=products or [])
    return WizardState(facts=facts, api=api, workspace=workspace, plan=plan)


def _opts(tmp_path: Path, *, dry_run: bool = False) -> WizardOptions:
    return WizardOptions(
        token="tok",
        api_base_url="https://app.sbomify.com",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=dry_run,
    )


def test_apply_plan_creates_product_and_components(tmp_path):
    plan = Plan(
        create_product="demo",
        create_components=[_planned("backend"), _planned("frontend", "frontend/package-lock.json")],
    )
    state = _state(tmp_path, plan)

    apply_plan(state, _opts(tmp_path))

    state.api.create_product.assert_called_once_with("demo")
    state.api.ensure_default_project.assert_called_once()
    assert state.api.create_component.call_count == 2
    assert state.api.attach_component_to_product.call_count == 2

    workflows = list((tmp_path / ".github" / "workflows").iterdir())
    assert {p.name for p in workflows} == {"sbomify-backend.yml", "sbomify-frontend.yml"}
    backend_yaml = (tmp_path / ".github" / "workflows" / "sbomify-backend.yml").read_text()
    assert "COMPONENT_ID: comp_1" in backend_yaml


def test_apply_plan_reuses_existing_product(tmp_path):
    plan = Plan(use_product_id="prod_existing", create_components=[_planned("backend")])
    products = [{"id": "prod_existing", "name": "existing"}]
    state = _state(tmp_path, plan, products=products)

    apply_plan(state, _opts(tmp_path))

    state.api.create_product.assert_not_called()
    state.api.create_component.assert_called_once()


def test_apply_plan_patches_contact_profile_when_strategy_is_profile(tmp_path):
    plan = Plan(
        create_product="demo",
        create_components=[_planned("backend", augmentation="profile", profile_id="profile_42")],
    )
    state = _state(tmp_path, plan)

    apply_plan(state, _opts(tmp_path))

    patch_calls = state.api.patch_component.call_args_list
    assert patch_calls
    last_call = patch_calls[-1]
    assert last_call.kwargs["contact_profile_id"] == "profile_42"


def test_apply_plan_writes_local_sbomify_json(tmp_path):
    target = tmp_path / "backend" / "sbomify.json"
    plan = Plan(
        create_product="demo",
        create_components=[
            _planned(
                "backend",
                repo_root=tmp_path,
                augmentation="local",
                sbomify_json={"supplier": {"name": "ACME"}},
            ),
        ],
        sbomify_json_files=[(target, {"supplier": {"name": "ACME"}})],
    )
    state = _state(tmp_path, plan)

    apply_plan(state, _opts(tmp_path))

    assert target.exists()
    assert "ACME" in target.read_text()


def test_apply_plan_creates_initial_release_when_tag_strategy_present(tmp_path):
    plan = Plan(
        create_product="demo",
        create_components=[_planned("backend", release_strategy="tag")],
        create_initial_release=True,
    )
    state = _state(tmp_path, plan)

    apply_plan(state, _opts(tmp_path))

    state.api.create_release.assert_called_once()


def test_apply_plan_propagates_api_errors(tmp_path):
    plan = Plan(create_product="demo", create_components=[_planned("backend")])
    state = _state(tmp_path, plan)
    state.api.create_product.side_effect = SbomifyAPIError(500, "boom")

    with pytest.raises(SbomifyAPIError):
        apply_plan(state, _opts(tmp_path))


def test_apply_plan_records_progress_in_state_applied(tmp_path):
    plan = Plan(create_product="demo", create_components=[_planned("backend")])
    state = _state(tmp_path, plan)

    apply_plan(state, _opts(tmp_path))

    joined = " | ".join(state.applied)
    assert "created product" in joined
    assert "created component" in joined
