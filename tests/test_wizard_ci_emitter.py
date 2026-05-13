"""Tests for sbomify_action.cli.wizard.ci_emitter."""

from __future__ import annotations

from pathlib import Path

import pytest

from sbomify_action.cli.wizard import ci_emitter
from sbomify_action.cli.wizard.state import (
    DiscoveredLockfile,
    Plan,
    PlannedComponent,
)


def _planned(
    name: str = "backend",
    rel_path: str = "backend/poetry.lock",
    ecosystem: str = "python",
    *,
    release_strategy: str = "latest",
) -> PlannedComponent:
    rel = Path(rel_path)
    return PlannedComponent(
        lockfile=DiscoveredLockfile(
            path=Path("/repo") / rel,
            rel_path=rel,
            ecosystem=ecosystem,
            suggested_name=name,
        ),
        name=name,
        release_strategy=release_strategy,  # type: ignore[arg-type]
    )


def _render(strategy: str, **overrides) -> str:
    kwargs = {
        "component_name": "backend",
        "component_id": "comp_001",
        "product_id": "prod_abc",
        "lock_file_rel": "backend/poetry.lock",
        "api_base_url": "https://app.sbomify.com",
        "release_strategy": strategy,
    }
    kwargs.update(overrides)
    return ci_emitter.render_workflow(**kwargs)


def test_render_latest_has_short_sha_and_no_release_tagging():
    out = _render("latest")
    assert "git rev-parse --short HEAD" in out
    assert "PRODUCT_RELEASE" not in out
    assert "tags: ['v*']" not in out
    assert "COMPONENT_ID: comp_001" in out
    assert "TODO: OIDC token wiring is pending" in out


def test_render_tag_emits_dual_triggers_and_release():
    out = _render("tag")
    assert "tags: ['v*']" in out
    assert "PRODUCT_RELEASE" in out
    assert "prod_abc" in out
    assert "GITHUB_REF_TYPE" in out


def test_render_manual_only_workflow_dispatch():
    out = _render("manual")
    assert "workflow_dispatch:" in out
    assert "branches: [" not in out
    assert "tags: ['v*']" not in out
    assert "version:" in out


def test_render_none_includes_disabled_release_note():
    out = _render("none")
    assert "release tracking is disabled" in out
    # Same trigger shape as 'latest'.
    assert "git rev-parse --short HEAD" in out
    assert "PRODUCT_RELEASE" not in out


def test_render_uses_default_branch():
    out = _render("latest", default_branch="trunk")
    assert "branches: [trunk]" in out


def test_workflow_filename_slugifies():
    assert ci_emitter.workflow_filename("Backend / API") == "sbomify-backend-api.yml"
    assert ci_emitter.workflow_filename("backend") == "sbomify-backend.yml"


def test_plan_workflow_files_marks_existing_files_as_skip(tmp_path):
    plan = Plan(create_components=[_planned()])
    existing = tmp_path / "sbomify-backend.yml"
    existing.write_text("existing")

    files = ci_emitter.plan_workflow_files(
        plan=plan,
        output_dir=tmp_path,
        api_base_url="https://app.sbomify.com",
        default_branch="main",
        product_id="prod_abc",
    )

    assert len(files) == 1
    path, _content, action = files[0]
    assert path == existing
    assert action == "skip"


def test_plan_workflow_files_writes_when_no_collision(tmp_path):
    plan = Plan(create_components=[_planned()])
    files = ci_emitter.plan_workflow_files(
        plan=plan,
        output_dir=tmp_path,
        api_base_url="https://app.sbomify.com",
        default_branch="main",
        product_id="prod_abc",
    )
    assert len(files) == 1
    assert files[0][2] == "write"


def test_plan_workflow_files_dedupes_colliding_slugs(tmp_path):
    # "My API" and "my api" both slugify to "my-api"; without dedupe the second
    # component would silently overwrite the first.
    plan = Plan(
        create_components=[
            _planned(name="My API", rel_path="a/poetry.lock"),
            _planned(name="my api", rel_path="b/poetry.lock"),
            _planned(name="MY  API", rel_path="c/poetry.lock"),
        ]
    )
    files = ci_emitter.plan_workflow_files(
        plan=plan,
        output_dir=tmp_path,
        api_base_url="https://app.sbomify.com",
        default_branch="main",
        product_id="prod_abc",
    )
    paths = [path.name for path, _content, _action in files]
    assert paths == [
        "sbomify-my-api.yml",
        "sbomify-my-api-2.yml",
        "sbomify-my-api-3.yml",
    ]
    # The path filter inside each workflow must match its own filename.
    for path, content, _action in files:
        assert f"'.github/workflows/{path.name}'" in content


def test_plan_workflow_files_substitutes_real_component_id(tmp_path):
    plan = Plan(create_components=[_planned()])
    files = ci_emitter.plan_workflow_files(
        plan=plan,
        output_dir=tmp_path,
        api_base_url="https://app.sbomify.com",
        default_branch="main",
        product_id="prod_abc",
        component_ids={Path("backend/poetry.lock"): "comp_real_id"},
    )
    assert "comp_real_id" in files[0][1]


def test_write_workflow_files_dry_run_writes_nothing(tmp_path):
    plan = Plan(create_components=[_planned()])
    files = ci_emitter.plan_workflow_files(
        plan=plan,
        output_dir=tmp_path,
        api_base_url="https://app.sbomify.com",
        default_branch="main",
        product_id="prod_abc",
    )
    written = ci_emitter.write_workflow_files(files, dry_run=True)
    assert written == [tmp_path / "sbomify-backend.yml"]
    assert not (tmp_path / "sbomify-backend.yml").exists()


def test_write_workflow_files_skip_action_does_not_write(tmp_path):
    target = tmp_path / "sbomify-backend.yml"
    target.write_text("untouched")
    files = [(target, "new content", "skip")]
    written = ci_emitter.write_workflow_files(files)
    assert written == []
    assert target.read_text() == "untouched"


def test_write_workflow_files_write_new_creates_dot_new_file(tmp_path):
    target = tmp_path / "sbomify-backend.yml"
    target.write_text("untouched")
    files = [(target, "new content", "write_new")]
    written = ci_emitter.write_workflow_files(files)
    assert written == [tmp_path / "sbomify-backend.yml.new"]
    assert (tmp_path / "sbomify-backend.yml.new").read_text() == "new content"
    assert target.read_text() == "untouched"


@pytest.mark.parametrize("strategy", ["latest", "tag", "manual", "none"])
def test_render_yaml_is_non_empty(strategy):
    out = _render(strategy)
    assert out.strip()
    assert "uses: sbomify/sbomify-action@" in out
    assert "TOKEN: ${{ secrets.SBOMIFY_TOKEN }}" in out
