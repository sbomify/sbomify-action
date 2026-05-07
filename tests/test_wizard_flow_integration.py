"""End-to-end flow tests for the wizard.

These tests drive ``run_wizard_flow`` with a mocked sbomify client and
canned answers to every interactive prompt. They focus on the
plan-first / write-last guarantees and the overall orchestration; the
unit-level behaviour of each phase is covered elsewhere.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sbomify_action.cli.wizard import wizard_runner
from sbomify_action.cli.wizard.wizard_runner import WizardOptions, run_wizard_flow


@pytest.fixture
def repo_with_lockfile(tmp_path: Path) -> Path:
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "poetry.lock").write_text("[metadata]\n")
    return tmp_path


def _make_client(monkeypatch) -> MagicMock:
    """Replace SbomifyClient with a MagicMock instance."""
    client = MagicMock()
    client.whoami.return_value = {"authenticated": True}
    client.list_products.return_value = []
    client.list_components.return_value = []
    client.list_contact_profiles.return_value = []
    client.create_product.return_value = {"id": "prod_new", "name": "demo"}
    client.ensure_default_project.return_value = {"id": "proj_default", "name": "demo-default"}
    client.create_component.return_value = {"id": "comp_1", "name": "backend"}

    def factory(*_args, **_kwargs):
        return client

    monkeypatch.setattr(wizard_runner, "SbomifyClient", factory)
    return client


def _patch_prompts(
    monkeypatch,
    *,
    confirm_answers: list[bool],
    select_answers: list[str | None],
    text_answers: list[str],
    checkbox_answers: list[list[str]] | None = None,
) -> None:
    """Drive each prompt helper with a queue of canned answers."""
    confirms = iter(confirm_answers)
    selects = iter(select_answers)
    texts = iter(text_answers)
    checkboxes = iter(checkbox_answers or [])

    def fake_confirm(*_a, **_kw):
        return next(confirms)

    def fake_select(*_a, **_kw):
        return next(selects)

    def fake_text(*_a, **_kw):
        return next(texts)

    def fake_checkbox(*_a, **_kw):
        return next(checkboxes)

    for module in (wizard_runner, "sbomify_action.cli.wizard.mapping"):
        target = module if not isinstance(module, str) else __import__(module, fromlist=["*"])
        monkeypatch.setattr(target, "ask_confirm", fake_confirm)
        monkeypatch.setattr(target, "ask_select", fake_select)
        monkeypatch.setattr(target, "ask_text", fake_text)
        if hasattr(target, "ask_checkbox"):
            monkeypatch.setattr(target, "ask_checkbox", fake_checkbox)


def _force_tty(monkeypatch) -> None:
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)


def _disable_pr_phase(monkeypatch) -> None:
    """Default for tests that don't exercise the PR flow."""
    monkeypatch.setattr(wizard_runner, "_gh_authenticated", lambda: False)


def test_non_tty_exits_with_warning(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    rc = run_wizard_flow(
        WizardOptions(
            token="tok",
            api_base_url="https://app.sbomify.com",
            repo_root=tmp_path,
            output_dir=tmp_path / ".github" / "workflows",
            dry_run=False,
        )
    )
    assert rc == 1


def test_initial_decline_makes_no_api_calls(monkeypatch, repo_with_lockfile):
    _force_tty(monkeypatch)
    _disable_pr_phase(monkeypatch)
    client = _make_client(monkeypatch)
    _patch_prompts(
        monkeypatch,
        confirm_answers=[False],  # decline at the welcome screen
        select_answers=[],
        text_answers=[],
        checkbox_answers=[],
    )

    rc = run_wizard_flow(
        WizardOptions(
            token="tok",
            api_base_url="https://app.sbomify.com",
            repo_root=repo_with_lockfile,
            output_dir=repo_with_lockfile / ".github" / "workflows",
            dry_run=False,
        )
    )

    assert rc == 1
    client.create_product.assert_not_called()
    client.create_component.assert_not_called()
    assert not (repo_with_lockfile / ".github" / "workflows").exists()


def test_happy_path_writes_workflow_and_calls_api(monkeypatch, repo_with_lockfile):
    _force_tty(monkeypatch)
    _disable_pr_phase(monkeypatch)
    client = _make_client(monkeypatch)
    _patch_prompts(
        monkeypatch,
        confirm_answers=[
            True,  # welcome continue
            True,  # apply review
            False,  # decline local SBOM generation
        ],
        select_answers=[
            "__create_new__",  # product picker → create new
            "skip",  # component details
            "latest",  # release strategy
        ],
        text_answers=[
            "demo",  # product name
            "backend",  # component name
        ],
        checkbox_answers=[["backend/poetry.lock"]],
    )

    rc = run_wizard_flow(
        WizardOptions(
            token="tok",
            api_base_url="https://app.sbomify.com",
            repo_root=repo_with_lockfile,
            output_dir=repo_with_lockfile / ".github" / "workflows",
            dry_run=False,
        )
    )

    assert rc == 0
    client.create_product.assert_called_once_with("demo")
    client.create_component.assert_called_once()
    workflow = repo_with_lockfile / ".github" / "workflows" / "sbomify-backend.yml"
    assert workflow.exists()
    content = workflow.read_text()
    assert "COMPONENT_ID: comp_1" in content
    assert "PRODUCT_RELEASE" not in content


def test_dry_run_walks_phases_without_api_calls_or_files(monkeypatch, repo_with_lockfile):
    _force_tty(monkeypatch)
    _disable_pr_phase(monkeypatch)
    client = _make_client(monkeypatch)
    _patch_prompts(
        monkeypatch,
        confirm_answers=[True],  # welcome continue
        select_answers=[
            "__create_new__",
            "skip",
            "latest",
        ],
        text_answers=["demo", "backend"],
        checkbox_answers=[["backend/poetry.lock"]],
    )

    rc = run_wizard_flow(
        WizardOptions(
            token="tok",
            api_base_url="https://app.sbomify.com",
            repo_root=repo_with_lockfile,
            output_dir=repo_with_lockfile / ".github" / "workflows",
            dry_run=True,
        )
    )

    assert rc == 0
    client.create_product.assert_not_called()
    client.create_component.assert_not_called()
    assert not (repo_with_lockfile / ".github" / "workflows").exists()


def test_generation_prompt_invokes_pipeline_per_component(monkeypatch, repo_with_lockfile):
    _force_tty(monkeypatch)
    client = _make_client(monkeypatch)
    client.token = "tok"

    pipeline_calls: list[tuple[str, str]] = []

    def fake_build_config(**kwargs):
        return {"_kwargs": kwargs}

    def fake_run_pipeline(config):
        pipeline_calls.append((config["_kwargs"]["component_id"], config["_kwargs"]["lock_file"]))

    import sys

    import sbomify_action.cli.main  # noqa: F401  ensure submodule loaded

    cli_main_module = sys.modules["sbomify_action.cli.main"]
    monkeypatch.setattr(cli_main_module, "build_config", fake_build_config)
    monkeypatch.setattr(cli_main_module, "run_pipeline", fake_run_pipeline)

    _patch_prompts(
        monkeypatch,
        confirm_answers=[
            True,  # welcome
            True,  # apply review
            True,  # generate now
        ],
        select_answers=["__create_new__", "skip", "latest"],
        text_answers=["demo", "backend"],
        checkbox_answers=[["backend/poetry.lock"]],
    )

    rc = run_wizard_flow(
        WizardOptions(
            token="tok",
            api_base_url="https://app.sbomify.com",
            repo_root=repo_with_lockfile,
            output_dir=repo_with_lockfile / ".github" / "workflows",
            dry_run=False,
        )
    )

    assert rc == 0
    assert pipeline_calls == [("comp_1", str(repo_with_lockfile / "backend" / "poetry.lock"))]


def test_generation_prompt_can_be_declined(monkeypatch, repo_with_lockfile):
    _force_tty(monkeypatch)
    client = _make_client(monkeypatch)

    # Sentinel: if run_pipeline is invoked, the test fails.
    def explode(*_a, **_kw):
        raise AssertionError("pipeline must not run when user declines")

    import sys

    import sbomify_action.cli.main  # noqa: F401

    cli_main_module = sys.modules["sbomify_action.cli.main"]
    monkeypatch.setattr(cli_main_module, "build_config", explode)
    monkeypatch.setattr(cli_main_module, "run_pipeline", explode)

    _patch_prompts(
        monkeypatch,
        confirm_answers=[True, True, False],
        select_answers=["__create_new__", "skip", "latest"],
        text_answers=["demo", "backend"],
        checkbox_answers=[["backend/poetry.lock"]],
    )

    rc = run_wizard_flow(
        WizardOptions(
            token="tok",
            api_base_url="https://app.sbomify.com",
            repo_root=repo_with_lockfile,
            output_dir=repo_with_lockfile / ".github" / "workflows",
            dry_run=False,
        )
    )

    assert rc == 0
    client.create_component.assert_called_once()


def test_no_lockfiles_exits_with_warning(monkeypatch, tmp_path):
    _force_tty(monkeypatch)
    _disable_pr_phase(monkeypatch)
    client = _make_client(monkeypatch)
    _patch_prompts(
        monkeypatch,
        confirm_answers=[True],
        select_answers=[],
        text_answers=[],
        checkbox_answers=[],
    )

    rc = run_wizard_flow(
        WizardOptions(
            token="tok",
            api_base_url="https://app.sbomify.com",
            repo_root=tmp_path,
            output_dir=tmp_path / ".github" / "workflows",
            dry_run=False,
        )
    )

    assert rc == 1
    client.list_products.assert_not_called()
