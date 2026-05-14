"""Tests for `detect_existing_workflows` — the grep+parse pass that picks
up sbomify workflows the user already wired up on a previous run."""

from __future__ import annotations

import textwrap
from pathlib import Path

from sbomify_action.cli.wizard.existing import detect_existing_workflows


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip("\n"))


def test_no_workflows_dir_returns_empty(tmp_path: Path) -> None:
    assert detect_existing_workflows(tmp_path) == []


def test_ignores_non_sbomify_workflows(tmp_path: Path) -> None:
    _write(
        tmp_path / ".github" / "workflows" / "lint.yml",
        """
        name: lint
        on: push
        jobs:
          lint:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: echo lint
        """,
    )
    assert detect_existing_workflows(tmp_path) == []


def test_parses_tag_strategy_workflow(tmp_path: Path) -> None:
    _write(
        tmp_path / ".github" / "workflows" / "sbomify-svc.yml",
        """
        name: sbomify - svc
        on:
          push:
            branches: [main]
            tags: ['v*']
          workflow_dispatch:
        jobs:
          sbom:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: sbomify/sbomify-action@master
                env:
                  COMPONENT_ID: comp_abc
                  LOCK_FILE: uv.lock
                  AUGMENT: 'true'
                  API_BASE_URL: https://app.sbomify.com
        """,
    )
    found = detect_existing_workflows(tmp_path)
    assert len(found) == 1
    wf = found[0]
    assert wf.component_id == "comp_abc"
    assert wf.lockfile_rel_path == Path("uv.lock")
    assert wf.release_strategy == "tag"
    assert wf.augment is True
    assert wf.api_base_url == "https://app.sbomify.com"


def test_infers_latest_strategy(tmp_path: Path) -> None:
    _write(
        tmp_path / ".github" / "workflows" / "sbomify-x.yml",
        """
        name: sbomify - x
        on:
          push:
            branches: [main]
          workflow_dispatch:
        jobs:
          sbom:
            steps:
              - uses: sbomify/sbomify-action@master
                env:
                  COMPONENT_ID: c1
                  LOCK_FILE: a.lock
        """,
    )
    [wf] = detect_existing_workflows(tmp_path)
    assert wf.release_strategy == "latest"


def test_infers_manual_strategy(tmp_path: Path) -> None:
    _write(
        tmp_path / ".github" / "workflows" / "sbomify-y.yml",
        """
        name: sbomify - y
        on:
          workflow_dispatch:
            inputs:
              version:
                required: false
        jobs:
          sbom:
            steps:
              - uses: sbomify/sbomify-action@master
                env:
                  COMPONENT_ID: c1
                  LOCK_FILE: a.lock
        """,
    )
    [wf] = detect_existing_workflows(tmp_path)
    assert wf.release_strategy == "manual"


def test_picks_up_hand_renamed_workflow(tmp_path: Path) -> None:
    """The detector must not rely on the `sbomify-*.yml` naming convention —
    if someone renamed it, we should still recognise the action call."""
    _write(
        tmp_path / ".github" / "workflows" / "sbom-renamed-by-hand.yaml",
        """
        name: my custom sbom job
        on:
          push:
            branches: [main]
        jobs:
          sbom:
            steps:
              - uses: sbomify/sbomify-action@v1.2.3
                env:
                  COMPONENT_ID: c2
                  LOCK_FILE: backend/poetry.lock
                  AUGMENT: 'false'
        """,
    )
    [wf] = detect_existing_workflows(tmp_path)
    assert wf.path.name == "sbom-renamed-by-hand.yaml"
    assert wf.component_id == "c2"
    assert wf.lockfile_rel_path == Path("backend/poetry.lock")
    assert wf.augment is False


def test_tolerates_malformed_yaml(tmp_path: Path) -> None:
    """A broken file that still mentions the action shouldn't crash the wizard."""
    _write(
        tmp_path / ".github" / "workflows" / "sbomify-broken.yml",
        """
        name: sbomify - broken
        on: push
        jobs:
          sbom:
            steps:
              - uses: sbomify/sbomify-action@master
                env:
                  THIS_IS: { unbalanced
        """,
    )
    # Parser logs and skips; no exception escapes.
    assert detect_existing_workflows(tmp_path) == []


def test_action_called_without_env_block(tmp_path: Path) -> None:
    """If the action is invoked without env (unusual but legal), we still
    surface the file so downstream code can warn about it — just with
    None fields."""
    _write(
        tmp_path / ".github" / "workflows" / "sbomify-bare.yml",
        """
        name: sbomify - bare
        on: push
        jobs:
          sbom:
            steps:
              - uses: sbomify/sbomify-action@master
        """,
    )
    [wf] = detect_existing_workflows(tmp_path)
    assert wf.component_id is None
    assert wf.lockfile_rel_path is None
    assert wf.augment is None
