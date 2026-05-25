"""Detect pre-existing sbomify workflow files in a repository.

When the wizard is re-run on a repo that already has sbomify wired up,
we want to pick up the existing configuration so we don't ask the user
to fill in the same fields again. This module finds and minimally parses
those workflow files.

Detection strategy: cheap grep for `sbomify/sbomify-action` in any YAML
under `.github/workflows/`. We don't rely on the wizard's emitted
filename pattern, so hand-renamed or hand-edited workflows still get
picked up. For each match we do a lenient YAML parse to pull the env
block and the `on:` triggers. Anything we can't pin down stays `None`
and the wizard treats it as not-yet-configured for that attribute.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from sbomify_action.cli.wizard.state import ReleaseStrategy
from sbomify_action.logging_config import logger

# Marker we look for in the file body. Matches `uses: sbomify/sbomify-action@...`
# and any future hand-edits that still call the action.
_ACTION_MARKER = "sbomify/sbomify-action"

# Only .github/workflows/ for now — that's the only CI provider the wizard
# emits templates for. If/when GitLab/CircleCI templates land they get their
# own search paths here.
_SEARCH_DIRS: tuple[tuple[str, ...], ...] = ((".github", "workflows"),)
_YAML_EXTS = (".yml", ".yaml")


@dataclass(frozen=True)
class ExistingWorkflow:
    """A previously-configured sbomify workflow we found on disk."""

    path: Path
    """Absolute path to the workflow file."""

    component_id: str | None
    """COMPONENT_ID env value, or None if missing."""

    lockfile_rel_path: Path | None
    """LOCK_FILE env value as a path relative to the repo root, or None."""

    release_strategy: ReleaseStrategy | None
    """Inferred from the `on:` block: tag/latest/manual, None when ambiguous."""

    augment: bool | None
    """AUGMENT env value as a bool, None if not set."""

    api_base_url: str | None
    """API_BASE_URL env value, None if not set."""


def detect_existing_workflows(repo_root: Path) -> list[ExistingWorkflow]:
    """Find every YAML in known CI folders that calls `sbomify/sbomify-action`."""
    found: list[ExistingWorkflow] = []
    for parts in _SEARCH_DIRS:
        directory = repo_root.joinpath(*parts)
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if not path.is_file() or path.suffix.lower() not in _YAML_EXTS:
                continue
            if not _file_mentions_action(path):
                continue
            try:
                parsed = _parse_workflow(path)
            except Exception as e:  # noqa: BLE001 — never let a malformed file crash the wizard
                logger.debug(f"Could not parse {path}: {e}")
                continue
            if parsed is not None:
                found.append(parsed)
    return found


def _file_mentions_action(path: Path) -> bool:
    """Quick string check: does this file contain `sbomify/sbomify-action`?"""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return _ACTION_MARKER in f.read()
    except OSError:
        return False


def _parse_workflow(path: Path) -> ExistingWorkflow | None:
    """Light YAML parse — only the bits we need to pre-fill the wizard."""
    with open(path, encoding="utf-8") as f:
        document = yaml.safe_load(f)
    if not isinstance(document, dict):
        return None

    env = _find_action_step_env(document)
    if env is None:
        # File mentioned the action but no step exposed the action's env;
        # could be a hand-edit. Surface the path with empty fields so the
        # caller can still warn about conflicts.
        env = {}

    component_id = _str_or_none(env.get("COMPONENT_ID"))
    lockfile = env.get("LOCK_FILE")
    lockfile_path = Path(str(lockfile)) if isinstance(lockfile, str) and lockfile else None

    augment_raw = env.get("AUGMENT")
    augment: bool | None
    if isinstance(augment_raw, bool):
        augment = augment_raw
    elif isinstance(augment_raw, str):
        augment = augment_raw.strip().lower() in {"true", "1", "yes", "on"}
    else:
        augment = None

    return ExistingWorkflow(
        path=path,
        component_id=component_id,
        lockfile_rel_path=lockfile_path,
        release_strategy=_infer_release_strategy(document),
        augment=augment,
        api_base_url=_str_or_none(env.get("API_BASE_URL")),
    )


def _find_action_step_env(document: dict[str, Any]) -> dict[str, Any] | None:
    """Walk jobs/steps looking for the `sbomify/sbomify-action` step's env."""
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return None
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if not isinstance(uses, str) or _ACTION_MARKER not in uses:
                continue
            env = step.get("env")
            return env if isinstance(env, dict) else {}
    return None


def _infer_release_strategy(document: dict[str, Any]) -> ReleaseStrategy | None:
    """Map the workflow's `on:` triggers back to one of our release strategies.

    Emitter contract:
      - tag    : push.branches + push.tags=['v*'] + workflow_dispatch
      - latest : push.branches + workflow_dispatch
      - manual : workflow_dispatch only (with `inputs.version`)
    """
    # YAML parses bare `on:` as the boolean key `True` in some edge cases
    # (the "Norway problem"-adjacent quirk for the literal `on`). The dict
    # is typed as ``dict[str, Any]`` but YAML can return ``dict[Any, Any]``,
    # so the True lookup goes through the cast to keep mypy happy.
    on_block = document.get("on")
    if on_block is None:
        on_block = cast("dict[Any, Any]", document).get(True)
    if not isinstance(on_block, dict):
        return None

    push = on_block.get("push")
    dispatch = "workflow_dispatch" in on_block

    if isinstance(push, dict):
        if push.get("tags"):
            return "tag"
        if push.get("branches"):
            return "latest"
    if dispatch and push is None:
        return "manual"
    return None


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
