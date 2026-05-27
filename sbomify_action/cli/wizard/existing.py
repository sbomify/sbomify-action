"""Detect an existing wizard-managed workflow at startup.

The wizard owns exactly one filename — ``.github/workflows/sboms.yml``
— and stamps every file it writes with a sentinel comment (see
``io.WIZARD_HEADER_SENTINEL``). This module is the entire detection
surface: ``does our file exist? does it carry our sentinel?``. No
YAML parsing, no grep over arbitrary workflow files, no inference of
intent from ``on:`` triggers.

If the file exists with the sentinel → the apply phase will overwrite
it (after .bak backup). If it exists *without* the sentinel → the
apply phase will refuse with a clear error.
"""

from __future__ import annotations

from pathlib import Path

from sbomify_action.cli.wizard.io import file_has_wizard_header

WIZARD_WORKFLOW_FILENAME = "sboms.yml"


def workflow_path(repo_root: Path) -> Path:
    """Return the absolute path to the wizard-owned workflow file."""
    return repo_root / ".github" / "workflows" / WIZARD_WORKFLOW_FILENAME


def wizard_workflow_exists(repo_root: Path) -> bool:
    """True iff a wizard-stamped ``sboms.yml`` already lives in the repo."""
    return file_has_wizard_header(workflow_path(repo_root))
