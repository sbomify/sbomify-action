"""Filesystem helpers for the wizard's apply phase.

The wizard writes one canonical workflow file
(``.github/workflows/sboms.yml``) and never touches anything else on
disk. ``write_workflow`` enforces the header-sentinel contract:

- If the file is absent, write it.
- If it's present and carries the sentinel comment, overwrite it
  (git is the source of truth for the previous version).
- If it's present *without* the sentinel, refuse — the user hand-wrote
  or hand-edited the file and we won't clobber it silently.

We deliberately do **not** create ``.bak`` files. The wizard targets
``.github/workflows/`` which is always under git control; checking in
both a ``foo.yml`` and a ``foo.yml.bak`` is noise next to ``git diff``
and ``git restore``.
"""

from __future__ import annotations

from pathlib import Path

# Marker the emitter writes on line 2 of every generated workflow.
WIZARD_HEADER_SENTINEL = "# sbomify-action wizard v1"


class WorkflowOwnershipError(Exception):
    """Raised when a workflow file exists but wasn't written by the wizard.

    The wizard refuses to overwrite hand-authored workflows: the safer
    failure mode is to ask the user to delete the file (or add the
    sentinel) than to silently clobber bespoke configuration.
    """


def file_has_wizard_header(path: Path) -> bool:
    """True iff ``path`` exists and its first ~20 lines contain the sentinel.

    Reads only the head of the file so we don't pay for a full read on
    huge YAMLs that happen to share the name. Twenty lines is enough to
    cover any sane comment header.
    """
    if not path.exists():
        return False
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for _ in range(20):
                line = f.readline()
                if not line:
                    break
                if WIZARD_HEADER_SENTINEL in line:
                    return True
    except OSError:
        return False
    return False


def write_workflow(path: Path, content: str) -> None:
    """Write the wizard's workflow file at ``path``.

    Raises ``WorkflowOwnershipError`` if the file exists but has no
    sentinel — the apply phase translates that into a clear error
    message. Otherwise overwrites in-place; git tracks the previous
    version so we don't bother with ``.bak``.
    """
    if path.exists() and not file_has_wizard_header(path):
        raise WorkflowOwnershipError(
            f"{path} exists but does not appear to be wizard-generated "
            f"(missing '{WIZARD_HEADER_SENTINEL}' header). Refusing to "
            "overwrite. Delete the file or add the header to allow "
            "the wizard to manage it."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
