"""Filesystem helpers for the wizard's apply phase.

The wizard writes one canonical workflow file
(``.github/workflows/sboms.yml``) and, when the user picks the
json_config augmentation strategy, a ``sbomify.json`` at the repo
root. Both writes enforce a header-sentinel contract:

- If the file is absent, write it.
- If it's present and carries the sentinel marker, overwrite it
  (git is the source of truth for the previous version).
- If it's present *without* the sentinel, refuse — the user hand-wrote
  or hand-edited the file and we won't clobber it silently.

Backup policy differs by file. For **workflow** files we deliberately
do **not** create ``.bak`` copies: ``.github/workflows/`` is under git
control, so checking in both a ``foo.yml`` and a ``foo.yml.bak`` is
noise next to ``git diff`` and ``git restore``. For **sbomify.json**,
which the user sometimes hand-edits between runs, ``write_sbomify_json``
keeps a one-shot ``sbomify.json.bak`` of the previous content when an
overwrite would change it — see that function for the rationale.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Marker the emitter writes on line 2 of every generated workflow. The
# emitted line appends the generating build's version (eg.
# ``# sbomify-action wizard v26.7.0``; older releases wrote a literal
# ``v1``), so ownership detection matches this version-agnostic
# prefix — files stamped by any wizard version stay recognised.
WIZARD_HEADER_SENTINEL = "# sbomify-action wizard"

# Top-level key on every wizard-generated sbomify.json. Its presence
# (any value) is the ownership marker; the version number is reserved
# for future migration tooling and does not gate the overwrite check.
WIZARD_JSON_SENTINEL_KEY = "__sbomify_wizard__"
WIZARD_JSON_SENTINEL_VALUE: dict[str, Any] = {"managed": True, "version": 1}


class WorkflowOwnershipError(Exception):
    """Raised when a workflow file exists but wasn't written by the wizard.

    The wizard refuses to overwrite hand-authored workflows: the safer
    failure mode is to ask the user to delete the file (or add the
    sentinel) than to silently clobber bespoke configuration.
    """


class SbomifyJsonOwnershipError(Exception):
    """Raised when sbomify.json exists but wasn't written by the wizard.

    Mirrors WorkflowOwnershipError. The wizard refuses to clobber a
    hand-authored sbomify.json that may carry fields the wizard form
    doesn't surface (eg. ``licenses``, ``vcs_*``, multi-entity
    suppliers).
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


def sbomify_json_has_wizard_sentinel(path: Path) -> bool:
    """True iff ``path`` is a JSON object that carries the wizard sentinel
    key at the top level.

    Tolerates malformed JSON / unreadable files by returning False —
    treating them as "not ours" is the safer default for the ownership
    check.
    """
    if not path.exists():
        return False
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and WIZARD_JSON_SENTINEL_KEY in data


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


def write_sbomify_json(path: Path, payload: dict[str, Any]) -> None:
    """Write a wizard-stamped sbomify.json at ``path``.

    Mirrors ``write_workflow``: refuses to overwrite a file that exists
    but lacks the wizard sentinel key, so a hand-crafted sbomify.json
    is never silently clobbered. The sentinel key is injected before
    serialisation; the action's json_config provider ignores unknown
    top-level keys so its presence doesn't change runtime behaviour.

    When the existing wizard-stamped file's content differs from what we're
    about to write, the previous version is saved next to it as
    ``sbomify.json.bak``. Unlike workflow files (which the wizard treats
    as fully wizard-owned because they live under ``.github/workflows``
    and are git-tracked), sbomify.json carries metadata the user
    sometimes hand-edits between runs (extra licenses, custom contacts)
    — keeping a one-shot ``.bak`` lets the user recover that work
    without rummaging through git for an unstaged file. We never write a
    ``.bak`` for byte-identical writes (re-running the wizard with no
    edits) so the bak doesn't get spuriously refreshed with the same
    content on every dry-run-then-real cycle.
    """
    if path.exists() and not sbomify_json_has_wizard_sentinel(path):
        raise SbomifyJsonOwnershipError(
            f"{path} exists but does not appear to be wizard-generated "
            f"(missing top-level '{WIZARD_JSON_SENTINEL_KEY}' key). "
            "Refusing to overwrite. Delete the file or add the key "
            '(e.g. \'"__sbomify_wizard__": {"managed": true}\') to '
            "allow the wizard to manage it."
        )
    # Sentinel goes AFTER the payload spread so a payload that happens
    # to contain ``__sbomify_wizard__`` (eg. round-tripped from an
    # earlier wizard write) cannot override or erase it. Without this
    # ordering, a stale or maliciously-crafted payload could strip the
    # ownership marker and silently take over future re-runs.
    stamped: dict[str, Any] = {**payload, WIZARD_JSON_SENTINEL_KEY: WIZARD_JSON_SENTINEL_VALUE}
    serialized = json.dumps(stamped, indent=2, sort_keys=True) + "\n"
    if path.exists():
        try:
            previous = path.read_text(encoding="utf-8")
        except OSError:
            previous = None
        if previous is not None and previous != serialized:
            path.with_suffix(path.suffix + ".bak").write_text(previous, encoding="utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")
