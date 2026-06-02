"""Top-level options passed into the wizard from the CLI layer.

Split out of ``app.py`` so non-Textual modules (state, ci_emitter,
tests) can import the dataclass cheaply, without dragging Textual's
import side effects along.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WizardOptions:
    """CLI-level options the user passed to ``sbomify-action wizard``."""

    token: str | None
    api_base_url: str
    repo_root: Path
    output_dir: Path
    """Where the emitted workflow lives, validated to be
    ``<repo_root>/.github/workflows/`` by the CLI layer. The wizard
    itself doesn't route writes through this — ``workflow_path()``
    hardcodes ``<repo_root>/.github/workflows/sboms.yml`` per the
    "one canonical filename" design decision. The field exists so
    the CLI flag (``--output-dir``) keeps a stable parsing surface
    and can reject misconfigured invocations before launching the
    TUI; if a future PR ever wants to allow alternative paths,
    plumb this value through ``workflow_path`` then. Removing the
    flag would be a CLI break, so we keep it as a no-op constraint."""
    dry_run: bool
    debug: bool = False
    """True when ``--debug`` was passed. The CLI layer captures DEBUG
    logs to an in-memory buffer that's dumped to stdout once the TUI
    exits — screens can read this flag to show extra detail in their
    UI if they want."""
