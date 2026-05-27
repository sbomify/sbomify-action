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
    dry_run: bool
