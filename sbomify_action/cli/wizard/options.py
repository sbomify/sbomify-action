"""User-supplied options for the Textual wizard.

Separated from `app.py` so screens can import the dataclass without
pulling Textual at import time (keeps test imports cheap and avoids a
circular dep with `cli/main.py`).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WizardOptions:
    """CLI-level options the user passed to `sbomify-action wizard`."""

    token: str | None
    api_base_url: str
    repo_root: Path
    output_dir: Path
    dry_run: bool
