"""Shared filesystem helpers used by the wizard's apply phase."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from sbomify_action.logging_config import logger


def write_config(config: dict[str, Any], path: Path, *, backup: bool = True) -> bool:
    """Write a sbomify.json configuration to disk, with optional backup.

    Args:
        config: Configuration dict to serialize.
        path: Destination path.
        backup: If True and path exists, copy it to ``<path>.bak`` first.

    Returns:
        True on success, False on OSError.
    """
    try:
        if backup and path.exists():
            backup_path = path.with_suffix(path.suffix + ".bak")
            shutil.copy2(path, backup_path)
            logger.info(f"Backup created: {backup_path}")

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            f.write("\n")

        return True
    except OSError as e:
        logger.warning(f"Failed to write config: {e}")
        return False
