"""Shared filesystem helpers used by both the init and wizard runners."""

import json
import shutil
from pathlib import Path
from typing import Any

from sbomify_action.cli.wizard.prompts import print_info, print_warning


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
            print_info(f"Backup created: {backup_path}")

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            f.write("\n")

        return True
    except OSError as e:
        print_warning(f"Failed to write config: {e}")
        return False
