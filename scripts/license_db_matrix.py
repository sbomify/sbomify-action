#!/usr/bin/env python3
"""Emit the GitHub Actions build matrix for the license databases.

.github/workflows/license-db.yaml used to hardcode every (distro, version) pair,
which meant adding a distro release took three edits -- lifecycle_data.py, the
generator's repository config, and the workflow -- and forgetting the third was
silent: the release simply never got a database built.

The matrix is now derived from the generator's own configuration, so the
workflow cannot fall behind the code. check_lifecycle_staleness.py separately
verifies that the generator's version list and lifecycle_data.py agree.

Usage:
    python scripts/license_db_matrix.py               # {"include": [...]}
    python scripts/license_db_matrix.py --pretty      # readable
    python scripts/license_db_matrix.py --distros alpine,ubuntu
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbomify_action._enrichment.license_db_generator import (  # noqa: E402
    DEBIAN_CODENAMES,
    RPM_DISTRO_REPOS,
    UBUNTU_CODENAMES,
)
from sbomify_action._enrichment.lifecycle_data import DISTRO_LIFECYCLE  # noqa: E402


def _version_sort_key(version: str) -> tuple:
    """Sort '3.9' before '3.10', and 'stream8' before 'stream10'."""
    digits = "".join(c if c.isdigit() or c == "." else " " for c in version).split()
    try:
        return (0, [int(part) for part in ".".join(digits).split(".") if part])
    except ValueError:
        return (1, version)


def build_matrix() -> list[dict[str, str]]:
    """Every (distro, version) pair the generator can build, in a stable order."""
    versions: dict[str, list[str]] = {
        # Alpine builds its repository URL from the version string, so every
        # release we track lifecycle data for is buildable.
        "alpine": list(DISTRO_LIFECYCLE.get("alpine", {})),
        "wolfi": ["rolling"],
        "ubuntu": list(UBUNTU_CODENAMES),
        "debian": list(DEBIAN_CODENAMES),
    }
    for distro, repos in RPM_DISTRO_REPOS.items():
        versions[distro] = list(repos)

    entries: list[dict[str, str]] = []
    for distro in sorted(versions):
        for version in sorted(versions[distro], key=_version_sort_key):
            entries.append({"distro": distro, "version": version})
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pretty", action="store_true", help="indent the JSON")
    parser.add_argument(
        "--distros",
        help="comma-separated subset of distros to include, or 'all' (default: all)",
    )
    args = parser.parse_args()

    entries = build_matrix()

    if args.distros and args.distros.strip().lower() != "all":
        wanted = {d.strip().lower() for d in args.distros.split(",") if d.strip()}
        unknown = wanted - {e["distro"] for e in entries}
        if unknown:
            print(f"unknown distro(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        entries = [e for e in entries if e["distro"] in wanted]

    if not entries:
        print("refusing to emit an empty matrix", file=sys.stderr)
        return 2

    print(json.dumps({"include": entries}, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
