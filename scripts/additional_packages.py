#!/usr/bin/env python3
"""Emit the external tools to add to sbomify-action's own SBOMs.

Replaces the shell script that scraped versions out of the Dockerfile. The
versions now live in sbomify_action/tools.toml, which also records *where*
each tool ends up -- and that distinction is the point.

The image SBOM and the runtime SBOM legitimately describe different software:

    --stage image     what a docker pull actually contains
    --stage runtime   what may be fetched on first use and verified against a
                      pinned digest
    --stage all       both, for a combined view

Listing runtime tools in the image SBOM would claim we ship binaries we do
not, which is exactly the kind of inaccuracy this project exists to prevent.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbomify_action.tool_manifest import (  # noqa: E402
    STAGE_IMAGE,
    STAGE_RUNTIME,
    image_package_urls,
    load_tools,
    runtime_package_urls,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stage",
        choices=[STAGE_IMAGE, STAGE_RUNTIME, "all"],
        default=STAGE_IMAGE,
        help="which set of tools to emit (default: image)",
    )
    parser.add_argument(
        "--env",
        action="store_true",
        help="emit shell assignments (NAME_VERSION=x) instead of PURLs, for `eval`",
    )
    args = parser.parse_args()

    if args.env:
        for name, tool in sorted(load_tools().items()):
            if tool.dockerfile_arg:
                print(f"{tool.dockerfile_arg}={tool.version}")
        return 0

    purls: list[str] = []
    if args.stage in (STAGE_IMAGE, "all"):
        purls += image_package_urls()
    if args.stage in (STAGE_RUNTIME, "all"):
        purls += runtime_package_urls()

    for purl in purls:
        print(purl)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
