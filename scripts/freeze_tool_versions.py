#!/usr/bin/env python3
"""Freeze lockfile-derived tool versions into the shipped manifest.

On master the versions live in the ecosystems' own lockfiles -- tools/go.mod
and tools/Cargo.lock -- so Dependabot maintains them and there is no bespoke
version file to keep in step.

Those lockfiles are not part of the Python package, and the published image
has no Go or Cargo toolchain to consult them with. So the image build resolves
them once and writes literal versions into sbomify_action/tools.toml before
the wheel is built. A release therefore hard-codes the versions it was built
against, and will fetch exactly those for as long as it exists -- which is the
only way its SBOM can be telling the truth.

Run with --check to verify a manifest is already frozen (used in CI to catch a
wheel built without this step).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbomify_action.tool_manifest import load_tools, plugin_version  # noqa: E402

MANIFEST = Path(__file__).resolve().parent.parent / "sbomify_action" / "tools.toml"

# version_from = { file = "...", module = "..." }  ->  version = "1.2.3"
_VERSION_FROM = re.compile(r"^version_from\s*=\s*\{[^}]*\}\s*$", re.M)


def freeze(manifest_path: Path, *, check: bool = False) -> int:
    text = manifest_path.read_text()
    if not _VERSION_FROM.search(text):
        print("Manifest is already frozen.")
        return 0
    if check:
        print(f"ERROR: {manifest_path} still resolves versions from lockfiles.", file=sys.stderr)
        print("The wheel would be unable to read them. Run scripts/freeze_tool_versions.py.", file=sys.stderr)
        return 1

    versions = {name: tool.version for name, tool in load_tools().items()}

    out: list[str] = []
    current: str | None = None
    kind: str | None = None
    for line in text.splitlines():
        # [plugin.*] as well as [tool.*]: the JVM plugin versions live in
        # tools/pom.xml and tools/build.gradle, which are no more part of the
        # package than the Go and Cargo lockfiles are. Freezing only [tool.*]
        # shipped a wheel that raised ManifestError on import.
        #
        # The name is matched without dots so nested tables such as
        # [tool.cosign.assets.amd64] do not register as a tool of their own --
        # they have no version to freeze, and resolving them eagerly failed.
        if header := re.match(r"^\[(tool|plugin)\.([^.\]]+)\]", line):
            kind, current = header.group(1), header.group(2)
        if _VERSION_FROM.match(line) and current:
            resolved = plugin_version(current) if kind == "plugin" else versions[current]
            out.append(f'version = "{resolved}"  # frozen from the lockfile at build time')
            print(f"  froze {current} -> {resolved}")
            continue
        out.append(line)

    manifest_path.write_text("\n".join(out) + "\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the manifest is not frozen")
    args = parser.parse_args()
    return freeze(MANIFEST, check=args.check)


if __name__ == "__main__":
    raise SystemExit(main())
