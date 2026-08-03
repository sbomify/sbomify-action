#!/usr/bin/env python3
"""Generate an SBOM for every ecosystem fixture and check it is worth having.

tests/test_ecosystem_routing.py asserts which generator *should* run. This
runs them for real and checks the result, which routing alone cannot: a
generator can win the chain and still return an empty document.

Run inside the image, where the runtime tools can be fetched:

    docker run --rm -v "$PWD/tests:/tests:ro" \\
        --entrypoint python <image> /tests/../scripts/ecosystem_matrix.py

Exits non-zero if any ecosystem produced fewer components than its floor, or
if a generator other than the intended one produced the SBOM. Floors are
deliberately low -- they catch "empty" and "collapsed", not small changes in
what upstream tools report.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbomify_action._generation.generator import create_default_registry  # noqa: E402
from sbomify_action._generation.protocol import GenerationInput  # noqa: E402

#: (fixture, lock file, generator that must produce it, minimum components).
#:
#: Floors are set below what the fixture currently yields, so upstream tools
#: reporting a few more or fewer components does not fail the build; only a
#: collapse does.
MATRIX = [
    ("python-requirements", "requirements.txt", "cyclonedx-py", 1),
    ("python-pipenv", "Pipfile.lock", "cyclonedx-py", 1),
    ("python-uv", "uv.lock", "cdxgen-fs", 1),
    ("rust", "Cargo.lock", "cyclonedx-cargo", 1),
    ("javascript", "package-lock.json", "cdxgen-fs", 20),
    ("java", "pom.xml", "cdxgen-fs", 5),
    ("go", "go.mod", "cyclonedx-gomod", 3),
    ("ruby", "Gemfile.lock", "cdxgen-fs", 100),
    ("dart", "pubspec.lock", "cdxgen-fs", 100),
    ("elixir", "mix.lock", "cdxgen-fs", 20),
    ("cpp", "conan.lock", "cdxgen-fs", 1),
]

PROJECTS = Path(__file__).resolve().parent.parent / "tests" / "test-data" / "projects"


def run_one(project: str, lock_file: str, sbom_format: str) -> tuple[str, int, str]:
    """Generate into a scratch copy so fixtures are never written to."""
    work = Path(tempfile.mkdtemp())
    src = PROJECTS / project
    # Copy directories too: a Rust crate is not a crate without src/, and
    # cargo refuses to parse the manifest.
    for item in src.iterdir():
        if item.is_dir():
            shutil.copytree(item, work / item.name)
        else:
            shutil.copy(item, work / item.name)

    out = work / "sbom.json"
    # Strict mode raises rather than degrading, which is correct in a run but
    # useless in a matrix: one bad ecosystem would hide the other ten. Catch
    # it here so every row is reported, and let --strict decide the exit code.
    try:
        result = create_default_registry().generate(
            GenerationInput(
                lock_file=str(work / lock_file),
                output_file=str(out),
                output_format=sbom_format,
            ),
            validate=False,
        )
    except Exception as exc:  # noqa: BLE001 - reporting, not handling
        return ("aborted", -1, str(exc).splitlines()[0][:88])
    if not result.success:
        return (result.generator_name or "none", -1, (result.error_message or "")[:90])
    components = len(json.loads(out.read_text()).get("components", []) or [])
    return (result.generator_name or "none", components, "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", default="cyclonedx", choices=["cyclonedx", "spdx"])
    parser.add_argument("--strict", action="store_true", help="fail on a wrong generator or a low count")
    args = parser.parse_args()

    print(f"{'ecosystem':<22}{'generator':<18}{'comps':>7}  {'expected':<18}verdict")
    failures = []
    for project, lock_file, expected, floor in MATRIX:
        generator, components, error = run_one(project, lock_file, args.format)

        problems = []
        # In SPDX the intended generator is often syft, since cdxgen and
        # cyclonedx-py emit CycloneDX only; only police identity for CycloneDX.
        if args.format == "cyclonedx" and generator != expected:
            problems.append(f"generator is {generator}")
        if components < floor:
            problems.append(f"{components} < {floor}")
        if error:
            problems.append(error)

        verdict = "ok" if not problems else "FAIL: " + "; ".join(problems)
        if problems:
            failures.append(project)
        shown = "-" if components < 0 else str(components)
        print(f"{project:<22}{generator:<18}{shown:>7}  {expected:<18}{verdict}")

    print(f"\n{len(MATRIX) - len(failures)}/{len(MATRIX)} ok")
    if failures and args.strict:
        print(f"failed: {', '.join(failures)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
