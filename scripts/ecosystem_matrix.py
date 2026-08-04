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
import os
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
#: (ecosystem, generator that must produce it, floor)
#:
#: The project and its lock file come from scripts/fetch_fixtures.py, which
#: clones the real repository. Floors are deliberately low: they catch "empty"
#: and "collapsed", not small changes in what upstream reports.
MATRIX = [
    ("python", "cyclonedx-py", 3),
    ("javascript", "cdxgen-fs", 5),
    ("java", "cyclonedx-maven", 20),
    ("java-gradle", "cyclonedx-gradle", 5),
    ("scala", "cyclonedx-sbt", 1),
    ("go", "cyclonedx-gomod", 50),
    ("rust", "cyclonedx-cargo", 20),
    ("ruby", "cdxgen-fs", 20),
    ("elixir", "cdxgen-fs", 10),
    ("dart", "cdxgen-fs", 20),
    ("php", "cdxgen-fs", 20),
    ("swift", "cdxgen-fs", 1),
    ("dotnet", "cdxgen-fs", 1),
]

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fetch_fixtures import DEFAULT_DIR, REPOS  # noqa: E402

PROJECTS = Path(os.environ.get("SBOMIFY_REAL_PROJECTS", DEFAULT_DIR))


def run_one(project: str, sbom_format: str) -> tuple[str, int, str]:
    """Generate into a scratch copy so fixtures are never written to."""
    _repo, _ref, lock_file = REPOS[project]
    src = PROJECTS / project
    if not src.is_dir():
        return ("not cloned", -1, "run scripts/fetch_fixtures.py first")
    # Cleaned up on every path. These are whole checkouts now, not a lock
    # file each -- leaking one per ecosystem filled /tmp and took the shell
    # down with it.
    # Staged beside the clones rather than in /tmp: these are whole
    # checkouts, and /tmp is commonly a smaller filesystem -- copying rails
    # into it exhausted the quota mid-run.
    staging = PROJECTS.parent / "matrix-work"
    staging.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(dir=staging))
    try:
        shutil.copytree(src, work, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git"))
        out = work / "sbom.json"
        # Strict mode raises rather than degrading, which is correct in a run
        # but useless in a matrix: one bad ecosystem would hide the rest. Catch
        # it here so every row is reported, and let --strict set the exit code.
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
        document = json.loads(out.read_text())
        # SPDX names them packages, CycloneDX components. Counting only the
        # latter made every SPDX row read zero and the whole format look
        # broken when it was not.
        components = len(document.get("components") or document.get("packages") or [])
        return (result.generator_name or "none", components, "")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", default="both", choices=["cyclonedx", "spdx", "both"])
    parser.add_argument("--strict", action="store_true", help="fail on a wrong generator or a low count")
    args = parser.parse_args()

    print(f"{'ecosystem':<22}{'format':<11}{'generator':<18}{'entries':>8}  verdict")
    print("-" * 70)
    formats = ["cyclonedx", "spdx"] if args.format == "both" else [args.format]
    failures = []
    total = 0
    for project, expected, floor in MATRIX:
        for fmt in formats:
            total += 1
            generator, components, error = run_one(project, fmt)

            problems = []
            # Generator identity is only policed for CycloneDX. For SPDX the
            # right answer varies: the ecosystems with a native resolver
            # convert their own output, and the rest fall to syft.
            if fmt == "cyclonedx" and generator != expected:
                problems.append(f"generator is {generator}")
            if components < floor:
                problems.append(f"{components} < {floor}")
            if error:
                problems.append(error[:60])

            verdict = "ok" if not problems else "FAIL: " + "; ".join(problems)
            if problems:
                failures.append(f"{project}/{fmt}")
            shown = "-" if components < 0 else str(components)
            print(f"{project:<22}{fmt:<11}{generator:<18}{shown:>8}  {verdict}")

    print("-" * 70)
    print(f"{total - len(failures)}/{total} ok")
    if failures and args.strict:
        print(f"failed: {', '.join(failures)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
