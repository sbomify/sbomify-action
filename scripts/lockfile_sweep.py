#!/usr/bin/env python3
"""Generate an SBOM for every lock file name the README promises.

scripts/ecosystem_matrix.py proves each *ecosystem* routes somewhere useful,
one file per ecosystem. That is a weaker claim than the README makes: it
lists 28 file names, and a name that never resolves is a broken promise
whether or not its ecosystem works elsewhere. requirements.txt and
poetry.lock are both "Python" and are read by different code paths.

This runs all 28 against real checkouts, in both formats, and prints what
each actually produced -- generator and entry count -- rather than asserting
what it should. Use it to find out; use ecosystem_matrix.py to keep it true.

    python scripts/lockfile_sweep.py [--only NAME ...] [--format ...]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ecosystem_matrix import ALIASES, REPOS, run_one  # noqa: E402

#: (row, the README name it proves). Ordered as the README table is.
SWEEP: list[tuple[str, str]] = [
    ("python-requirements", "requirements.txt"),
    ("python", "poetry.lock"),
    ("python-pipenv", "Pipfile.lock"),
    ("python-uv", "uv.lock"),
    ("python-pyproject", "pyproject.toml"),
    ("js-package-json", "package.json"),
    ("javascript", "package-lock.json"),
    ("js-yarn", "yarn.lock"),
    ("keycloak-js", "pnpm-lock.yaml"),
    ("js-bun", "bun.lock"),
    ("java", "pom.xml"),
    ("java-groovy", "build.gradle"),
    ("java-gradle", "build.gradle.kts"),
    ("java-lockfile", "gradle.lockfile"),
    ("go", "go.mod"),
    ("go-sum", "go.sum"),
    ("rust", "Cargo.lock"),
    ("ruby", "Gemfile.lock"),
    ("php-json", "composer.json"),
    ("php", "composer.lock"),
    ("dotnet", "packages.lock.json"),
    ("swift-manifest", "Package.swift"),
    ("swift", "Package.resolved"),
    ("dart", "pubspec.lock"),
    ("elixir", "mix.lock"),
    ("scala", "build.sbt"),
    ("cpp", "conan.lock"),
    ("terraform", ".terraform.lock.hcl"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", default="both", choices=["cyclonedx", "spdx", "both"])
    parser.add_argument("--only", action="append")
    args = parser.parse_args()
    formats = ["cyclonedx", "spdx"] if args.format == "both" else [args.format]

    print(f"{'lock file':<22}{'fixture':<20}{'format':<11}{'generator':<18}{'entries':>8}  note")
    print("-" * 92)
    empty = 0
    ran = 0
    for row, name in SWEEP:
        if args.only and name not in args.only and row not in args.only:
            continue
        source = ALIASES.get(row, (row,))[0]
        repo = REPOS.get(source, ("?",))[0]
        for fmt in formats:
            ran += 1
            generator, entries, error = run_one(row, fmt)
            note = error[:34] if error else ""
            if entries <= 0:
                empty += 1
                note = note or "NOTHING PRODUCED"
            shown = "-" if entries < 0 else str(entries)
            print(f"{name:<22}{repo.split('/')[-1][:19]:<20}{fmt:<11}{generator:<18}{shown:>8}  {note}")
    print("-" * 92)
    print(f"{empty} of {ran} cells produced nothing")
    return 1 if empty else 0


if __name__ == "__main__":
    raise SystemExit(main())
