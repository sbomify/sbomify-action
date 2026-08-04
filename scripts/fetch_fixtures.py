#!/usr/bin/env python3
"""Refresh the ecosystem fixtures from real upstream projects.

Hand-written fixtures test a shape that does not exist. The .NET one proved
it: cdxgen accepted a lone packages.lock.json and rejected the same lock file
next to its .csproj with "uniqueItems" on /dependencies -- and every real .NET
project has both. A fixture nobody ships is a fixture that can pass while the
product is broken.

Every source below is a popular, actively maintained project, pinned to a tag
or commit so the fixture is reproducible and its provenance is recorded rather
than remembered. Run this to refresh; the results are committed, because the
test suite must not need the network.

    python scripts/fetch_fixtures.py [--only ecosystem]
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROJECTS = Path(__file__).resolve().parent.parent / "tests" / "test-data" / "projects"
RAW = "https://raw.githubusercontent.com"

#: fixture -> (upstream repo, pinned ref, {destination: source path})
SOURCES: dict[str, tuple[str, str, dict[str, str]]] = {
    # Not commons-lang: it has 7 test and 1 provided dependency and zero at
    # compile scope, so a correct SBOM of it is empty. A fixture that cannot
    # tell success from failure is worse than no fixture.
    "java": ("spring-projects/spring-petclinic", "main", {"pom.xml": "pom.xml"}),
    # RxJava rather than okhttp: okhttp resolves its versions through a
    # Gradle version catalog and buildSrc, so a handful of files is not a
    # buildable project and gradle reports "No packages found" -- which cdxgen
    # turns into an empty SBOM and a zero exit code. RxJava's build.gradle
    # declares its dependencies inline.
    "java-gradle": (
        "ReactiveX/RxJava",
        "v3.1.9",
        {
            "build.gradle": "build.gradle",
            "gradle.properties": "gradle.properties",
            "settings.gradle": "settings.gradle",
        },
    ),
    # main.go matters: cyclonedx-gomod declines a module with no Go source, so
    # without it this fixture silently tests cdxgen instead of the native tool.
    "go": ("gohugoio/hugo", "v0.136.5", {"go.mod": "go.mod", "go.sum": "go.sum", "main.go": "main.go"}),
    # Not ripgrep: it is a cargo workspace, and cyclonedx-cargo writes one SBOM
    # per member there, which the generator declines by design. fd is a single
    # crate, which is what this fixture is meant to exercise.
    "rust": ("sharkdp/fd", "v10.2.0", {"Cargo.lock": "Cargo.lock", "Cargo.toml": "Cargo.toml"}),
    "ruby": ("rails/rails", "v7.2.2", {"Gemfile.lock": "Gemfile.lock", "Gemfile": "Gemfile"}),
    "elixir": ("phoenixframework/phoenix", "v1.7.14", {"mix.lock": "mix.lock", "mix.exs": "mix.exs"}),
    "dart": ("flutter/gallery", "main", {"pubspec.lock": "pubspec.lock", "pubspec.yaml": "pubspec.yaml"}),
    "javascript": (
        "axios/axios",
        "v1.7.7",
        {
            "package-lock.json": "package-lock.json",
            "package.json": "package.json",
        },
    ),
    "php": ("symfony/demo", "main", {"composer.lock": "composer.lock", "composer.json": "composer.json"}),
    # project/build.properties is not optional: the sbt launcher reads it to
    # decide which sbt to run. Without it the launcher falls back to whatever
    # it ships, and cdxgen's dependency-graph plugin is published for sbt 1.x
    # only -- it fails with "Not found" for sbt-dependency-graph_sbt2_3.
    "scala": (
        "typelevel/cats",
        "v2.12.0",
        {
            "build.sbt": "build.sbt",
            "project/build.properties": "project/build.properties",
            "project/plugins.sbt": "project/plugins.sbt",
        },
    ),
    "swift": (
        "ChimeHQ/Neon",
        "main",
        {
            "Package.resolved": "Package.resolved",
            "Package.swift": "Package.swift",
        },
    ),
    "dotnet": (
        "HangfireIO/Hangfire",
        "v1.8.15",
        {
            "packages.lock.json": ".nuget/packages.lock.json",
        },
    ),
}


def fetch(repo: str, ref: str, source: str) -> bytes:
    url = f"{RAW}/{repo}/{ref}/{source}"
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310
        return response.read()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", help="refresh a single ecosystem")
    args = parser.parse_args()

    failures = 0
    for name, (repo, ref, files) in sorted(SOURCES.items()):
        if args.only and args.only != name:
            continue
        target = PROJECTS / name
        target.mkdir(parents=True, exist_ok=True)
        for destination, source in files.items():
            try:
                body = fetch(repo, ref, source)
            except urllib.error.HTTPError as exc:
                print(f"  {name:<14}FAILED {source}: HTTP {exc.code}", file=sys.stderr)
                failures += 1
                continue
            (target / destination).write_bytes(body)
            print(f"  {name:<14}{destination:<22}{len(body):>9} bytes  {repo}@{ref}")
        (target / "SOURCE").write_text(
            f"{repo}@{ref}\n{RAW}/{repo}/{ref}/\n"
            "Fetched by scripts/fetch_fixtures.py. Real upstream data, not hand-written.\n"
        )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
