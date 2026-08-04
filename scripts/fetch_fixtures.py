#!/usr/bin/env python3
"""Clone the real projects the ecosystem matrix runs against.

Not lock files -- whole repositories, shallow-cloned at a pinned tag.

Assembling a project out of a few downloaded files does not work, and the
failures are instructive rather than incidental. cdxgen accepted a lone
packages.lock.json and rejected the same file beside its .csproj, which is
the shape every real .NET project has. An sbt build needs all of project/,
because plugins.sbt declares what build.sbt references. Gradle resolves
versions through a catalog and buildSrc. A Go module without its source
collapses to one component. In each case a partial fixture tests something
nobody ships, and can pass while the product is broken.

These are too large to commit, so they are cloned on demand into a cache
directory. The committed fixtures under tests/test-data/projects stay small
and hermetic for the routing tests; this is for the integration matrix, which
needs the network anyway to fetch bundles and resolve dependencies.

    python scripts/fetch_fixtures.py [--only ecosystem] [--dir PATH]
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_DIR = Path(os.environ.get("SBOMIFY_REAL_PROJECTS", Path.home() / ".cache" / "sbomify" / "real-projects"))

#: ecosystem -> (repo, pinned ref, path to the lock file within the checkout)
#:
#: Chosen to be popular and maintained, and small enough to clone. Two
#: exclusions worth recording: commons-lang has no compile-scope dependencies,
#: so a correct SBOM of it is empty and it cannot tell success from failure;
#: ripgrep is a cargo workspace, where cyclonedx-cargo writes one SBOM per
#: member and the generator declines by design.
REPOS: dict[str, tuple[str, str, str]] = {
    # The lock file has to be one the generators actually claim, and a real
    # one. flask keeps its requirements under requirements/dev.txt and
    # requests names its requirements-dev.txt -- neither is
    # "requirements.txt", so the chain reported "no generator found". Pointing
    # at requests' pyproject.toml instead got further and then failed:
    # cyclonedx-py claims pyproject.toml but resolves it through poetry.lock,
    # which a setuptools project does not have.
    "python": ("python-poetry/poetry", "1.8.4", "poetry.lock"),
    "javascript": ("axios/axios", "v1.7.7", "package-lock.json"),
    "java": ("spring-projects/spring-petclinic", "main", "pom.xml"),
    "java-gradle": ("ReactiveX/RxJava", "v3.1.9", "build.gradle"),
    "scala": ("scopt/scopt", "v4.1.0", "build.sbt"),
    "go": ("gohugoio/hugo", "v0.136.5", "go.mod"),
    "rust": ("sharkdp/fd", "v10.2.0", "Cargo.lock"),
    "ruby": ("rails/rails", "v7.2.2", "Gemfile.lock"),
    "elixir": ("phoenixframework/phoenix", "v1.7.14", "mix.lock"),
    "dart": ("flutter/gallery", "main", "pubspec.lock"),
    "php": ("symfony/demo", "main", "composer.lock"),
    "swift": ("ChimeHQ/Neon", "main", "Package.resolved"),
    "dotnet": ("HangfireIO/Hangfire", "v1.8.15", ".nuget/packages.lock.json"),
}


def clone(repo: str, ref: str, target: Path) -> bool:
    """Shallow-clone one repository at a pinned ref."""
    marker = target / ".sbomify-clone"
    if marker.is_file() and marker.read_text().strip() == f"{repo}@{ref}":
        print(f"  {target.name:<14}already cloned")
        return True
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(  # noqa: S603
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--branch",
            ref,
            "--quiet",  # noqa: S607
            f"https://github.com/{repo}.git",
            str(target),
        ],
        capture_output=True,
        text=True,
        timeout=1800,
    )
    if result.returncode != 0:
        print(f"  {target.name:<14}CLONE FAILED: {result.stderr.strip()[:100]}", file=sys.stderr)
        return False
    # --depth 1 already fetches a single commit, but the pack is still about
    # half the checkout and nothing here reads git history afterwards.
    shutil.rmtree(target / ".git", ignore_errors=True)
    marker.write_text(f"{repo}@{ref}\n")
    size = sum(f.stat().st_size for f in target.rglob("*") if f.is_file()) / (1024 * 1024)
    print(f"  {target.name:<14}{repo}@{ref}  {size:.0f} MB")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only")
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR)
    args = parser.parse_args()

    failures = 0
    for name, (repo, ref, _lock) in sorted(REPOS.items()):
        if args.only and args.only != name:
            continue
        if not clone(repo, ref, args.dir / name):
            failures += 1
    print(f"  -> {args.dir}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
