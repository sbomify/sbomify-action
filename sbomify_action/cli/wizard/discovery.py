"""Lockfile discovery for the sbomify-action wizard."""

import os
import re
import subprocess
from pathlib import Path

from sbomify_action._generation.utils import (
    ALL_LOCK_FILES,
    get_lock_file_ecosystem,
)
from sbomify_action.cli.wizard.state import DiscoveredLockfile

DISCOVERY_CAP = 200

_SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}

# Within a single directory, prefer the lockfile with the highest priority
# (lower number = higher priority).
_LOCKFILE_PRIORITY: dict[str, int] = {
    # Python
    "uv.lock": 10,
    "poetry.lock": 11,
    "Pipfile.lock": 12,
    "requirements.txt": 13,
    "pyproject.toml": 14,
    # JavaScript
    "bun.lock": 20,
    "pnpm-lock.yaml": 21,
    "yarn.lock": 22,
    "package-lock.json": 23,
    "package.json": 24,
    # PHP
    "composer.lock": 30,
    "composer.json": 31,
    # Go
    "go.sum": 40,
    "go.mod": 41,
    # Java
    "gradle.lockfile": 50,
    "build.gradle.kts": 51,
    "build.gradle": 52,
    "pom.xml": 53,
    # Swift
    "Package.resolved": 60,
    "Package.swift": 61,
}


def slugify(value: str) -> str:
    """Lower-case ASCII slug — letters, digits, hyphens; trimmed; max 60 chars."""
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:60]


def _is_git_repo(path: Path) -> bool:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _git_tracked_files(repo_root: Path) -> list[Path] | None:
    """Return tracked + untracked-but-not-ignored files via git ls-files.

    Falls back to ``None`` if git is unavailable or fails.
    """
    try:
        result = subprocess.run(
            [
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    files: list[Path] = []
    for line in result.stdout.splitlines():
        rel = line.strip()
        if not rel:
            continue
        files.append(Path(rel))
    return files


def _walk_files(repo_root: Path) -> list[Path]:
    """Fallback file walk that skips common build/cache directories."""
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            abs_path = Path(dirpath) / name
            try:
                rel = abs_path.relative_to(repo_root)
            except ValueError:
                continue
            files.append(rel)
    return files


def _suggested_name(rel_path: Path, repo_root_name: str, ecosystem: str) -> str:
    """Build a default component name from the lockfile location."""
    parent = rel_path.parent
    if str(parent) in ("", "."):
        # Top-level lockfile; default to repo name + ecosystem hint to
        # disambiguate when multiple top-level lockfiles exist.
        base = f"{repo_root_name}-{ecosystem}" if repo_root_name else ecosystem
    else:
        base = parent.name
    return slugify(base) or "component"


def _dedup_by_priority(
    candidates: list[tuple[Path, str]],
) -> list[tuple[Path, str]]:
    """Within each parent dir, keep only the highest-priority lockfile."""
    by_parent: dict[Path, tuple[Path, str, int]] = {}
    extras: list[tuple[Path, str]] = []
    for rel_path, ecosystem in candidates:
        priority = _LOCKFILE_PRIORITY.get(rel_path.name)
        if priority is None:
            extras.append((rel_path, ecosystem))
            continue
        parent = rel_path.parent
        existing = by_parent.get(parent)
        if existing is None or priority < existing[2]:
            by_parent[parent] = (rel_path, ecosystem, priority)

    deduped = [(path, eco) for path, eco, _ in by_parent.values()]
    deduped.extend(extras)
    deduped.sort(key=lambda item: str(item[0]))
    return deduped


def discover(repo_root: Path) -> list[DiscoveredLockfile]:
    """Find all lockfiles under ``repo_root``.

    Prefers ``git ls-files`` when in a git repo (respects ``.gitignore``),
    otherwise walks the tree skipping common build/cache directories.
    """
    repo_root = repo_root.resolve()
    repo_root_name = slugify(repo_root.name)

    rel_paths: list[Path] | None = None
    if _is_git_repo(repo_root):
        rel_paths = _git_tracked_files(repo_root)
    if rel_paths is None:
        rel_paths = _walk_files(repo_root)

    candidates: list[tuple[Path, str]] = []
    for rel in rel_paths:
        name = rel.name
        if name not in ALL_LOCK_FILES:
            continue
        ecosystem = get_lock_file_ecosystem(name)
        if not ecosystem:
            continue
        candidates.append((rel, ecosystem))

    deduped = _dedup_by_priority(candidates)
    if len(deduped) > DISCOVERY_CAP:
        deduped = deduped[:DISCOVERY_CAP]

    results: list[DiscoveredLockfile] = []
    for rel, ecosystem in deduped:
        abs_path = (repo_root / rel).resolve()
        results.append(
            DiscoveredLockfile(
                path=abs_path,
                rel_path=rel,
                ecosystem=ecosystem,
                suggested_name=_suggested_name(rel, repo_root_name, ecosystem),
            )
        )
    return results
