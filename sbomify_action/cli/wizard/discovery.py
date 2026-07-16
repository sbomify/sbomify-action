"""Lockfile discovery for the wizard.

Walks the repo root once at wizard start to find every lockfile the
action can generate an SBOM from. The discover screen presents this
list for multi-select; everything downstream operates on the user's
selection.

Reuses ``sbomify_action._generation.utils.ALL_LOCK_FILES`` /
``get_lock_file_ecosystem`` so wizard support tracks the rest of the
codebase automatically when new ecosystems land.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from sbomify_action._generation.utils import ALL_LOCK_FILES, get_lock_file_ecosystem
from sbomify_action.cli.wizard.state import DiscoveredLockfile

# Cap the walk so we never scan a degenerate monorepo into memory. 200
# is enormous in practice; if a repo legitimately has more lockfiles
# than this, the wizard isn't the right tool for them anyway.
DISCOVERY_CAP = 200

# Directories we never recurse into.
_SKIP_DIRS = frozenset(
    {
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
        ".idea",
        ".vscode",
        # AI coding-agent config dirs. Claude Code keeps agent worktrees
        # (full repo copies) at .claude/worktrees/, so recursing would
        # double-count every lockfile in the repo. The others hold only
        # tool config today, but skipping them is harmless and guards
        # against the same worktree pattern landing there.
        ".claude",
        ".cursor",
        ".codex",
        ".gemini",
        # Common in-repo worktree conventions used by parallel-agent
        # orchestrators (ccmanager, agent-deck, ...) and humans alike.
        ".worktrees",
        ".trees",
    }
)

# Within a single directory we may find multiple lockfiles
# (eg. ``uv.lock`` + ``pyproject.toml``). Smaller priority numbers win
# — the authoritative lockfile beats the manifest.
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
    # Rust
    "Cargo.lock": 55,
    "Cargo.toml": 56,
    # Swift
    "Package.resolved": 60,
    "Package.swift": 61,
}


def slugify(value: str) -> str:
    """Convert ``value`` into a lowercase, hyphen-separated ASCII slug.

    Trims leading / trailing hyphens and caps at 60 chars — long enough
    for human-readable names while well under sbomify's component name
    length limit.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:60]


def _suggested_name(repo_name: str, lock_name: str) -> str:
    """Build a default component-name suggestion for a lockfile.

    The pattern is ``<repo-slug>-<ecosystem-or-lockfile-slug>``. The
    suffix lets multi-language repos disambiguate (eg. ``widget-py`` vs
    ``widget-js``) without the user having to type a name.
    """
    ecosystem = get_lock_file_ecosystem(lock_name)
    if ecosystem:
        suffix = slugify(ecosystem)
    else:
        suffix = slugify(lock_name)
    base = slugify(repo_name)
    if not suffix or suffix == base:
        return base or "component"
    return f"{base}-{suffix}" if base else suffix


def discover(repo_root: Path, *, repo_name: str | None = None) -> list[DiscoveredLockfile]:
    """Find every supported lockfile under ``repo_root``.

    For each directory, only the highest-priority lockfile is kept so
    we don't double-count (e.g. ``uv.lock`` + ``pyproject.toml`` in the
    same dir).
    """
    repo_root = repo_root.resolve()
    repo_name = repo_name or repo_root.name

    # path → best lockfile in that directory
    best_per_dir: dict[Path, tuple[int, Path]] = {}

    for path in _walk(repo_root):
        name = path.name
        if name not in ALL_LOCK_FILES:
            continue

        priority = _LOCKFILE_PRIORITY.get(name, 99)
        current = best_per_dir.get(path.parent)
        if current is None or priority < current[0]:
            best_per_dir[path.parent] = (priority, path)

        # Cap on unique directories, not on raw matches. Monorepos
        # commonly have ``uv.lock + pyproject.toml + requirements.txt``
        # in every project directory, so a raw-match cap of 200 would
        # truncate at ~67 projects even though best_per_dir collapses
        # them down to one entry per dir.
        if len(best_per_dir) >= DISCOVERY_CAP:
            break

    found: list[DiscoveredLockfile] = []
    for _priority, path in best_per_dir.values():
        rel = path.relative_to(repo_root)
        ecosystem = get_lock_file_ecosystem(path.name) or "unknown"
        found.append(
            DiscoveredLockfile(
                path=path,
                rel_path=rel,
                ecosystem=ecosystem,
                suggested_name=_suggested_name(repo_name, path.name),
            )
        )

    found.sort(key=lambda lf: (str(lf.rel_path.parent), lf.rel_path.name))
    return found


def _walk(root: Path) -> Iterator[Path]:
    """Yield every file under ``root``, skipping irrelevant directories."""
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (PermissionError, OSError):
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name in _SKIP_DIRS:
                    continue
                stack.append(entry)
            elif entry.is_file():
                yield entry
