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

import os
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

from sbomify_action._generation.utils import ALL_LOCK_FILES, get_lock_file_ecosystem
from sbomify_action.cli.wizard.state import DiscoveredLockfile, NestedRepoKind

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

# Within a single directory an ecosystem may have both a lockfile and a
# manifest (eg. ``uv.lock`` + ``pyproject.toml``). Smaller priority
# numbers win — the authoritative lockfile beats the manifest. Priorities
# only compete within one ecosystem; a polyglot root (``uv.lock`` +
# ``bun.lock``) keeps one entry per ecosystem.
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


def _suggested_name(repo_name: str, lock_name: str, dir_name: str | None = None) -> str:
    """Build a default component-name suggestion for a lockfile.

    The pattern is ``<repo-slug>[-<dir-slug>]-<ecosystem-or-lockfile-slug>``.
    The ecosystem suffix lets multi-language repos disambiguate
    (eg. ``widget-py`` vs ``widget-js``); the optional directory slug is
    added only when two lockfiles would otherwise suggest the same name
    (eg. ``bun.lock`` + ``website/bun.lock``).
    """
    ecosystem = get_lock_file_ecosystem(lock_name)
    if ecosystem:
        suffix = slugify(ecosystem)
    else:
        suffix = slugify(lock_name)
    base = slugify(repo_name)
    if dir_name and (dir_slug := slugify(dir_name)):
        base = f"{base}-{dir_slug}" if base else dir_slug
    if not suffix or suffix == base:
        return base or "component"
    return f"{base}-{suffix}" if base else suffix


def discover(repo_root: Path, *, repo_name: str | None = None) -> list[DiscoveredLockfile]:
    """Find every supported lockfile under ``repo_root``.

    Within each directory, only the highest-priority lockfile *per
    ecosystem* is kept, so we don't double-count ``uv.lock`` +
    ``pyproject.toml`` while a polyglot root (``uv.lock`` + ``bun.lock``)
    still yields both.
    """
    repo_root = repo_root.resolve()
    repo_name = repo_name or repo_root.name

    # (directory, ecosystem) → best lockfile for that ecosystem there
    best_per_dir_eco: dict[tuple[Path, str], tuple[int, Path]] = {}

    for path in _walk(repo_root):
        name = path.name
        if name not in ALL_LOCK_FILES:
            continue

        ecosystem = get_lock_file_ecosystem(name) or "unknown"
        priority = _LOCKFILE_PRIORITY.get(name, 99)
        key = (path.parent, ecosystem)
        current = best_per_dir_eco.get(key)
        if current is None or priority < current[0]:
            best_per_dir_eco[key] = (priority, path)

        # Cap on unique (directory, ecosystem) pairs, not raw matches.
        # Monorepos commonly have ``uv.lock + pyproject.toml +
        # requirements.txt`` in every project directory, so a raw-match
        # cap of 200 would truncate at ~67 projects even though
        # best_per_dir_eco collapses them down to one entry per pair.
        if len(best_per_dir_eco) >= DISCOVERY_CAP:
            break

    submodule_paths = _submodule_paths(repo_root)
    nested_cache: dict[Path, tuple[str, NestedRepoKind] | None] = {}

    found: list[DiscoveredLockfile] = []
    for (_dir, ecosystem), (_priority, path) in best_per_dir_eco.items():
        rel = path.relative_to(repo_root)
        nested = _enclosing_nested_repo(path.parent, repo_root, submodule_paths, nested_cache)
        found.append(
            DiscoveredLockfile(
                path=path,
                rel_path=rel,
                ecosystem=ecosystem,
                suggested_name=_suggested_name(repo_name, path.name),
                nested_repo=nested[0] if nested else None,
                nested_repo_kind=nested[1] if nested else None,
            )
        )

    # Same ecosystem in several directories (eg. ``bun.lock`` +
    # ``website/bun.lock``) collides on the plain ``<repo>-<ecosystem>``
    # suggestion — qualify the colliding ones with their full relative
    # directory path (not just the basename, which itself collides for
    # eg. ``apps/web`` + ``packages/web``; slugify turns ``/`` into ``-``).
    name_counts = Counter(lf.suggested_name for lf in found)
    found = [
        replace(
            lf,
            suggested_name=_suggested_name(repo_name, lf.rel_path.name, dir_name=str(lf.rel_path.parent)),
        )
        if name_counts[lf.suggested_name] > 1 and lf.rel_path.parent != Path(".")
        else lf
        for lf in found
    ]

    found.sort(key=lambda lf: (str(lf.rel_path.parent), lf.rel_path.name))
    return found


# ``path = <value>`` lines inside .gitmodules. Values may be quoted when
# they contain spaces; git writes forward slashes on every platform.
_GITMODULES_PATH_RE = re.compile(r"^\s*path\s*=\s*(?P<path>.+?)\s*$", re.MULTILINE)


def _submodule_paths(repo_root: Path) -> frozenset[str]:
    """Repo-relative POSIX paths declared as submodules in ``.gitmodules``.

    Parsed directly from the file rather than via ``git submodule`` so it
    works without a git binary and for submodules that were declared but
    never initialised.
    """
    try:
        text = (repo_root / ".gitmodules").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset()
    return frozenset(m.group("path").strip('"').rstrip("/") for m in _GITMODULES_PATH_RE.finditer(text))


def _enclosing_nested_repo(
    directory: Path,
    repo_root: Path,
    submodule_paths: frozenset[str],
    cache: dict[Path, tuple[str, NestedRepoKind] | None],
) -> tuple[str, NestedRepoKind] | None:
    """Innermost ancestor of ``directory`` that is its own repository.

    A directory counts if it is declared in ``.gitmodules``
    (``submodule``) or carries its own ``.git`` entry (``vendored``).
    The second branch does not inspect the entry: a ``.git`` directory
    (checked-in clone) and a ``.git`` file (worktree, or a submodule
    checkout the parent never declared) are both ``vendored``, since
    either way the code belongs to another repository. Results are
    memoised per directory since sibling lockfiles share ancestors.
    """
    if directory == repo_root:
        return None
    if directory in cache:
        return cache[directory]
    rel = directory.relative_to(repo_root).as_posix()
    result: tuple[str, NestedRepoKind] | None
    if rel in submodule_paths:
        result = (rel, "submodule")
    elif (directory / ".git").exists():
        result = (rel, "vendored")
    else:
        result = _enclosing_nested_repo(directory.parent, repo_root, submodule_paths, cache)
    cache[directory] = result
    return result


def _walk(root: Path) -> Iterator[Path]:
    """Yield every file under ``root``, skipping irrelevant directories.

    Symlinked directories are not descended into. A symlink can point at one
    of its own ancestors -- ``crystal-lang/crystal`` ships ``lib/markd/lib ->
    ..``, written by its package manager -- and following it walks
    ``lib/markd/lib/markd/lib/...`` without end. ``DISCOVERY_CAP`` does not
    save us: it counts unique (directory, ecosystem) pairs, so a cycle
    containing no lockfiles never advances it while the stack grows without
    bound. This is the wizard's first action, so the symptom was the entry
    point to the whole tool hanging before it drew anything.

    Not descending is the right answer rather than merely the terminating
    one. A symlinked directory either points inside the repo, in which case
    its contents are already reachable by their real path, or outside it, in
    which case they are not part of this project and should not be offered
    as components of it.

    Symlinked *files* are still yielded: a symlinked lockfile is a real
    lockfile for this project.

    Nothing outside ``root`` is ever reported, and that is enforced rather
    than implied: any entry that *is* a symlink has its real path checked
    against the root before it is used. Declining to descend into symlinked
    directories already makes escape impossible, so this is belt and braces
    -- but it is the invariant the wizard depends on (every path it shows
    becomes a component of *this* repo), so it is worth stating in code that
    a later change cannot quietly break. Only symlinks pay for the check; a
    plain entry under a plain parent cannot leave the tree.

    ``os.scandir`` rather than ``Path.iterdir``: its entries answer
    ``is_dir(follow_symlinks=False)`` and ``is_symlink()`` from the directory
    data the OS already returned, where ``Path.is_dir(follow_symlinks=...)``
    needs Python 3.13 and this project supports 3.11.
    """
    root_real = os.path.realpath(root)
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name in _SKIP_DIRS:
                                continue
                            stack.append(Path(entry.path))
                        elif entry.is_file():
                            if entry.is_symlink() and not _within(entry.path, root_real):
                                continue
                            yield Path(entry.path)
                    except OSError:
                        # A dangling symlink, or a race with something
                        # writing the tree: skip the entry, keep walking.
                        continue
        except (PermissionError, OSError):
            continue


def _within(path: str, root_real: str) -> bool:
    """True when ``path`` really resolves inside ``root_real``.

    Compared on the resolved path, not the spelling: ``repo/link`` may be
    written as though it were inside the repo while pointing anywhere.

    ``is_relative_to`` rather than a string prefix. Prefix comparison needs
    a trailing separator to stop ``/repo-other`` matching a ``/repo`` root,
    and appending one breaks when the root *is* the separator: ``"/" +
    os.sep`` is ``"//"``, which nothing under ``/`` starts with, so a repo
    at the filesystem root would have had every file rejected. Comparing
    path components has no such corner.
    """
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    return Path(real).is_relative_to(root_real)
