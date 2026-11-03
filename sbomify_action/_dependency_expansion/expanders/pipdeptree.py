"""Pipdeptree-based dependency expander for Python requirements.txt files."""

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from ...logging_config import logger
from ...tool_checks import check_tool_available
from ..models import DiscoveredDependency, normalize_python_package_name

_PIPDEPTREE_AVAILABLE, _ = check_tool_available("pipdeptree")

# Valid Python package name pattern (PEP 508): alphanumeric, hyphens, underscores, dots
_VALID_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")


class PipdeptreeExpander:
    """Discovers Python transitive dependencies using pipdeptree.

    pipdeptree inspects installed packages in the current Python
    environment and reports their dependency tree. This expander
    uses it to find transitive dependencies that are NOT listed
    in requirements.txt but are installed as dependencies of
    packages that ARE listed.

    That only yields true results when the environment being inspected
    *is* the environment the lockfile describes. It frequently is not:
    installed via pipx/uvx (or run from the Docker image), the
    interpreter belongs to sbomify-action and holds sbomify-action's own
    dependencies, not the scanned project's. Because this tool depends
    on common libraries (requests and its chain), the lookups still
    resolve and the expansion silently reports *our* versions as the
    project's transitive dependencies.

    ``_verify_environment_matches`` is what stops that: expansion only
    proceeds once the installed versions corroborate the lockfile's
    pins. See :meth:`_verify_environment_matches` for the exact rules.

    Requirements:
        - pipdeptree must be installed
        - Packages from requirements.txt must be installed in the
          environment being inspected, at the versions it pins
    """

    SUPPORTED_LOCK_FILES = ("requirements.txt",)

    @property
    def name(self) -> str:
        return "pipdeptree"

    @property
    def priority(self) -> int:
        return 10  # Native Python tool, high priority

    @property
    def ecosystems(self) -> list[str]:
        return ["pypi"]

    def supports(self, lock_file: Path) -> bool:
        """Check if this expander supports the given lockfile."""
        if not _PIPDEPTREE_AVAILABLE:
            return False
        return lock_file.name in self.SUPPORTED_LOCK_FILES

    def can_expand(self) -> bool:
        """Check whether pipdeptree can run at all.

        This is only an availability probe — it says nothing about
        *which* environment pipdeptree would inspect, and it is true in
        any environment where the tool is installed (including our own).
        The check that the environment actually corresponds to the
        lockfile lives in :meth:`_verify_environment_matches`, which
        needs the lockfile and therefore runs inside :meth:`expand`.
        """
        if not _PIPDEPTREE_AVAILABLE:
            return False

        try:
            result = subprocess.run(
                ["pipdeptree", "--json-tree", "--warn", "silence"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0
        except Exception:
            return False

    def expand(self, lock_file: Path) -> list[DiscoveredDependency]:
        """Discover transitive dependencies using pipdeptree.

        Returns list of dependencies that are installed but NOT
        in the original requirements.txt.
        """
        # 1. Parse requirements.txt to get direct dependency names
        direct_deps = self._parse_requirements(lock_file)
        direct_names = {normalize_python_package_name(name) for name in direct_deps}

        logger.debug(f"Found {len(direct_names)} direct dependencies in {lock_file.name}")

        if not direct_deps:
            return []

        # 2. Refuse to expand from an environment that isn't the project's.
        # Everything below reads installed versions and attributes them to
        # the scanned project, so this has to hold before any of it runs.
        installed = self._installed_versions()
        if installed is None:
            return []
        if not self._verify_environment_matches(direct_deps, installed, lock_file):
            return []

        # 3. Run pipdeptree filtered to only the direct dependencies.
        # We pass original (non-normalized) names here because pipdeptree
        # performs its own name normalization internally via pkg_resources.
        # The normalized `direct_names` set is used later for comparison.
        package_list = ",".join(direct_deps.keys())
        tree = self._run_pipdeptree(packages=package_list)
        if not tree:
            logger.debug("pipdeptree returned no results for the specified packages")
            return []

        logger.debug(f"pipdeptree returned {len(tree)} direct dependency trees")

        # 4. Find transitive dependencies (deps of direct packages that aren't in requirements.txt)
        discovered: list[DiscoveredDependency] = []
        seen_package_versions: set[str] = set()

        for pkg in tree:
            # Start at depth=0 for the direct dependency, its children are depth=1
            self._collect_transitives(
                pkg,
                direct_names,
                discovered,
                seen_package_versions,
                depth=0,
            )

        logger.info(f"pipdeptree discovered {len(discovered)} transitive dependencies")
        return discovered

    def _installed_versions(self) -> dict[str, str] | None:
        """Every package installed in the inspected environment.

        Uses pipdeptree's flat ``--json`` rather than the filtered
        ``--json-tree`` used for discovery: passing ``--packages`` a name
        that isn't installed makes pipdeptree emit nothing at all rather
        than a partial tree, which is indistinguishable from a parse
        failure and hides exactly the case the verification needs to
        catch. Returns ``None`` if pipdeptree could not be read.
        """
        try:
            # nosemgrep: dangerous-subprocess-use-audit  # list-form, shell=False, fixed executable
            result = subprocess.run(
                ["pipdeptree", "--json", "--warn", "silence"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                logger.warning(f"pipdeptree failed while listing installed packages: {result.stderr}")
                return None
            entries: list[dict[str, Any]] = json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            logger.warning("pipdeptree timed out while listing installed packages")
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"pipdeptree package list not valid JSON: {e}")
            return None
        except Exception as e:  # noqa: BLE001
            logger.warning(f"pipdeptree error while listing installed packages: {e}")
            return None

        versions: dict[str, str] = {}
        for entry in entries:
            package = entry.get("package") or {}
            name = package.get("package_name") or package.get("key") or ""
            if name:
                versions[normalize_python_package_name(name)] = str(package.get("installed_version", "")).strip()
        return versions

    def _verify_environment_matches(
        self,
        direct_deps: dict[str, str | None],
        installed: dict[str, str],
        lock_file: Path,
    ) -> bool:
        """Decide whether the inspected environment is the lockfile's.

        pipdeptree reports whatever the running interpreter has
        installed. Attributing those versions to the scanned project is
        only sound when the two coincide, so require positive evidence
        rather than assuming it:

        1. Every direct dependency must be installed. A lockfile whose
           packages are largely absent describes a different project;
           the few that resolve are coincidental overlap with our own
           dependency chain.
        2. Every ``==`` pin must equal the installed version. One
           disagreement means a different (or stale) environment.
        3. At least one ``==`` pin must exist to check. With nothing
           pinned there is no evidence either way, and guessing here
           writes fabricated versions into a signed document.

        Versions are compared as exact strings, so an unusual but
        equivalent spelling errs toward skipping. That direction is
        deliberate: a skipped expansion logs why and loses only
        transitive discovery, while a wrong one ships silently.
        """
        missing = sorted(name for name in direct_deps if normalize_python_package_name(name) not in installed)
        if missing:
            shown = ", ".join(missing[:5]) + (f" (+{len(missing) - 5} more)" if len(missing) > 5 else "")
            logger.info(
                f"Dependency expansion skipped: {len(missing)} of {len(direct_deps)} packages in "
                f"{lock_file.name} are not installed in the environment running sbomify-action "
                f"({shown}). Transitive discovery reads that environment, so expanding here would "
                "report unrelated versions as the project's dependencies."
            )
            return False

        pinned = {name: version for name, version in direct_deps.items() if version}
        if not pinned:
            logger.info(
                f"Dependency expansion skipped: {lock_file.name} pins no exact versions (==), so there "
                "is no way to confirm the environment running sbomify-action is the one it describes. "
                "Transitive discovery reads that environment and would otherwise report its versions "
                "as the project's."
            )
            return False

        mismatches = [
            f"{name} pins {version} but {installed[normalize_python_package_name(name)] or '<unknown>'} is installed"
            for name, version in pinned.items()
            if installed[normalize_python_package_name(name)] != str(version).strip()
        ]
        if mismatches:
            shown = "; ".join(mismatches[:3]) + (f" (+{len(mismatches) - 3} more)" if len(mismatches) > 3 else "")
            logger.info(
                f"Dependency expansion skipped: the environment running sbomify-action does not match "
                f"{lock_file.name} ({shown}). Transitive discovery reads that environment, so expanding "
                "here would report its versions as the project's."
            )
            return False

        logger.debug(
            f"Environment matches {lock_file.name}: {len(pinned)} pinned version(s) confirmed installed; "
            "proceeding with transitive discovery"
        )
        return True

    def _parse_requirements(self, lock_file: Path) -> dict[str, str | None]:
        """Parse requirements.txt and return {name: version} dict."""
        deps: dict[str, str | None] = {}

        with open(lock_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                # Skip options like -r, -e, --index-url, etc.
                if line.startswith("-"):
                    continue

                # Skip URL/VCS requirements (git+https://..., https://..., etc.)
                if "://" in line:
                    logger.debug(f"Skipping URL requirement: {line}")
                    continue

                # Skip PEP 508 direct references (pkg @ https://...)
                if " @ " in line:
                    logger.debug(f"Skipping direct reference requirement: {line}")
                    continue

                # Handle environment markers (e.g., requests; python_version >= "3.6")
                if ";" in line:
                    line = line.split(";")[0].strip()

                # Parse the requirement line
                name, version = self._parse_requirement_line(line)
                if name:
                    # Validate package name contains only allowed characters
                    if not _VALID_PACKAGE_NAME.match(name):
                        logger.debug(f"Skipping invalid package name: {name}")
                        continue
                    deps[name] = version

        return deps

    def _parse_requirement_line(self, line: str) -> tuple[str | None, str | None]:
        """Parse a single requirement line.

        Handles formats like:
        - requests
        - requests==2.31.0
        - requests>=2.0,<3
        - requests[security]>=2.0
        """
        # Remove inline comments
        if "#" in line:
            line = line.split("#")[0].strip()

        if not line:
            return None, None

        # Handle various specifiers: ==, >=, <=, ~=, !=, <, >
        for op in ["==", ">=", "<=", "~=", "!=", "<", ">"]:
            if op in line:
                parts = line.split(op, 1)
                name = parts[0].strip()
                version = parts[1].strip() if op == "==" else None

                # Handle version ranges (e.g., "2.0,<3" -> just take first version)
                if version and "," in version:
                    version = None  # Can't determine exact version

                # Remove extras like [security]
                if "[" in name:
                    name = name.split("[")[0]

                return name, version

        # No version specifier
        name = line.strip()
        if "[" in name:
            name = name.split("[")[0]

        return name, None

    def _run_pipdeptree(self, packages: str | None = None) -> list[dict[str, Any]] | None:
        """Run pipdeptree and return JSON tree.

        Args:
            packages: Comma-separated list of package names to filter to.
                     If None, returns all packages in the environment.
        """
        cmd = ["pipdeptree", "--json-tree", "--warn", "silence"]
        if packages:
            cmd.extend(["--packages", packages])

        try:
            # nosemgrep: dangerous-subprocess-use-audit  # list-form, shell=False, fixed executable
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                logger.warning(f"pipdeptree failed: {result.stderr}")
                return None
            parsed: list[dict[str, Any]] = json.loads(result.stdout)
            return parsed
        except subprocess.TimeoutExpired:
            logger.warning("pipdeptree timed out")
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"pipdeptree output not valid JSON: {e}")
            return None
        except Exception as e:
            logger.warning(f"pipdeptree error: {e}")
            return None

    def _collect_transitives(
        self,
        pkg: dict[str, Any],
        direct_names: set[str],
        discovered: list[DiscoveredDependency],
        seen_package_versions: set[str],
        depth: int,
        parent: str | None = None,
    ) -> None:
        """Recursively collect transitive dependencies."""
        name = pkg.get("package_name", "")
        if not name:
            return
        version = pkg.get("installed_version", "")
        normalized = normalize_python_package_name(name)

        # Skip if already processed
        pkg_key = f"{normalized}@{version}"
        if pkg_key in seen_package_versions:
            return
        seen_package_versions.add(pkg_key)

        # If this is NOT a direct dependency and we're past the root level,
        # it's a transitive dependency
        if depth > 0 and normalized not in direct_names:
            discovered.append(
                DiscoveredDependency(
                    name=name,
                    version=version,
                    purl=f"pkg:pypi/{normalized}@{version}",
                    parent=parent,
                    depth=depth,
                    ecosystem="pypi",
                )
            )

        # Recurse into dependencies
        for dep in pkg.get("dependencies", []):
            self._collect_transitives(
                dep,
                direct_names,
                discovered,
                seen_package_versions,
                depth=depth + 1,
                parent=name,
            )
