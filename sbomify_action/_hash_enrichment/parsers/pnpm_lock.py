"""Parser for pnpm-lock.yaml files (pnpm)."""

from pathlib import Path
from typing import Any

import yaml

from ..models import PackageHash


class PnpmLockParser:
    """Parser for pnpm-lock.yaml files.

    pnpm-lock.yaml v6+ structure:
    packages:
      /@scope/name@1.2.3:
        resolution: {integrity: sha512-...}
        ...

    Or for newer versions (v9+):
    packages:
      '@scope/name@1.2.3':
        resolution:
          integrity: sha512-...

    Or snapshots format:
    snapshots:
      package@version:
        ...
    """

    name = "pnpm-lock"
    supported_files = ("pnpm-lock.yaml",)
    ecosystem = "npm"

    def supports(self, lock_file_name: str) -> bool:
        return lock_file_name in self.supported_files

    def parse(self, lock_file_path: Path) -> list[PackageHash]:
        """Parse pnpm-lock.yaml and extract hashes.

        Args:
            lock_file_path: Path to pnpm-lock.yaml file

        Returns:
            List of PackageHash objects for all packages with integrity hashes.
        """
        with lock_file_path.open("r") as f:
            data = yaml.safe_load(f)

        hashes: list[PackageHash] = []

        if not isinstance(data, dict):
            return hashes

        seen: set[tuple[str, str]] = set()

        # Try packages section (v5-v8)
        packages = data.get("packages", {})
        if packages:
            hashes.extend(self._parse_packages(packages, seen))

        # Try snapshots section (v9+)
        snapshots = data.get("snapshots", {})
        if snapshots and not hashes:
            hashes.extend(self._parse_snapshots(snapshots, data, seen))

        return hashes

    def _parse_packages(self, packages: dict[str, Any], seen: set[tuple[str, str]] | None = None) -> list[PackageHash]:
        """Parse packages section.

        Deduplicates by (name, version) to return one hash per package@version.
        """
        if seen is None:
            seen = set()

        hashes: list[PackageHash] = []

        for pkg_key, pkg_data in packages.items():
            if not isinstance(pkg_data, dict):
                continue

            # Extract name and version from key
            # Formats: "/@scope/name@1.2.3" or "/name@1.2.3" or "@scope/name@1.2.3"
            name, version = self._parse_package_key(pkg_key)
            if not name or not version:
                continue

            # Deduplicate by (name, version)
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)

            # Get integrity from resolution
            resolution = pkg_data.get("resolution", {})
            if isinstance(resolution, dict):
                integrity = resolution.get("integrity")
            else:
                integrity = None

            if not integrity:
                continue

            pkg_hash = PackageHash.from_sri(
                name=name,
                version=version,
                sri_hash=integrity,
                artifact_type="tarball",
            )
            if pkg_hash:
                hashes.append(pkg_hash)

        return hashes

    def _parse_snapshots(
        self, snapshots: dict[str, Any], data: dict[str, Any], seen: set[tuple[str, str]] | None = None
    ) -> list[PackageHash]:
        """Parse snapshots section (pnpm v9+).

        In v9+, the integrity is in the packages section keyed by name@version,
        while snapshots just reference them.
        """
        if seen is None:
            seen = set()

        hashes: list[PackageHash] = []
        packages = data.get("packages", {})

        for snap_key in snapshots:
            # Parse name and version from snapshot key
            name, version = self._parse_package_key(snap_key)
            if not name or not version:
                continue

            # Deduplicate by (name, version)
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)

            # Look up integrity in packages section
            # Try different key formats
            pkg_data = None
            for key_format in [f"{name}@{version}", f"/{name}@{version}"]:
                if key_format in packages:
                    pkg_data = packages[key_format]
                    break

            if not pkg_data or not isinstance(pkg_data, dict):
                continue

            resolution = pkg_data.get("resolution", {})
            if isinstance(resolution, dict):
                integrity = resolution.get("integrity")
            else:
                integrity = None

            if not integrity:
                continue

            pkg_hash = PackageHash.from_sri(
                name=name,
                version=version,
                sri_hash=integrity,
                artifact_type="tarball",
            )
            if pkg_hash:
                hashes.append(pkg_hash)

        return hashes

    @staticmethod
    def _parse_package_key(key: str) -> tuple[str | None, str | None]:
        """Parse package name and version from pnpm key.

        Formats:
        - "/@scope/name@1.2.3"
        - "/name@1.2.3"
        - "@scope/name@1.2.3"
        - "name@1.2.3"
        - "/@scope/name@1.2.3(peer@2.0.0)"  # with peer deps
        """
        # Remove leading slash if present
        if key.startswith("/"):
            key = key[1:]

        # Remove peer dependency suffix if present
        if "(" in key:
            key = key.split("(")[0]

        # Find the @ that separates name from version
        if key.startswith("@"):
            # Scoped package: @scope/name@version
            at_pos = key.find("@", 1)
        else:
            # Unscoped package: name@version
            at_pos = key.find("@")

        if at_pos == -1:
            return None, None

        name = key[:at_pos]
        version = key[at_pos + 1 :]

        return name, version
