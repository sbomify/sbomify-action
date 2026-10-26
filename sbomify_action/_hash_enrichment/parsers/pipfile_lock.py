"""Parser for Pipfile.lock files (Python Pipenv)."""

import json
from pathlib import Path

from ..models import PackageHash


class PipfileLockParser:
    """Parser for Pipfile.lock files.

    Pipfile.lock is a JSON file with structure:
    {
        "default": {
            "package-name": {
                "hashes": ["sha256:...", "sha256:..."],
                "version": "==1.2.3"
            }
        },
        "develop": { ... }
    }
    """

    name = "pipfile-lock"
    supported_files = ("Pipfile.lock",)
    ecosystem = "pypi"

    def supports(self, lock_file_name: str) -> bool:
        return lock_file_name in self.supported_files

    def parse(self, lock_file_path: Path) -> list[PackageHash]:
        """Parse Pipfile.lock and extract hashes.

        For each package, returns ONE hash. If multiple algorithms are present,
        prefers SHA-512 > SHA-384 > SHA-256.

        Args:
            lock_file_path: Path to Pipfile.lock file

        Returns:
            List of PackageHash objects (one per package).
        """
        with lock_file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        hashes: list[PackageHash] = []
        seen_packages: set[tuple[str, str]] = set()  # (name, version)

        # Process both default and develop sections
        for section in ["default", "develop"]:
            packages = data.get(section, {})
            for name, pkg_data in packages.items():
                if not isinstance(pkg_data, dict):
                    continue

                # Version has == prefix, e.g., "==5.1.1"
                version = pkg_data.get("version", "")
                if version.startswith("=="):
                    version = version[2:]
                elif version.startswith("="):
                    version = version[1:]

                if not version:
                    continue

                # Skip if we've already processed this package
                pkg_key = (name.lower(), version)
                if pkg_key in seen_packages:
                    continue
                seen_packages.add(pkg_key)

                # Hashes are prefixed, e.g., "sha256:abc123..."
                # Pick the best hash (prefer stronger algorithms)
                pkg_hashes = pkg_data.get("hashes", [])
                best_hash = self._select_best_hash(pkg_hashes)
                if best_hash:
                    pkg_hash = PackageHash.from_prefixed(
                        name=name,
                        version=version,
                        prefixed_hash=best_hash,
                        artifact_type="wheel",  # Pipenv typically installs wheels
                    )
                    if pkg_hash:
                        hashes.append(pkg_hash)

        return hashes

    @staticmethod
    def _select_best_hash(hash_strings: list[str]) -> str | None:
        """Select the best hash from available hashes.

        Prefers stronger algorithms: SHA-512 > SHA-384 > SHA-256 > SHA-1 > MD5.
        """
        if not hash_strings:
            return None

        # Priority order (higher is better)
        priority = {
            "sha512": 5,
            "sha384": 4,
            "sha256": 3,
            "sha1": 2,
            "md5": 1,
        }

        best_hash = None
        best_priority = 0

        for hash_str in hash_strings:
            if ":" not in hash_str:
                continue
            prefix = hash_str.split(":")[0].lower()
            hash_priority = priority.get(prefix, 0)
            if hash_priority > best_priority:
                best_priority = hash_priority
                best_hash = hash_str

        return best_hash or (hash_strings[0] if hash_strings else None)
