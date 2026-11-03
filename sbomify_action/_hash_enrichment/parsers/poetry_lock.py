"""Parser for poetry.lock files (Python Poetry)."""

import tomllib
from pathlib import Path

from ..models import PackageHash


class PoetryLockParser:
    """Parser for poetry.lock files.

    poetry.lock is a TOML file with [[package]] sections:
    [[package]]
    name = "django"
    version = "5.1.1"

    [[package.files]]
    file = "django-5.1.1-py3-none-any.whl"
    hash = "sha256:abc123..."

    Or in newer versions:
    [package.files]
    "django-5.1.1-py3-none-any.whl" = "sha256:abc123..."
    """

    name = "poetry-lock"
    supported_files = ("poetry.lock",)
    ecosystem = "pypi"

    def supports(self, lock_file_name: str) -> bool:
        return lock_file_name in self.supported_files

    def parse(self, lock_file_path: Path) -> list[PackageHash]:
        """Parse poetry.lock and extract hashes.

        For each package, returns ONE hash with preference:
        1. Universal wheel (py3-none-any) if available
        2. First wheel hash if any wheels exist
        3. sdist hash as fallback

        Args:
            lock_file_path: Path to poetry.lock file

        Returns:
            List of PackageHash objects (one per package).
        """
        with lock_file_path.open("rb") as f:
            data = tomllib.load(f)

        hashes: list[PackageHash] = []
        packages = data.get("package", [])

        for pkg in packages:
            name = pkg.get("name")
            version = pkg.get("version")

            if not name or not version:
                continue

            # Collect all file entries with their hashes
            file_entries: list[tuple[str, str]] = []  # (filename, hash)

            files = pkg.get("files", [])

            # Handle files array format (newer poetry versions)
            if isinstance(files, list):
                for file_entry in files:
                    if isinstance(file_entry, dict):
                        hash_str = file_entry.get("hash")
                        filename = file_entry.get("file", "")
                        if hash_str and filename:
                            file_entries.append((filename, hash_str))

            # Handle dict format (some poetry versions)
            elif isinstance(files, dict):
                for filename, hash_str in files.items():
                    if isinstance(hash_str, str):
                        file_entries.append((filename, hash_str))

            # Select the best hash
            best = self._select_best_file_hash(file_entries)
            if best:
                filename, hash_str = best
                artifact_type = self._detect_artifact_type(filename)
                pkg_hash = PackageHash.from_prefixed(
                    name=name,
                    version=version,
                    prefixed_hash=hash_str,
                    artifact_type=artifact_type,
                )
                if pkg_hash:
                    hashes.append(pkg_hash)

        return hashes

    def _select_best_file_hash(self, file_entries: list[tuple[str, str]]) -> tuple[str, str] | None:
        """Select the best file hash from available entries.

        Prefers universal wheels (py3-none-any) over platform-specific ones,
        and wheels over sdists.
        """
        if not file_entries:
            return None

        universal_wheel = None
        first_wheel = None
        first_sdist = None

        for filename, hash_str in file_entries:
            is_wheel = filename.endswith(".whl")
            is_sdist = filename.endswith((".tar.gz", ".tar.bz2", ".zip"))

            if is_wheel:
                if first_wheel is None:
                    first_wheel = (filename, hash_str)
                if "py3-none-any" in filename or "py2.py3-none-any" in filename:
                    universal_wheel = (filename, hash_str)
                    break  # Found universal, stop searching
            elif is_sdist and first_sdist is None:
                first_sdist = (filename, hash_str)

        return universal_wheel or first_wheel or first_sdist

    @staticmethod
    def _detect_artifact_type(filename: str) -> str:
        """Detect artifact type from filename."""
        if filename.endswith(".whl"):
            return "wheel"
        elif filename.endswith((".tar.gz", ".tar.bz2", ".zip")):
            return "sdist"
        return "unknown"
