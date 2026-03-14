"""Parser for uv.lock files (Python uv package manager)."""

from pathlib import Path

import tomllib

from ..models import PackageHash


class UvLockParser:
    """Parser for uv.lock files.

    uv.lock is a TOML file with [[package]] sections containing:
    - name, version
    - sdist = { hash = "sha256:...", ... }
    - wheels = [{ hash = "sha256:...", ... }, ...]
    """

    name = "uv-lock"
    supported_files = ("uv.lock",)
    ecosystem = "pypi"

    def supports(self, lock_file_name: str) -> bool:
        return lock_file_name in self.supported_files

    def parse(self, lock_file_path: Path) -> list[PackageHash]:
        """Parse uv.lock and extract hashes.

        For each package, returns ONE hash with preference:
        1. Universal wheel (py3-none-any) if available
        2. First wheel hash if any wheels exist
        3. sdist hash as fallback

        Args:
            lock_file_path: Path to uv.lock file

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

            # Try to find the best wheel hash (prefer universal wheels)
            wheels = pkg.get("wheels", [])
            wheel_hash = self._select_best_wheel_hash(wheels)

            if wheel_hash:
                pkg_hash = PackageHash.from_prefixed(
                    name=name,
                    version=version,
                    prefixed_hash=wheel_hash,
                    artifact_type="wheel",
                )
                if pkg_hash:
                    hashes.append(pkg_hash)
                continue

            # Fall back to sdist hash if no wheels
            sdist = pkg.get("sdist")
            if sdist and isinstance(sdist, dict):
                hash_str = sdist.get("hash")
                if hash_str:
                    pkg_hash = PackageHash.from_prefixed(
                        name=name,
                        version=version,
                        prefixed_hash=hash_str,
                        artifact_type="sdist",
                    )
                    if pkg_hash:
                        hashes.append(pkg_hash)

        return hashes

    def _select_best_wheel_hash(self, wheels: list[dict[str, str]]) -> str | None:
        """Select the best wheel hash from available wheels.

        Prefers universal wheels (py3-none-any) over platform-specific ones.
        """
        if not wheels:
            return None

        universal_hash = None
        first_hash = None

        for wheel in wheels:
            if not isinstance(wheel, dict):
                continue

            hash_str = wheel.get("hash")
            if not hash_str:
                continue

            # Track first valid hash as fallback
            if first_hash is None:
                first_hash = hash_str

            # Check if this is a universal wheel
            url = wheel.get("url", "")
            filename = wheel.get("filename", "") or url.split("/")[-1] if url else ""
            if "py3-none-any" in filename or "py2.py3-none-any" in filename:
                universal_hash = hash_str
                break  # Found universal, stop searching

        return universal_hash or first_hash
