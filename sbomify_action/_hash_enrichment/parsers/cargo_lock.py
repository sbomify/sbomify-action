"""Parser for Cargo.lock files (Rust)."""

import tomllib
from pathlib import Path

from ..models import HashAlgorithm, PackageHash


class CargoLockParser:
    """Parser for Cargo.lock files.

    Cargo.lock is a TOML file with [[package]] sections:
    [[package]]
    name = "serde"
    version = "1.0.193"
    checksum = "abc123..."  # Always SHA256, no prefix
    """

    name = "cargo-lock"
    supported_files = ("Cargo.lock",)
    ecosystem = "cargo"

    def supports(self, lock_file_name: str) -> bool:
        return lock_file_name in self.supported_files

    def parse(self, lock_file_path: Path) -> list[PackageHash]:
        """Parse Cargo.lock and extract hashes.

        Args:
            lock_file_path: Path to Cargo.lock file

        Returns:
            List of PackageHash objects for all packages with checksums.
        """
        with lock_file_path.open("rb") as f:
            data = tomllib.load(f)

        hashes: list[PackageHash] = []
        packages = data.get("package", [])

        for pkg in packages:
            name = pkg.get("name")
            version = pkg.get("version")
            checksum = pkg.get("checksum")

            if not name or not version or not checksum:
                continue

            # Cargo checksums are always SHA256, no prefix
            hashes.append(
                PackageHash(
                    name=name,
                    version=version,
                    algorithm=HashAlgorithm.SHA256,
                    value=checksum,
                    artifact_type="crate",
                )
            )

        return hashes
