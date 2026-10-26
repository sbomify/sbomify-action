"""Parser for pubspec.lock files (Dart/Flutter)."""

from pathlib import Path

import yaml

from ..models import HashAlgorithm, PackageHash


class PubspecLockParser:
    """Parser for pubspec.lock files.

    pubspec.lock is a YAML file with structure:
    packages:
      package_name:
        dependency: "direct main"
        description:
          name: package_name
          sha256: abc123...
          url: "https://pub.dev"
        source: hosted
        version: "1.2.3"
    """

    name = "pubspec-lock"
    supported_files = ("pubspec.lock",)
    ecosystem = "pub"

    def supports(self, lock_file_name: str) -> bool:
        return lock_file_name in self.supported_files

    def parse(self, lock_file_path: Path) -> list[PackageHash]:
        """Parse pubspec.lock and extract hashes.

        Args:
            lock_file_path: Path to pubspec.lock file

        Returns:
            List of PackageHash objects for all packages with hashes.
        """
        with lock_file_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        hashes: list[PackageHash] = []
        packages = data.get("packages", {})

        for name, pkg_data in packages.items():
            if not isinstance(pkg_data, dict):
                continue

            version = pkg_data.get("version")
            if version and version.startswith('"') and version.endswith('"'):
                version = version[1:-1]

            if not version:
                continue

            # Hash is in description.sha256
            description = pkg_data.get("description", {})
            if isinstance(description, dict):
                sha256 = description.get("sha256")
                if sha256:
                    hashes.append(
                        PackageHash(
                            name=name,
                            version=version,
                            algorithm=HashAlgorithm.SHA256,
                            value=sha256,
                            artifact_type="package",
                        )
                    )

        return hashes
