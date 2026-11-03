"""Hashes for PlatformIO libraries, from the PlatformIO registry."""

from collections import Counter
from pathlib import Path
from typing import Any

import requests

from sbomify_action._platformio import InstalledLibrary, installed_libraries
from sbomify_action.http_client import get_default_headers
from sbomify_action.logging_config import logger

from ..models import HashAlgorithm, PackageHash, normalize_package_name

REGISTRY_API = "https://api.registry.platformio.org/v3/packages"
DEFAULT_TIMEOUT = 10  # seconds


class _RegistryUnreachable(Exception):
    """The registry did not answer at all; asking again for the next library will not help."""


def _registry_versions(version: str) -> list[str]:
    """The installed version, then the forms the registry may hold it under.

    PlatformIO normalises versions to full semver when it installs, so a
    release published as `2.8` is recorded in `.piopm` as `2.8.0` -- and the
    registry answers only to `2.8`.
    """
    candidates = [version]
    trimmed = version
    while trimmed.endswith(".0") and trimmed.count(".") > 1:
        trimmed = trimmed[: -len(".0")]
        candidates.append(trimmed)
    return candidates


def _archive_sha256(release: dict[str, Any]) -> str | None:
    """The checksum of the archive for every system, else the only one there is."""
    files = [f for f in release.get("files") or [] if isinstance(f, dict)]
    universal = [f for f in files if f.get("system") in (None, "*")]
    for artifact in universal or (files if len(files) == 1 else []):
        checksum = artifact.get("checksum")
        sha256 = checksum.get("sha256") if isinstance(checksum, dict) else None
        if sha256:
            return str(sha256)
    return None


def _fetch_sha256(library: InstalledLibrary) -> str | None:
    url = f"{REGISTRY_API}/{library.owner}/library/{library.name}"
    for version in _registry_versions(library.version):
        try:
            response = requests.get(
                url, params={"version": version}, headers=get_default_headers(), timeout=DEFAULT_TIMEOUT
            )
        except (requests.ConnectionError, requests.Timeout) as e:
            raise _RegistryUnreachable(str(e)) from e
        except requests.RequestException as e:
            logger.debug(f"PlatformIO registry: {library.owner}/{library.name}: {e}")
            return None
        if response.status_code != 200:
            continue
        try:
            body = response.json()
        except ValueError:
            return None
        release = body.get("version") if isinstance(body, dict) else None
        if not isinstance(release, dict) or release.get("name") != version:
            continue
        return _archive_sha256(release)
    return None


class PlatformIOParser:
    """SHA-256 of each registry library's published archive.

    PlatformIO records no hash at install time, but the registry publishes
    one for every release: the checksum of the archive `pio pkg install`
    downloads. That is the same thing Cargo.lock or package-lock.json records.

    Libraries installed from git get no hash here. Their commit, which pins
    the source exactly, is already in the component's purl.
    """

    name = "platformio"
    supported_files = ("platformio.ini",)
    ecosystem = "platformio"

    def supports(self, lock_file_name: str) -> bool:
        return lock_file_name in self.supported_files

    def parse(self, lock_file_path: Path) -> list[PackageHash]:
        libraries = installed_libraries(lock_file_path)
        # Hashes are matched to components by name and version. Two
        # installed libraries sharing both -- different owners, or a registry
        # copy beside an archive -- cannot be told apart that way, and a hash
        # on the wrong one is worse than none.
        keys = Counter((normalize_package_name(library.name, self.ecosystem), library.version) for library in libraries)
        hashes: list[PackageHash] = []
        for library in libraries:
            if not library.from_registry:
                continue
            if keys[(normalize_package_name(library.name, self.ecosystem), library.version)] > 1:
                logger.info(f"PlatformIO: more than one {library.name}@{library.version} installed; not hashing it")
                continue
            try:
                sha256 = _fetch_sha256(library)
            except _RegistryUnreachable as e:
                logger.warning(f"PlatformIO registry unreachable, skipping hashes: {e}")
                break
            if sha256:
                hashes.append(
                    PackageHash(
                        name=library.name,
                        version=library.version,
                        algorithm=HashAlgorithm.SHA256,
                        value=sha256,
                        artifact_type="tarball",
                    )
                )
        return hashes
