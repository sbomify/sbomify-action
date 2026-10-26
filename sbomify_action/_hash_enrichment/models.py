"""Data models for lockfile hash extraction."""

from dataclasses import dataclass
from enum import Enum


class HashAlgorithm(Enum):
    """Supported hash algorithms with CycloneDX/SPDX mappings.

    Algorithm names follow CycloneDX conventions (with hyphens).
    Use cyclonedx_alg and spdx_alg properties for format-specific names.
    """

    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"
    BLAKE2B_256 = "BLAKE2b-256"
    BLAKE2B_384 = "BLAKE2b-384"
    BLAKE2B_512 = "BLAKE2b-512"
    BLAKE3 = "BLAKE3"

    @property
    def cyclonedx_alg(self) -> str:
        """Return CycloneDX algorithm name."""
        return self.value

    @property
    def spdx_alg(self) -> str:
        """Return SPDX algorithm name.

        SPDX uses specific algorithm names:
        - SHA-1 → SHA1, SHA-256 → SHA256, etc. (no hyphen)
        - SHA3-256 → SHA3-256 (keep hyphen for SHA3)
        - BLAKE2b-256 → BLAKE2b-256 (keep format with lowercase 'b')
        - BLAKE3 → BLAKE3
        """
        # BLAKE algorithms keep their exact format
        if self.value.startswith("BLAKE"):
            return self.value
        # SHA3 keeps the hyphen
        if self.value.startswith("SHA3"):
            return self.value
        # SHA-1, SHA-256, etc. remove hyphen
        return self.value.replace("-", "")

    @classmethod
    def from_prefix(cls, prefix: str) -> "HashAlgorithm | None":
        """Parse algorithm from common hash prefixes.

        Args:
            prefix: Hash prefix like 'sha256', 'sha512', 'md5', etc.

        Returns:
            HashAlgorithm if recognized, None otherwise.
        """
        mapping = {
            "md5": cls.MD5,
            "sha1": cls.SHA1,
            "sha-1": cls.SHA1,
            "sha256": cls.SHA256,
            "sha-256": cls.SHA256,
            "sha384": cls.SHA384,
            "sha-384": cls.SHA384,
            "sha512": cls.SHA512,
            "sha-512": cls.SHA512,
            "sha3-256": cls.SHA3_256,
            "sha3-384": cls.SHA3_384,
            "sha3-512": cls.SHA3_512,
            "blake2b-256": cls.BLAKE2B_256,
            "blake2b-384": cls.BLAKE2B_384,
            "blake2b-512": cls.BLAKE2B_512,
            "blake3": cls.BLAKE3,
        }
        return mapping.get(prefix.lower())


@dataclass
class PackageHash:
    """Hash extracted from a lockfile.

    Represents a single hash value for a specific package version.
    A package may have multiple hashes (e.g., for sdist and wheels,
    or multiple algorithms).
    """

    name: str
    version: str
    algorithm: HashAlgorithm
    value: str  # Hex-encoded hash value
    artifact_type: str = "unknown"  # e.g., "sdist", "wheel", "tarball"

    @classmethod
    def from_prefixed(
        cls,
        name: str,
        version: str,
        prefixed_hash: str,
        artifact_type: str = "unknown",
    ) -> "PackageHash | None":
        """Parse hash from prefixed format like 'sha256:abc123...'.

        Args:
            name: Package name
            version: Package version
            prefixed_hash: Hash string with algorithm prefix (e.g., 'sha256:abc...')
            artifact_type: Type of artifact (sdist, wheel, etc.)

        Returns:
            PackageHash if parsing succeeds, None otherwise.
        """
        if ":" not in prefixed_hash:
            return None

        prefix, value = prefixed_hash.split(":", 1)
        algorithm = HashAlgorithm.from_prefix(prefix)
        if algorithm is None:
            return None

        return cls(
            name=name,
            version=version,
            algorithm=algorithm,
            value=value,
            artifact_type=artifact_type,
        )

    @classmethod
    def from_sri(
        cls,
        name: str,
        version: str,
        sri_hash: str,
        artifact_type: str = "unknown",
    ) -> "PackageHash | None":
        """Parse hash from SRI (Subresource Integrity) format.

        SRI format: algorithm-base64hash (e.g., 'sha512-abc...=')
        Used by npm, yarn, pnpm.

        Args:
            name: Package name
            version: Package version
            sri_hash: SRI hash string (e.g., 'sha512-abc...')
            artifact_type: Type of artifact

        Returns:
            PackageHash if parsing succeeds, None otherwise.
        """
        import base64

        if "-" not in sri_hash:
            return None

        prefix, b64_value = sri_hash.split("-", 1)
        algorithm = HashAlgorithm.from_prefix(prefix)
        if algorithm is None:
            return None

        try:
            # Convert base64 to hex
            hex_value = base64.b64decode(b64_value).hex()
        except Exception:
            return None

        return cls(
            name=name,
            version=version,
            algorithm=algorithm,
            value=hex_value,
            artifact_type=artifact_type,
        )


def normalize_package_name(name: str, ecosystem: str) -> str:
    """Normalize package name for matching across lockfile and SBOM.

    Different ecosystems have different normalization rules:
    - PyPI: case-insensitive, underscores/hyphens/dots are equivalent
    - npm: case-insensitive (scoped packages normalize scope and name separately)
    - Cargo: case-insensitive, hyphens and underscores equivalent
    - pub (Dart): case-insensitive, underscores only (no hyphens allowed)

    Args:
        name: Package name to normalize
        ecosystem: Ecosystem identifier (pypi, npm, cargo, pub, etc.)

    Returns:
        Normalized package name for comparison.
    """
    if ecosystem == "pypi":
        # PEP 503: normalize by lowercasing and replacing separators
        return name.lower().replace("-", "_").replace(".", "_")
    elif ecosystem == "npm":
        # npm is case-insensitive for both scoped and unscoped packages
        # Scoped: @scope/name -> @scope/name (lowercased)
        return name.lower()
    elif ecosystem == "cargo":
        # Cargo is case-insensitive, hyphens and underscores equivalent
        return name.lower().replace("-", "_")
    elif ecosystem == "pub":
        # Dart pub packages are lowercase with underscores only
        return name.lower()
    elif ecosystem == "platformio":
        # SPDX conversion folds the registry owner into the name
        # ("bblanchon/ArduinoJson"); the registry itself matches names
        # case-insensitively.
        return name.rsplit("/", 1)[-1].lower()
    else:
        # Default: lowercase
        return name.lower()
