"""Archive extraction for Yocto SPDX tar.zst and tar.gz files."""

import sys
import tarfile
import tempfile
from pathlib import Path

from sbomify_action.exceptions import FileProcessingError
from sbomify_action.logging_config import logger


def _detect_archive_type(path: str) -> str:
    """Detect archive type from file extension.

    Returns:
        "zst" for .tar.zst, "gz" for .tar.gz

    Raises:
        FileProcessingError: If the archive type is not supported
    """
    p = Path(path)
    suffixes = "".join(p.suffixes).lower()
    if suffixes.endswith(".spdx.tar.zst") or suffixes.endswith(".tar.zst"):
        return "zst"
    if suffixes.endswith(".spdx.tar.gz") or suffixes.endswith(".tar.gz") or suffixes.endswith(".tgz"):
        return "gz"
    raise FileProcessingError(f"Unsupported archive type: {p.name}. Expected .tar.zst or .tar.gz")


def extract_archive(archive_path: str, dest_dir: str | None = None) -> str:
    """Extract a Yocto SPDX archive to a directory.

    Args:
        archive_path: Path to .tar.zst or .tar.gz archive
        dest_dir: Destination directory. If None, a temporary directory is created.

    Returns:
        Path to the directory containing extracted files.

    Raises:
        FileProcessingError: If extraction fails or archive is invalid
    """
    path = Path(archive_path)
    if not path.exists():
        raise FileProcessingError(f"Archive not found: {archive_path}")

    archive_type = _detect_archive_type(archive_path)

    if dest_dir is None:
        dest_dir = tempfile.mkdtemp(prefix="yocto-spdx-")

    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)

    logger.info(f"Extracting {path.name} to {dest}")

    try:
        if archive_type == "zst":
            _extract_tar_zst(path, dest)
        else:
            _extract_tar_gz(path, dest)
    except FileProcessingError:
        raise
    except Exception as e:
        raise FileProcessingError(f"Failed to extract archive {path.name}: {e}") from e

    # Count extracted files
    extracted = list(dest.rglob("*.spdx.json"))
    if not extracted:
        raise FileProcessingError(f"No .spdx.json files found in archive {path.name}")

    logger.info(f"Extracted {len(extracted)} SPDX files from {path.name}")
    return str(dest)


def _extract_tar_zst(archive: Path, dest: Path) -> None:
    """Extract a tar.zst archive.

    Python 3.14+ reads zstd natively (PEP 784), so the zstandard package is
    only needed on older interpreters. It ships no wheels for 3.15, and the
    image has no compiler to build it from source.
    """
    if sys.version_info >= (3, 14):
        with tarfile.open(archive, mode="r|zst") as tar:
            tar.extractall(path=dest, filter="data")
        return

    import zstandard

    dctx = zstandard.ZstdDecompressor()
    with open(archive, "rb") as fh:
        with dctx.stream_reader(fh) as reader:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                tar.extractall(path=dest, filter="data")


def _extract_tar_gz(archive: Path, dest: Path) -> None:
    """Extract a tar.gz archive."""
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(path=dest, filter="data")
