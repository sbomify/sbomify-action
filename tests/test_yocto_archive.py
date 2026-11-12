"""Tests for Yocto archive extraction."""

import json
import os
import sys
import tarfile
from pathlib import Path

import pytest

from sbomify_action._yocto.archive import _detect_archive_type, extract_archive
from sbomify_action.exceptions import FileProcessingError

YOCTO_TEST_DATA = Path(__file__).parent / "test-data" / "yocto"


def _create_tar_gz(dest_path: str, source_dir: str) -> None:
    """Helper to create a tar.gz from a directory."""
    with tarfile.open(dest_path, "w:gz") as tar:
        for f in Path(source_dir).glob("*.spdx.json"):
            tar.add(f, arcname=f.name)


def _create_tar_zst(dest_path: str, source_dir: str) -> None:
    """Helper to create a tar.zst from a directory."""
    # First create a tar in memory, then compress with zstd
    tar_path = dest_path + ".tar"
    with tarfile.open(tar_path, "w") as tar:
        for f in Path(source_dir).glob("*.spdx.json"):
            tar.add(f, arcname=f.name)

    with open(tar_path, "rb") as ifh, open(dest_path, "wb") as ofh:
        if sys.version_info >= (3, 14):
            from compression import zstd

            ofh.write(zstd.compress(ifh.read()))
        else:
            import zstandard

            zstandard.ZstdCompressor().copy_stream(ifh, ofh)
    os.unlink(tar_path)


class TestDetectArchiveType:
    def test_tar_zst(self):
        assert _detect_archive_type("image.spdx.tar.zst") == "zst"

    def test_tar_gz(self):
        assert _detect_archive_type("image.spdx.tar.gz") == "gz"

    def test_plain_tar_zst(self):
        assert _detect_archive_type("image.tar.zst") == "zst"

    def test_plain_tar_gz(self):
        assert _detect_archive_type("image.tar.gz") == "gz"

    def test_tgz(self):
        assert _detect_archive_type("image.tgz") == "gz"

    def test_unsupported(self):
        with pytest.raises(FileProcessingError, match="Unsupported archive type"):
            _detect_archive_type("image.zip")


class TestExtractArchive:
    def test_extract_tar_gz(self, tmp_path):
        archive = str(tmp_path / "test.spdx.tar.gz")
        _create_tar_gz(archive, str(YOCTO_TEST_DATA))

        dest = str(tmp_path / "output")
        result = extract_archive(archive, dest)

        assert result == dest
        extracted = list(Path(dest).glob("*.spdx.json"))
        assert len(extracted) >= 3  # at least our 3 packages + rootfs + recipe + runtime

    def test_extract_tar_zst(self, tmp_path):
        archive = str(tmp_path / "test.spdx.tar.zst")
        _create_tar_zst(archive, str(YOCTO_TEST_DATA))

        dest = str(tmp_path / "output")
        result = extract_archive(archive, dest)

        assert result == dest
        extracted = list(Path(dest).glob("*.spdx.json"))
        assert len(extracted) >= 3

    def test_extract_creates_temp_dir(self, tmp_path):
        archive = str(tmp_path / "test.spdx.tar.gz")
        _create_tar_gz(archive, str(YOCTO_TEST_DATA))

        result = extract_archive(archive)
        try:
            assert Path(result).exists()
            extracted = list(Path(result).glob("*.spdx.json"))
            assert len(extracted) >= 3
        finally:
            import shutil

            shutil.rmtree(result, ignore_errors=True)

    def test_archive_not_found(self):
        with pytest.raises(FileProcessingError, match="Archive not found"):
            extract_archive("/nonexistent/path.spdx.tar.zst")

    def test_no_spdx_files(self, tmp_path):
        # Create an archive with no .spdx.json files
        dummy = tmp_path / "src"
        dummy.mkdir()
        (dummy / "readme.txt").write_text("hello")

        archive = str(tmp_path / "empty.tar.gz")
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(str(dummy / "readme.txt"), arcname="readme.txt")

        with pytest.raises(FileProcessingError, match="No .spdx.json files found"):
            extract_archive(archive, str(tmp_path / "out"))

    def test_spdx_version_present_in_extracted(self, tmp_path):
        """Verify extracted files contain SPDX 2.2 content."""
        archive = str(tmp_path / "test.spdx.tar.gz")
        _create_tar_gz(archive, str(YOCTO_TEST_DATA))

        dest = str(tmp_path / "output")
        extract_archive(archive, dest)

        # Check at least one file has spdxVersion
        for f in Path(dest).glob("*.spdx.json"):
            with open(f) as fh:
                data = json.load(fh)
            assert data.get("spdxVersion") == "SPDX-2.2"
            break
