"""Tests for Yocto pipeline orchestrator."""

import json
import shutil
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from sbomify_action._upload.result import UploadResult
from sbomify_action._yocto.models import YoctoConfig, YoctoPipelineResult
from sbomify_action._yocto.pipeline import _process_single_package, run_yocto_pipeline
from sbomify_action.exceptions import APIError, ConfigurationError, PlanLimitError

YOCTO_TEST_DATA = Path(__file__).parent / "test-data" / "yocto"
API_BASE = "https://app.sbomify.com"
TOKEN = "test-token"


def _make_tar_gz(tmp_path: Path) -> str:
    """Create a tar.gz from test fixtures."""
    archive_path = str(tmp_path / "test.spdx.tar.gz")
    with tarfile.open(archive_path, "w:gz") as tar:
        for f in YOCTO_TEST_DATA.glob("*.spdx.json"):
            tar.add(str(f), arcname=f.name)
    return archive_path


def _make_config(archive_path: str, **kwargs) -> YoctoConfig:
    defaults = {
        "input_path": archive_path,
        "token": TOKEN,
        "product_id": "test-product",
        "release_version": "1.0.0",
        "api_base_url": API_BASE,
    }
    defaults.update(kwargs)
    return YoctoConfig(**defaults)


class TestProcessSinglePackage:
    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    def test_upload_success(self, mock_upload, tmp_path):
        spdx_file = str(YOCTO_TEST_DATA / "busybox.spdx.json")
        mock_upload.return_value = UploadResult.success_result(destination_name="sbomify", sbom_id="sbom-123")
        config = _make_config(str(tmp_path / "dummy.tar.gz"))

        result = _process_single_package("busybox", spdx_file, "comp-1", config)
        assert result == "sbom-123"

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    def test_duplicate_artifact_returns_none(self, mock_upload, tmp_path):
        spdx_file = str(YOCTO_TEST_DATA / "busybox.spdx.json")
        mock_upload.return_value = UploadResult.failure_result(
            destination_name="sbomify",
            error_message="Duplicate",
            error_code="DUPLICATE_ARTIFACT",
        )
        config = _make_config(str(tmp_path / "dummy.tar.gz"))

        result = _process_single_package("busybox", spdx_file, "comp-1", config)
        assert result is None

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    def test_upload_failure_raises(self, mock_upload, tmp_path):
        spdx_file = str(YOCTO_TEST_DATA / "busybox.spdx.json")
        mock_upload.return_value = UploadResult.failure_result(
            destination_name="sbomify",
            error_message="Server error",
        )
        config = _make_config(str(tmp_path / "dummy.tar.gz"))

        with pytest.raises(APIError, match="Upload failed"):
            _process_single_package("busybox", spdx_file, "comp-1", config)

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    def test_upload_success_without_sbom_id_raises(self, mock_upload, tmp_path):
        spdx_file = str(YOCTO_TEST_DATA / "busybox.spdx.json")
        mock_upload.return_value = UploadResult.success_result(destination_name="sbomify", sbom_id=None)
        config = _make_config(str(tmp_path / "dummy.tar.gz"))

        with pytest.raises(APIError, match="no SBOM ID was returned"):
            _process_single_package("busybox", spdx_file, "comp-1", config)

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.augment_sbom_from_file")
    def test_augment_called(self, mock_augment, mock_upload, tmp_path):
        spdx_file = str(YOCTO_TEST_DATA / "busybox.spdx.json")

        # Make augment write the file so upload can read it
        def fake_augment(input_file, output_file, **kwargs):
            shutil.copy(input_file, output_file)
            return "spdx"

        mock_augment.side_effect = fake_augment
        mock_upload.return_value = UploadResult.success_result(destination_name="sbomify", sbom_id="sbom-456")
        config = _make_config(str(tmp_path / "dummy.tar.gz"), augment=True)

        result = _process_single_package("busybox", spdx_file, "comp-1", config)
        assert result == "sbom-456"
        mock_augment.assert_called_once()

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.enrich_sbom")
    def test_enrich_called(self, mock_enrich, mock_upload, tmp_path):
        spdx_file = str(YOCTO_TEST_DATA / "busybox.spdx.json")

        def fake_enrich(input_file, output_file, **kwargs):
            shutil.copy(input_file, output_file)

        mock_enrich.side_effect = fake_enrich
        mock_upload.return_value = UploadResult.success_result(destination_name="sbomify", sbom_id="sbom-789")
        config = _make_config(str(tmp_path / "dummy.tar.gz"), enrich=True)

        result = _process_single_package("busybox", spdx_file, "comp-1", config)
        assert result == "sbom-789"
        mock_enrich.assert_called_once()


class TestRunYoctoPipeline:
    @patch("sbomify_action._yocto.pipeline.tag_sbom_with_release")
    @patch("sbomify_action._yocto.pipeline.create_release")
    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.list_components")
    def test_full_pipeline(self, mock_list, mock_upload, mock_create_release, mock_tag, tmp_path):
        archive = _make_tar_gz(tmp_path)
        config = _make_config(archive)

        mock_list.return_value = {}  # no existing components
        mock_upload.return_value = UploadResult.success_result(destination_name="sbomify", sbom_id="sbom-001")
        mock_create_release.return_value = "release-001"

        with patch("sbomify_action._yocto.pipeline.get_or_create_component") as mock_goc:
            mock_goc.return_value = ("comp-new", True)
            result = run_yocto_pipeline(config)

        assert result.packages_found == 3  # busybox, base-files, zlib
        assert result.sboms_uploaded == 3
        assert result.components_created == 3
        assert result.errors == 0
        assert result.release_id == "release-001"
        assert mock_tag.call_count == 3

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.list_components")
    def test_dry_run(self, mock_list, mock_upload, tmp_path):
        archive = _make_tar_gz(tmp_path)
        config = _make_config(archive, dry_run=True)

        result = run_yocto_pipeline(config)

        assert result.packages_found == 3
        assert result.sboms_uploaded == 0
        assert result.sboms_skipped == 3
        mock_list.assert_not_called()
        mock_upload.assert_not_called()

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.list_components")
    def test_continue_on_error(self, mock_list, mock_upload, tmp_path):
        archive = _make_tar_gz(tmp_path)
        config = _make_config(archive)

        mock_list.return_value = {}
        # First package fails, rest succeed
        call_count = {"n": 0}

        def upload_side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise APIError("Connection failed")
            return UploadResult.success_result(destination_name="sbomify", sbom_id=f"sbom-{call_count['n']}")

        mock_upload.side_effect = upload_side_effect

        with patch("sbomify_action._yocto.pipeline.get_or_create_component") as mock_goc:
            mock_goc.return_value = ("comp-1", True)
            with patch("sbomify_action._yocto.pipeline.create_release") as mock_rel:
                mock_rel.return_value = "rel-1"
                with patch("sbomify_action._yocto.pipeline.tag_sbom_with_release"):
                    result = run_yocto_pipeline(config)

        assert result.packages_found == 3
        assert result.errors >= 1
        assert result.sboms_uploaded >= 1  # at least some succeeded
        assert result.has_errors is True

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.list_components")
    def test_duplicate_artifacts_counted_as_skipped(self, mock_list, mock_upload, tmp_path):
        archive = _make_tar_gz(tmp_path)
        config = _make_config(archive)

        mock_list.return_value = {"busybox": "c1", "base-files": "c2", "zlib": "c3"}
        mock_upload.return_value = UploadResult.failure_result(
            destination_name="sbomify",
            error_message="Duplicate",
            error_code="DUPLICATE_ARTIFACT",
        )

        with patch("sbomify_action._yocto.pipeline.get_or_create_component") as mock_goc:
            mock_goc.side_effect = lambda url, tok, name, cache: (cache.get(name, "x"), False)
            result = run_yocto_pipeline(config)

        assert result.sboms_skipped == 3
        assert result.sboms_uploaded == 0
        assert result.errors == 0

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    @patch("sbomify_action._yocto.pipeline.list_components")
    def test_plan_limit_stops_early(self, mock_list, mock_upload, tmp_path):
        archive = _make_tar_gz(tmp_path)
        config = _make_config(archive)

        mock_list.return_value = {}
        # First package succeeds, then plan limit hit on second
        call_count = {"n": 0}

        def goc_side_effect(url, tok, name, cache):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return ("comp-1", True)
            raise PlanLimitError("Maximum 200 components reached")

        mock_upload.return_value = UploadResult.success_result(destination_name="sbomify", sbom_id="sbom-001")

        with patch("sbomify_action._yocto.pipeline.get_or_create_component") as mock_goc:
            mock_goc.side_effect = goc_side_effect
            with patch("sbomify_action._yocto.pipeline.create_release") as mock_rel:
                mock_rel.return_value = "rel-1"
                with patch("sbomify_action._yocto.pipeline.tag_sbom_with_release"):
                    result = run_yocto_pipeline(config)

        assert result.errors == 1
        assert result.sboms_uploaded == 1
        # Should have stopped after 2nd package, not processed all 3
        assert mock_goc.call_count == 2


SPDX3_DATA = {
    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    "@graph": [
        {
            "type": "SpdxDocument",
            "spdxId": "urn:spdx:doc",
            "name": "test-image",
            "creationInfo": "urn:spdx:ci",
        },
        {
            "type": "CreationInfo",
            "spdxId": "urn:spdx:ci",
            "specVersion": "3.0.1",
        },
        {
            "type": "software_Package",
            "spdxId": "urn:spdx:pkg-busybox",
            "name": "busybox",
            "packageVersion": "1.36.1",
            "creationInfo": "urn:spdx:ci",
        },
        {
            "type": "software_Package",
            "spdxId": "urn:spdx:pkg-zlib",
            "name": "zlib",
            "packageVersion": "1.3.1",
            "creationInfo": "urn:spdx:ci",
        },
    ],
}


def _write_spdx3_file(tmp_path: Path) -> str:
    """Write a minimal SPDX 3 JSON-LD fixture and return the path."""
    path = tmp_path / "image.spdx.json"
    path.write_text(json.dumps(SPDX3_DATA))
    return str(path)


class TestSpdx3Pipeline:
    @patch("sbomify_action._yocto.pipeline.tag_sbom_with_release")
    @patch("sbomify_action._yocto.pipeline.create_release")
    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    def test_spdx3_single_file_pipeline(self, mock_upload, mock_create_release, mock_tag, tmp_path):
        spdx3_file = _write_spdx3_file(tmp_path)
        config = _make_config(spdx3_file, component_id="comp-abc")

        mock_upload.return_value = UploadResult.success_result(destination_name="sbomify", sbom_id="sbom-s3")
        mock_create_release.return_value = "release-s3"

        result = run_yocto_pipeline(config)

        assert result.packages_found == 2  # busybox + zlib
        assert result.sboms_uploaded == 1
        assert result.errors == 0
        assert result.release_id == "release-s3"
        mock_tag.assert_called_once_with(API_BASE, TOKEN, "sbom-s3", "release-s3")

    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    def test_spdx3_dry_run(self, mock_upload, tmp_path):
        spdx3_file = _write_spdx3_file(tmp_path)
        config = _make_config(spdx3_file, component_id="comp-abc", dry_run=True)

        result = run_yocto_pipeline(config)

        assert result.packages_found == 2
        assert result.sboms_uploaded == 0
        assert result.sboms_skipped == 1
        mock_upload.assert_not_called()

    def test_spdx3_missing_component_id(self, tmp_path):
        spdx3_file = _write_spdx3_file(tmp_path)
        config = _make_config(spdx3_file)  # no component_id

        with pytest.raises(ConfigurationError, match="--component-id"):
            run_yocto_pipeline(config)

    @patch("sbomify_action._yocto.pipeline.tag_sbom_with_release")
    @patch("sbomify_action._yocto.pipeline.create_release")
    @patch("sbomify_action._yocto.pipeline.upload_sbom")
    def test_spdx3_upload_success_with_release_tagging(self, mock_upload, mock_create_release, mock_tag, tmp_path):
        spdx3_file = _write_spdx3_file(tmp_path)
        config = _make_config(spdx3_file, component_id="comp-xyz")

        mock_upload.return_value = UploadResult.success_result(destination_name="sbomify", sbom_id="sbom-100")
        mock_create_release.return_value = "rel-200"

        result = run_yocto_pipeline(config)

        assert result.sboms_uploaded == 1
        assert result.release_id == "rel-200"
        mock_create_release.assert_called_once_with(API_BASE, TOKEN, "test-product", "1.0.0")
        mock_tag.assert_called_once_with(API_BASE, TOKEN, "sbom-100", "rel-200")


class TestYoctoPipelineResult:
    def test_has_errors(self):
        r = YoctoPipelineResult(errors=1)
        assert r.has_errors is True

    def test_no_errors(self):
        r = YoctoPipelineResult()
        assert r.has_errors is False
