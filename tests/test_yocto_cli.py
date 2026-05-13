"""Tests for the Yocto CLI command."""

import json
import tarfile
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from sbomify_action._yocto.models import YoctoPipelineResult
from sbomify_action.cli.main import cli

YOCTO_TEST_DATA = Path(__file__).parent / "test-data" / "yocto"


def _make_tar_gz(tmp_path: Path) -> str:
    """Create a tar.gz from test fixtures."""
    archive_path = str(tmp_path / "test.spdx.tar.gz")
    with tarfile.open(archive_path, "w:gz") as tar:
        for f in YOCTO_TEST_DATA.glob("*.spdx.json"):
            tar.add(str(f), arcname=f.name)
    return archive_path


class TestYoctoCli:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["yocto", "--help"])
        assert result.exit_code == 0
        assert "Yocto/OpenEmbedded" in result.output
        assert "--release" in result.output
        assert "--dry-run" in result.output

    def test_missing_release(self, tmp_path):
        archive = _make_tar_gz(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["--token", "t", "yocto", archive])
        assert result.exit_code != 0
        assert "Missing option '--release'" in result.output or "required" in result.output.lower()

    def test_missing_token(self, tmp_path, monkeypatch):
        # Clear both env vars so the fallback chain truly has no token to find.
        monkeypatch.delenv("TOKEN", raising=False)
        monkeypatch.delenv("SBOMIFY_TOKEN", raising=False)
        archive = _make_tar_gz(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["yocto", archive, "--release", "prod:1.0"])
        assert result.exit_code != 0

    @patch("sbomify_action._yocto.pipeline.run_yocto_pipeline")
    def test_sbomify_token_env_var_accepted(self, mock_pipeline, tmp_path, monkeypatch):
        # yocto should pick up $SBOMIFY_TOKEN (in addition to $TOKEN), matching
        # the wizard's env-var precedence via the shared _resolve_token helper.
        monkeypatch.delenv("TOKEN", raising=False)
        monkeypatch.setenv("SBOMIFY_TOKEN", "from-sbomify-env")
        archive = _make_tar_gz(tmp_path)
        mock_pipeline.return_value = YoctoPipelineResult()

        runner = CliRunner()
        result = runner.invoke(cli, ["yocto", archive, "--release", "prod:1.0"])
        assert result.exit_code == 0
        config = mock_pipeline.call_args[0][0]
        assert config.token == "from-sbomify-env"

    def test_invalid_release_format(self, tmp_path):
        archive = _make_tar_gz(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["--token", "t", "yocto", archive, "--release", "no-colon"])
        assert result.exit_code != 0
        assert "product_id:version" in result.output

    def test_empty_product_id(self, tmp_path):
        archive = _make_tar_gz(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["--token", "t", "yocto", archive, "--release", ":1.0"])
        assert result.exit_code != 0
        assert "non-empty" in result.output

    def test_empty_version(self, tmp_path):
        archive = _make_tar_gz(tmp_path)
        runner = CliRunner()
        result = runner.invoke(cli, ["--token", "t", "yocto", archive, "--release", "prod:"])
        assert result.exit_code != 0
        assert "non-empty" in result.output

    @patch("sbomify_action._yocto.pipeline.run_yocto_pipeline")
    def test_dry_run(self, mock_pipeline, tmp_path):
        archive = _make_tar_gz(tmp_path)
        mock_pipeline.return_value = YoctoPipelineResult(packages_found=3, sboms_skipped=3)

        runner = CliRunner()
        result = runner.invoke(cli, ["--token", "t", "yocto", archive, "--release", "prod:1.0", "--dry-run"])
        assert result.exit_code == 0
        mock_pipeline.assert_called_once()

        config = mock_pipeline.call_args[0][0]
        assert config.dry_run is True
        assert config.product_id == "prod"
        assert config.release_version == "1.0"

    @patch("sbomify_action._yocto.pipeline.run_yocto_pipeline")
    def test_exit_code_1_on_errors(self, mock_pipeline, tmp_path):
        archive = _make_tar_gz(tmp_path)
        mock_pipeline.return_value = YoctoPipelineResult(errors=1)

        runner = CliRunner()
        result = runner.invoke(cli, ["--token", "t", "yocto", archive, "--release", "prod:1.0"])
        assert result.exit_code == 1

    @patch("sbomify_action._yocto.pipeline.run_yocto_pipeline")
    def test_augment_enrich_flags(self, mock_pipeline, tmp_path):
        archive = _make_tar_gz(tmp_path)
        mock_pipeline.return_value = YoctoPipelineResult()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["--token", "t", "yocto", archive, "--release", "prod:1.0", "--augment", "--enrich"],
        )
        assert result.exit_code == 0

        config = mock_pipeline.call_args[0][0]
        assert config.augment is True
        assert config.enrich is True

    @patch("sbomify_action._yocto.pipeline.run_yocto_pipeline")
    def test_api_base_url(self, mock_pipeline, tmp_path):
        archive = _make_tar_gz(tmp_path)
        mock_pipeline.return_value = YoctoPipelineResult()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "--token",
                "t",
                "--api-base-url",
                "https://custom.example.com/",
                "yocto",
                archive,
                "--release",
                "prod:1.0",
            ],
        )
        assert result.exit_code == 0
        config = mock_pipeline.call_args[0][0]
        assert config.api_base_url == "https://custom.example.com"  # trailing slash stripped

    def test_nonexistent_archive(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["yocto", "/nonexistent/path.tar.zst", "--token", "t", "--release", "prod:1.0"])
        assert result.exit_code != 0

    @patch("sbomify_action._yocto.pipeline.run_yocto_pipeline")
    def test_spdx3_with_component_id(self, mock_pipeline, tmp_path):
        spdx3_file = tmp_path / "image.spdx.json"
        spdx3_file.write_text(
            json.dumps(
                {
                    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                    "@graph": [{"type": "software_Package", "spdxId": "urn:pkg", "name": "test"}],
                }
            )
        )
        mock_pipeline.return_value = YoctoPipelineResult(packages_found=1, sboms_uploaded=1)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "--token",
                "t",
                "yocto",
                str(spdx3_file),
                "--release",
                "prod:1.0",
                "--component-id",
                "comp-abc",
            ],
        )
        assert result.exit_code == 0
        mock_pipeline.assert_called_once()

        config = mock_pipeline.call_args[0][0]
        assert config.component_id == "comp-abc"
        assert config.input_path == str(spdx3_file)

    @patch("sbomify_action._yocto.pipeline.run_yocto_pipeline")
    def test_spdx3_without_component_id(self, mock_pipeline, tmp_path):
        """SPDX 3 without --component-id should fail in the pipeline (ConfigurationError)."""
        spdx3_file = tmp_path / "image.spdx.json"
        spdx3_file.write_text(
            json.dumps(
                {
                    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                    "@graph": [{"type": "software_Package", "spdxId": "urn:pkg", "name": "test"}],
                }
            )
        )
        mock_pipeline.return_value = YoctoPipelineResult()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["--token", "t", "yocto", str(spdx3_file), "--release", "prod:1.0"],
        )
        # CLI itself accepts it (component_id=None), pipeline validates
        assert result.exit_code == 0
        config = mock_pipeline.call_args[0][0]
        assert config.component_id is None
