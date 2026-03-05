"""Tests for the TEA CLI subcommand group."""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from sbomify_action.cli.main import cli
from sbomify_action.cli.tea import _select_best_format


class TestTeaGroup(unittest.TestCase):
    """Test that the tea subcommand group is registered."""

    def setUp(self):
        self.runner = CliRunner()

    def test_tea_help(self):
        """tea --help should show the TEA CLI help text."""
        result = self.runner.invoke(cli, ["tea", "--help"])
        assert result.exit_code == 0
        assert "TEA" in result.output or "tea" in result.output.lower()

    def test_tea_discover_help(self):
        """tea discover --help should show discover subcommand help."""
        result = self.runner.invoke(cli, ["tea", "discover", "--help"])
        assert result.exit_code == 0
        assert "TEI" in result.output or "tei" in result.output.lower()

    def test_tea_conformance_help(self):
        """tea conformance --help should show conformance subcommand help."""
        result = self.runner.invoke(cli, ["tea", "conformance", "--help"])
        assert result.exit_code == 0
        assert "conformance" in result.output.lower()

    def test_tea_search_products_help(self):
        """tea search-products --help should be available."""
        result = self.runner.invoke(cli, ["tea", "search-products", "--help"])
        assert result.exit_code == 0

    def test_tea_inspect_help(self):
        """tea inspect --help should be available."""
        result = self.runner.invoke(cli, ["tea", "inspect", "--help"])
        assert result.exit_code == 0

    def test_tea_download_help(self):
        """tea download --help should be available."""
        result = self.runner.invoke(cli, ["tea", "download", "--help"])
        assert result.exit_code == 0


class TestTeaFetch(unittest.TestCase):
    """Test the custom fetch convenience command."""

    def setUp(self):
        self.runner = CliRunner()

    def test_fetch_help(self):
        """tea fetch --help should show fetch subcommand help."""
        result = self.runner.invoke(cli, ["tea", "fetch", "--help"])
        assert result.exit_code == 0
        assert "fetch" in result.output.lower() or "SBOM" in result.output

    def test_fetch_requires_identifier(self):
        """tea fetch should fail if no --tei or --product-release-uuid given."""
        result = self.runner.invoke(
            cli,
            ["tea", "fetch", "--base-url", "https://tea.example.com/v1", "-o", "sbom.json"],
        )
        assert result.exit_code != 0

    @patch("sbomify_action.cli.tea._build_client")
    def test_fetch_by_tei(self, mock_build_client):
        """tea fetch --tei should discover, find BOM, and download."""
        from libtea.models import (
            Artifact,
            ArtifactFormat,
            ArtifactType,
            Collection,
            CollectionBelongsTo,
            DiscoveryInfo,
            TeaServerInfo,
        )

        mock_client = MagicMock()
        mock_build_client.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_build_client.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.discover.return_value = [
            DiscoveryInfo(
                product_release_uuid="pr-uuid-1",
                servers=[TeaServerInfo(root_url="https://tea.example.com/v1", versions=["0.3.0-beta.2"], priority=1.0)],
            )
        ]
        mock_client.get_product_release_collection_latest.return_value = Collection(
            uuid="col-uuid",
            version=1,
            date=None,
            belongs_to=CollectionBelongsTo.PRODUCT_RELEASE,
            update_reason=None,
            artifacts=[
                Artifact(
                    uuid="art-uuid",
                    name="sbom",
                    type=ArtifactType.BOM,
                    distribution_types=None,
                    formats=[
                        ArtifactFormat(
                            media_type="application/vnd.cyclonedx+json",
                            description=None,
                            url="https://cdn.example.com/sbom.json",
                            signature_url=None,
                        )
                    ],
                )
            ],
        )
        mock_client.download_artifact.return_value = "/tmp/sbom.json"

        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                cli,
                [
                    "tea",
                    "fetch",
                    "--base-url",
                    "https://tea.example.com/v1",
                    "--tei",
                    "urn:tei:purl:example.com:pkg:pypi/lib@1.0",
                    "-o",
                    "sbom.json",
                ],
            )
            assert result.exit_code == 0, f"Failed with: {result.output}"
            mock_client.discover.assert_called_once()
            mock_client.download_artifact.assert_called_once()

    @patch("sbomify_action.cli.tea._build_client")
    def test_fetch_no_bom_artifact(self, mock_build_client):
        """tea fetch should error when no BOM artifact found."""
        from libtea.models import (
            Artifact,
            ArtifactFormat,
            ArtifactType,
            Collection,
            CollectionBelongsTo,
            DiscoveryInfo,
            TeaServerInfo,
        )

        mock_client = MagicMock()
        mock_build_client.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_build_client.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.discover.return_value = [
            DiscoveryInfo(
                product_release_uuid="pr-uuid-1",
                servers=[TeaServerInfo(root_url="https://tea.example.com/v1", versions=["0.3.0-beta.2"], priority=1.0)],
            )
        ]
        mock_client.get_product_release_collection_latest.return_value = Collection(
            uuid="col-uuid",
            version=1,
            date=None,
            belongs_to=CollectionBelongsTo.PRODUCT_RELEASE,
            update_reason=None,
            artifacts=[
                Artifact(
                    uuid="art-uuid",
                    name="vex",
                    type=ArtifactType.VULNERABILITIES,
                    distribution_types=None,
                    formats=[
                        ArtifactFormat(
                            media_type="application/json",
                            description=None,
                            url="https://cdn.example.com/vex.json",
                            signature_url=None,
                        )
                    ],
                )
            ],
        )

        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                cli,
                [
                    "tea",
                    "fetch",
                    "--base-url",
                    "https://tea.example.com/v1",
                    "--tei",
                    "urn:tei:purl:example.com:pkg:pypi/lib@1.0",
                    "-o",
                    "sbom.json",
                ],
            )
            assert result.exit_code != 0

    @patch("sbomify_action.cli.tea._build_client")
    def test_fetch_by_component_release_uuid(self, mock_build_client):
        """tea fetch --component-release-uuid should fetch without discovery."""
        from libtea.models import (
            Artifact,
            ArtifactFormat,
            ArtifactType,
            Checksum,
            ChecksumAlgorithm,
            Collection,
            CollectionBelongsTo,
        )

        mock_client = MagicMock()
        mock_build_client.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_build_client.return_value.__exit__ = MagicMock(return_value=False)

        checksums = (Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value="abc123"),)
        mock_client.get_component_release_collection_latest.return_value = Collection(
            uuid="col-uuid",
            version=1,
            date=None,
            belongs_to=CollectionBelongsTo.COMPONENT_RELEASE,
            update_reason=None,
            artifacts=[
                Artifact(
                    uuid="art-uuid",
                    name="sbom",
                    type=ArtifactType.BOM,
                    distribution_types=None,
                    formats=[
                        ArtifactFormat(
                            media_type="application/vnd.cyclonedx+json",
                            description=None,
                            url="https://cdn.example.com/sbom.json",
                            signature_url=None,
                            checksums=checksums,
                        )
                    ],
                )
            ],
        )
        mock_client.download_artifact.return_value = Path("/tmp/sbom.json")

        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                cli,
                [
                    "tea",
                    "fetch",
                    "--base-url",
                    "https://tea.example.com/v1",
                    "--component-release-uuid",
                    "cr-uuid-1",
                    "-o",
                    "sbom.json",
                ],
            )
            assert result.exit_code == 0, f"Failed with: {result.output}"
            mock_client.discover.assert_not_called()
            mock_client.get_component_release_collection_latest.assert_called_once_with("cr-uuid-1")
            mock_client.download_artifact.assert_called_once()
            # Verify checksums were passed through
            call_kwargs = mock_client.download_artifact.call_args
            assert call_kwargs.kwargs.get("verify_checksums") == checksums


class TestSelectBestFormat(unittest.TestCase):
    """Test the _select_best_format helper."""

    def _make_fmt(self, media_type=None, url=None):
        return MagicMock(media_type=media_type, url=url)

    def test_prefers_cyclonedx(self):
        spdx = self._make_fmt("application/spdx+json", "https://a.com/spdx.json")
        cdx = self._make_fmt("application/vnd.cyclonedx+json", "https://a.com/cdx.json")
        assert _select_best_format([spdx, cdx]) is cdx

    def test_prefers_spdx_over_generic(self):
        generic = self._make_fmt("application/json", "https://a.com/generic.json")
        spdx = self._make_fmt("application/spdx+json", "https://a.com/spdx.json")
        assert _select_best_format([generic, spdx]) is spdx

    def test_falls_back_to_url(self):
        unknown = self._make_fmt("application/xml", "https://a.com/sbom.xml")
        assert _select_best_format([unknown]) is unknown

    def test_skips_format_without_url(self):
        no_url = self._make_fmt("application/xml", None)
        with_url = self._make_fmt("text/plain", "https://a.com/file")
        assert _select_best_format([no_url, with_url]) is with_url

    def test_returns_none_for_empty(self):
        assert _select_best_format([]) is None

    def test_returns_none_when_no_url(self):
        no_url = self._make_fmt("application/xml", None)
        assert _select_best_format([no_url]) is None
