"""Tests for the TEA CLI subcommand group."""

import unittest
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from sbomify_action.cli.main import cli


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
