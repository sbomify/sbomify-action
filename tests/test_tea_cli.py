"""Tests for the TEA CLI subcommand group."""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from libtea.exceptions import TeaError
from libtea.models import (
    Artifact,
    ArtifactFormat,
    ArtifactType,
    Checksum,
    ChecksumAlgorithm,
    Collection,
    CollectionBelongsTo,
    DiscoveryInfo,
    TeaServerInfo,
)

from sbomify_action.cli.main import cli
from sbomify_action.cli.tea import _select_best_format


def _mock_client_context(mock_build_client):
    """Set up mock_build_client as a context manager returning a MagicMock client."""
    mock_client = MagicMock()
    mock_build_client.return_value.__enter__ = MagicMock(return_value=mock_client)
    mock_build_client.return_value.__exit__ = MagicMock(return_value=False)
    return mock_client


def _make_collection(belongs_to, artifacts):
    """Create a Collection with defaults filled in."""
    return Collection(
        uuid="col-uuid",
        version=1,
        date=None,
        belongs_to=belongs_to,
        update_reason=None,
        artifacts=artifacts,
    )


def _make_bom_artifact(media_type="application/vnd.cyclonedx+json", url="https://cdn.example.com/sbom.json", **kwargs):
    """Create a BOM Artifact with a single format."""
    return Artifact(
        uuid="art-uuid",
        name="sbom",
        type=ArtifactType.BOM,
        distribution_types=None,
        formats=[ArtifactFormat(media_type=media_type, description=None, url=url, signature_url=None, **kwargs)],
    )


def _make_discovery(pr_uuid="pr-uuid-1"):
    """Create a DiscoveryInfo."""
    return DiscoveryInfo(
        product_release_uuid=pr_uuid,
        servers=[TeaServerInfo(root_url="https://tea.example.com/v1", versions=["0.3.0-beta.2"], priority=1.0)],
    )


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
        """tea fetch should fail with clear error if no identifier given."""
        result = self.runner.invoke(
            cli,
            ["tea", "fetch", "--base-url", "https://tea.example.com/v1", "-o", "sbom.json"],
        )
        assert result.exit_code != 0
        assert "--tei" in result.output or "Must specify" in result.output

    def test_fetch_rejects_multiple_identifiers(self):
        """tea fetch should reject multiple identifiers."""
        result = self.runner.invoke(
            cli,
            [
                "tea",
                "fetch",
                "--base-url",
                "https://tea.example.com/v1",
                "--tei",
                "urn:tei:test",
                "--product-release-uuid",
                "some-uuid",
                "-o",
                "sbom.json",
            ],
        )
        assert result.exit_code != 0
        assert "Only one" in result.output or result.exit_code == 1

    @patch("sbomify_action.cli.tea._build_client")
    def test_fetch_by_tei(self, mock_build_client):
        """tea fetch --tei should discover, find BOM, and download."""
        mock_client = _mock_client_context(mock_build_client)
        mock_client.discover.return_value = [_make_discovery()]
        mock_client.get_product_release_collection_latest.return_value = _make_collection(
            CollectionBelongsTo.PRODUCT_RELEASE, [_make_bom_artifact()]
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
        mock_client = _mock_client_context(mock_build_client)
        mock_client.discover.return_value = [_make_discovery()]

        vex_artifact = Artifact(
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
        mock_client.get_product_release_collection_latest.return_value = _make_collection(
            CollectionBelongsTo.PRODUCT_RELEASE, [vex_artifact]
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
        mock_client = _mock_client_context(mock_build_client)

        checksums = (Checksum(algorithm_type=ChecksumAlgorithm.SHA_256, algorithm_value="abc123"),)
        mock_client.get_component_release_collection_latest.return_value = _make_collection(
            CollectionBelongsTo.COMPONENT_RELEASE, [_make_bom_artifact(checksums=checksums)]
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

    @patch("sbomify_action.cli.tea._build_client")
    def test_fetch_tea_error(self, mock_build_client):
        """tea fetch should handle TeaError gracefully."""
        mock_client = _mock_client_context(mock_build_client)
        mock_client.discover.side_effect = TeaError("Server error")

        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                cli,
                [
                    "tea",
                    "fetch",
                    "--base-url",
                    "https://tea.example.com/v1",
                    "--tei",
                    "urn:tei:test",
                    "-o",
                    "sbom.json",
                ],
            )
            assert result.exit_code != 0

    @patch("sbomify_action.cli.tea._build_client")
    def test_fetch_io_error(self, mock_build_client):
        """tea fetch should handle OSError gracefully."""
        mock_client = _mock_client_context(mock_build_client)
        mock_client.discover.return_value = [_make_discovery()]
        mock_client.get_product_release_collection_latest.return_value = _make_collection(
            CollectionBelongsTo.PRODUCT_RELEASE, [_make_bom_artifact()]
        )
        mock_client.download_artifact.side_effect = OSError("Disk full")

        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                cli,
                [
                    "tea",
                    "fetch",
                    "--base-url",
                    "https://tea.example.com/v1",
                    "--tei",
                    "urn:tei:test",
                    "-o",
                    "sbom.json",
                ],
            )
            assert result.exit_code != 0


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
