"""Tests for the TEA CLI subcommand group."""

import unittest

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
