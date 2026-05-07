"""Integration tests for the sbomify wizard CLI surface."""

import json

from click.testing import CliRunner

from sbomify_action.cli.main import cli


class TestInitCommand:
    """`init` is a thin alias for `wizard`."""

    def test_init_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--help"])
        assert result.exit_code == 0
        assert "alias" in result.output.lower()
        assert "wizard" in result.output.lower()

    def test_init_shares_wizard_options(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--help"])
        for opt in ("--token", "--api-base-url", "--repo-root", "--output-dir", "--dry-run"):
            assert opt in result.output


class TestWizardCommand:
    def test_wizard_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["wizard", "--help"])
        assert result.exit_code == 0
        for opt in ("--token", "--api-base-url", "--repo-root", "--output-dir", "--dry-run"):
            assert opt in result.output


class TestWriteConfig:
    """write_config is the shared filesystem helper used by apply_plan."""

    def test_write_config(self, tmp_path):
        from sbomify_action.cli.wizard.io import write_config

        config = {"lifecycle_phase": "build"}
        config_path = tmp_path / "sbomify.json"

        assert write_config(config, config_path, backup=False) is True
        assert json.loads(config_path.read_text()) == config

    def test_write_config_creates_backup(self, tmp_path):
        from sbomify_action.cli.wizard.io import write_config

        config_path = tmp_path / "sbomify.json"
        original = {"original": True}
        config_path.write_text(json.dumps(original))

        new_config = {"new": True}
        assert write_config(new_config, config_path, backup=True) is True

        backup_path = tmp_path / "sbomify.json.bak"
        assert backup_path.exists()
        assert json.loads(backup_path.read_text()) == original
        assert json.loads(config_path.read_text()) == new_config
