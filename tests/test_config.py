import os
import tempfile
import unittest
from importlib import import_module
from pathlib import Path
from unittest.mock import patch

from sbomify_action.cli.main import (
    SBOMIFY_PRODUCTION_API,
    Config,
    load_config,
)
from sbomify_action.exceptions import ConfigurationError

# Import the module using importlib to avoid shadowing by __init__.py exports
cli_main_module = import_module("sbomify_action.cli.main")


class TestConfig(unittest.TestCase):
    """Test cases for the Config dataclass and related functionality."""

    @patch("sbomify_action.oidc.is_github_oidc_available", return_value=False)
    def test_config_validation_missing_token(self, _mock_oidc):
        """Test that Config raises ConfigurationError when token is missing and UPLOAD=true."""
        config = Config(token="", component_id="test-component", sbom_file="/path/to/sbom.json", upload=True)

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("sbomify API token is not defined", str(cm.exception))

    def test_config_validation_missing_component_id(self):
        """Test that Config raises ConfigurationError when component_id is missing and UPLOAD=true."""
        config = Config(token="test-token", component_id="", sbom_file="/path/to/sbom.json", upload=True)

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("Component ID is not defined", str(cm.exception))

    def test_config_validation_multiple_inputs(self):
        """Test that Config raises ConfigurationError when multiple input types are provided."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            lock_file="/path/to/requirements.txt",
        )

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("Please provide only one of", str(cm.exception))

    def test_config_validation_no_inputs(self):
        """Test that Config raises ConfigurationError when no inputs are provided."""
        config = Config(token="test-token", component_id="test-component")

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("Please provide one of", str(cm.exception))

    def test_bom_type_non_sbom_rejects_generation(self):
        """A non-SBOM BOM_TYPE with a generation source is rejected (it would generate an SBOM and
        upload it mislabeled)."""
        config = Config(
            token="test-token",
            component_id="test-component",
            bom_type="vex",
            lock_file="/path/to/requirements.txt",
        )
        with self.assertRaises(ConfigurationError) as cm:
            config.validate()
        self.assertIn("cannot be", str(cm.exception))

    def test_bom_type_non_sbom_rejects_docker_generation(self):
        """A non-SBOM BOM_TYPE with a docker image (generation) is rejected."""
        config = Config(
            token="test-token",
            component_id="test-component",
            bom_type="hbom",
            docker_image="alpine:latest",
        )
        with self.assertRaises(ConfigurationError) as cm:
            config.validate()
        self.assertIn("verbatim", str(cm.exception))

    def test_bom_type_non_sbom_clears_component_overrides(self):
        """Non-SBOM BOM_TYPE ignores document-rewriting override inputs (verbatim contract)."""
        config = Config(
            token="test-token",
            component_id="test-component",
            bom_type="vex",
            sbom_file="/path/to/authored.vex.cdx.json",
            component_name="renamed",
            component_version="9.9.9",
            component_purl="pkg:npm/renamed@9.9.9",
            override_name=True,
        )
        config.validate()
        self.assertIsNone(config.component_name)
        self.assertIsNone(config.component_version)
        self.assertIsNone(config.component_purl)
        self.assertFalse(config.override_name)

    def test_bom_type_non_sbom_with_real_file_ok(self):
        """A non-SBOM BOM_TYPE with a real SBOM_FILE (pre-authored artifact) validates."""
        config = Config(
            token="test-token",
            component_id="test-component",
            bom_type="vex",
            sbom_file="/path/to/authored.vex.cdx.json",
            upload=True,
        )
        config.validate()  # no error

    def test_bom_type_non_sbom_rejects_spdx_format(self):
        """A non-SBOM BOM_TYPE with SPDX is rejected: SPDX sanitization would rewrite the bytes."""
        config = Config(
            token="test-token",
            component_id="test-component",
            bom_type="vex",
            sbom_file="/path/to/authored.vex.cdx.json",
            sbom_format="spdx",
            upload=True,
        )
        with self.assertRaises(ConfigurationError) as cm:
            config.validate()
        self.assertIn("CycloneDX", str(cm.exception))

    def test_bom_type_non_sbom_rejects_non_sbomify_destinations(self):
        """Non-SBOM artifacts are only recorded by the sbomify backend; other
        destinations re-encode the payload and treat it as a plain SBOM."""
        config = Config(
            token="test-token",
            component_id="test-component",
            bom_type="vex",
            sbom_file="/path/to/authored.vex.cdx.json",
            upload=True,
            upload_destinations=["sbomify", "dependency-track"],
        )
        with self.assertRaises(ConfigurationError) as cm:
            config.validate()
        self.assertIn("dependency-track", str(cm.exception))

    def test_bom_type_non_sbom_rejects_product_release(self):
        """Releases hold one SBOM per component and format; tagging a VEX/CBOM
        into a release either collides with the component's SBOM or occupies
        its slot, so PRODUCT_RELEASE is rejected for non-SBOM artifacts."""
        config = Config(
            token="test-token",
            component_id="test-component",
            bom_type="vex",
            sbom_file="/path/to/authored.vex.cdx.json",
            product_releases='["myproduct:v1.0.0"]',
        )
        with self.assertRaises(ConfigurationError) as cm:
            config.validate()
        self.assertIn("PRODUCT_RELEASE", str(cm.exception))

    def test_bom_type_non_sbom_no_upload_allows_other_destinations(self):
        """With UPLOAD=false nothing is sent anywhere, so configured
        destinations are irrelevant and must not fail validation."""
        config = Config(
            token="test-token",
            component_id="test-component",
            bom_type="vex",
            sbom_file="/path/to/authored.vex.cdx.json",
            upload=False,
            upload_destinations=["sbomify", "dependency-track"],
        )
        config.validate()  # no error

    def test_config_validation_valid_config(self):
        """Test that Config validation passes with valid configuration."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
        )

        # Should not raise any exception
        config.validate()

    def test_config_validation_standalone_mode_no_token_required(self):
        """Test that TOKEN is not required in standalone mode (UPLOAD=false, AUGMENT=false, no PRODUCT_RELEASE)."""
        config = Config(
            token="",
            component_id="",
            sbom_file="/path/to/sbom.json",
            upload=False,
            augment=False,
        )

        # Should not raise any exception
        config.validate()

    def test_config_validation_dtrack_only_no_sbomify_credentials(self):
        """Test that sbomify TOKEN/COMPONENT_ID not required when uploading only to dependency-track."""
        config = Config(
            token="",
            component_id="",
            sbom_file="/path/to/sbom.json",
            upload=True,
            upload_destinations=["dependency-track"],
            augment=False,
        )

        # Should not raise any exception - sbomify credentials not required
        config.validate()

    @patch("sbomify_action.oidc.is_github_oidc_available", return_value=False)
    def test_config_validation_multi_destination_requires_sbomify_credentials(self, _mock_oidc):
        """Test that sbomify credentials ARE required when sbomify is one of multiple destinations."""
        config = Config(
            token="",
            component_id="",
            sbom_file="/path/to/sbom.json",
            upload=True,
            upload_destinations=["sbomify", "dependency-track"],
            augment=False,
        )

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("sbomify API token is not defined", str(cm.exception))
        self.assertIn("uploading to sbomify", str(cm.exception))

    @patch("sbomify_action.oidc.is_github_oidc_available", return_value=False)
    def test_config_validation_upload_requires_token(self, _mock_oidc):
        """Test that TOKEN is required when uploading to sbomify."""
        config = Config(
            token="",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            upload=True,
            upload_destinations=["sbomify"],
        )

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("sbomify API token is not defined", str(cm.exception))
        self.assertIn("uploading to sbomify", str(cm.exception))

    def test_config_validation_augment_does_not_require_token(self):
        """Test that AUGMENT=true works without TOKEN when not uploading to sbomify."""
        config = Config(
            token="",
            component_id="",
            sbom_file="/path/to/sbom.json",
            upload=False,
            augment=True,
        )
        # Should not raise - augmentation can use sbomify.json without API credentials
        config.validate()

    @patch("sbomify_action.oidc.is_github_oidc_available", return_value=False)
    def test_config_validation_product_release_requires_token(self, _mock_oidc):
        """Test that TOKEN is required when PRODUCT_RELEASE is set even if UPLOAD=false."""
        config = Config(
            token="",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            upload=False,
            augment=False,
            product_releases='["product_id:v1.0.0"]',
        )

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("sbomify API token is not defined", str(cm.exception))
        self.assertIn("PRODUCT_RELEASE is set", str(cm.exception))

    @patch("sbomify_action.oidc.is_github_oidc_available", return_value=True)
    def test_config_validation_oidc_available_no_token_required(self, _mock_oidc):
        """When GitHub OIDC is available, validate() should NOT raise for missing TOKEN."""
        config = Config(
            token="",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            upload=True,
            upload_destinations=["sbomify"],
        )
        # Should not raise — pipeline will perform OIDC exchange at runtime
        config.validate()

    @patch("sbomify_action.oidc.is_github_oidc_available", return_value=True)
    def test_config_validation_oidc_available_still_requires_component_id(self, _mock_oidc):
        """OIDC bypasses the TOKEN requirement but COMPONENT_ID is still required."""
        config = Config(
            token="",
            component_id="",
            sbom_file="/path/to/sbom.json",
            upload=True,
            upload_destinations=["sbomify"],
        )
        with self.assertRaises(ConfigurationError) as cm:
            config.validate()
        self.assertIn("Component ID is not defined", str(cm.exception))

    def test_will_use_sbomify_api_includes_augment(self):
        """AUGMENT alone (no upload, no PR) marks the run as 'may use sbomify API'."""
        config = Config(
            token="",
            component_id="comp-1",
            sbom_file="/path/to/sbom.json",
            upload=False,
            augment=True,
        )
        # validate() doesn't require credentials here (augment can fall back to
        # sbomify.json) — but will_use_sbomify_api is True so run_pipeline knows
        # to attempt OIDC exchange if available.
        self.assertFalse(config.requires_sbomify_api)
        self.assertTrue(config.will_use_sbomify_api)

    def test_will_use_sbomify_api_equals_requires_when_uploading(self):
        config = Config(
            token="t",
            component_id="c",
            sbom_file="/path/to/sbom.json",
            upload=True,
            upload_destinations=["sbomify"],
        )
        self.assertTrue(config.requires_sbomify_api)
        self.assertTrue(config.will_use_sbomify_api)

    def test_will_use_sbomify_api_false_when_no_sbomify_involvement(self):
        config = Config(
            token="",
            component_id="",
            sbom_file="/path/to/sbom.json",
            upload=False,
            augment=False,
        )
        self.assertFalse(config.requires_sbomify_api)
        self.assertFalse(config.will_use_sbomify_api)

    def test_config_token_excluded_from_repr(self):
        """field(repr=False) keeps the token out of repr(config) so accidental
        logging or pytest diffs don't leak the short-lived OIDC-minted JWT."""
        config = Config(token="super-secret-jwt-value", component_id="c", sbom_file="x")
        self.assertNotIn("super-secret-jwt-value", repr(config))

    def test_config_validation_upload_requires_component_id(self):
        """Test that COMPONENT_ID is required when uploading to sbomify."""
        config = Config(
            token="test-token",
            component_id="",
            sbom_file="/path/to/sbom.json",
            upload=True,
            upload_destinations=["sbomify"],
        )

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("Component ID is not defined", str(cm.exception))
        self.assertIn("uploading to sbomify", str(cm.exception))

    def test_config_url_validation_invalid_scheme(self):
        """Test that Config raises ConfigurationError for invalid URL schemes."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            api_base_url="ftp://invalid.com",
        )

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("API base URL must start with http:// or https://", str(cm.exception))

    def test_config_url_validation_missing_hostname(self):
        """Test that Config raises ConfigurationError for URLs without hostname."""
        config = Config(
            token="test-token", component_id="test-component", sbom_file="/path/to/sbom.json", api_base_url="https://"
        )

        with self.assertRaises(ConfigurationError) as cm:
            config.validate()

        self.assertIn("API base URL must include a valid hostname", str(cm.exception))

    @patch.object(cli_main_module, "logger")
    def test_config_url_validation_http_warning(self, mock_logger):
        """Test that Config issues warning for HTTP on non-localhost."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            api_base_url="http://example.com/api",
        )

        config.validate()
        mock_logger.warning.assert_called_with(
            "Using HTTP (not HTTPS) for API communication - consider using HTTPS in production"
        )

    @patch.object(cli_main_module, "logger")
    def test_config_url_validation_http_localhost_no_warning(self, mock_logger):
        """Test that Config does not warn for HTTP on localhost."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            api_base_url="http://127.0.0.1:8000/api",
        )

        config.validate()
        mock_logger.warning.assert_not_called()

    def test_config_url_trailing_slash_removal(self):
        """Test that trailing slashes are removed from URLs."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            api_base_url="https://api.example.com/",
        )

        config.validate()
        self.assertEqual(config.api_base_url, "https://api.example.com")

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "UPLOAD": "False",
            "AUGMENT": "True",
            "PRODUCT_RELEASE": '["Gu9wem8mkX:v1.0.0", "GFcFpn8q4h:v2.1.0"]',
        },
    )
    def test_load_config_from_environment(self):
        """Test loading configuration from environment variables."""
        config = load_config()

        self.assertEqual(config.token, "test-token")
        self.assertEqual(config.component_id, "test-component")
        self.assertFalse(config.upload)
        self.assertTrue(config.augment)

    @patch("sbomify_action.oidc.is_github_oidc_available", return_value=False)
    @patch.dict(os.environ, {"TOKEN": "", "COMPONENT_ID": "test"})
    @patch("sys.exit")
    def test_load_config_exits_on_invalid_config(self, mock_exit, _mock_oidc):
        """Test that load_config exits when configuration is invalid.

        is_github_oidc_available is patched to False so the test is
        deterministic when run under CI workflows that grant id-token: write.
        """
        load_config()
        mock_exit.assert_called_once_with(1)

    def test_load_config_uses_production_api_default(self):
        """Test that load_config uses production API as default."""
        with patch.dict(
            os.environ,
            {"TOKEN": "test-token", "COMPONENT_ID": "test-component", "SBOM_FILE": "tests/test-data/valid_json.json"},
            clear=True,
        ):
            config = load_config()
            self.assertEqual(config.api_base_url, SBOMIFY_PRODUCTION_API)

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "PRODUCT_RELEASE": '["Gu9wem8mkX:v1.0.0", "GFcFpn8q4h:v2.1.0"]',
        },
    )
    def test_load_config_with_product_releases(self):
        """Test loading configuration with valid product releases."""
        config = load_config()

        # After validation, should be converted to a list
        self.assertEqual(config.product_releases, ["Gu9wem8mkX:v1.0.0", "GFcFpn8q4h:v2.1.0"])

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "PRODUCT_RELEASE": '["Gu9wem8mkX:v1.0.0"]',
        },
    )
    def test_load_config_with_single_product_release(self):
        """Test loading configuration with single product release."""
        config = load_config()

        # After validation, should be converted to a list
        self.assertEqual(config.product_releases, ["Gu9wem8mkX:v1.0.0"])

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "PRODUCT_RELEASE": "not-json",
        },
    )
    @patch("sys.exit")
    def test_load_config_invalid_product_release_json(self, mock_exit):
        """Test that invalid JSON for PRODUCT_RELEASE causes exit."""
        load_config()
        mock_exit.assert_called_once_with(1)

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "PRODUCT_RELEASE": '"not-a-list"',
        },
    )
    @patch("sys.exit")
    def test_load_config_product_release_not_list(self, mock_exit):
        """Test that non-list PRODUCT_RELEASE causes exit."""
        load_config()
        mock_exit.assert_called_once_with(1)

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "PRODUCT_RELEASE": '["invalid-format"]',
        },
    )
    @patch("sys.exit")
    def test_load_config_invalid_product_release_format(self, mock_exit):
        """Test that invalid format in PRODUCT_RELEASE causes exit."""
        load_config()
        mock_exit.assert_called_once_with(1)

    @patch.dict(
        os.environ,
        {
            "TOKEN": "test-token",
            "COMPONENT_ID": "test-component",
            "SBOM_FILE": "tests/test-data/valid_json.json",
            "PRODUCT_RELEASE": '["ab:v1.0.0"]',
        },
    )
    def test_load_config_short_product_id_allowed(self):
        """Test that short product IDs are now allowed."""
        config = load_config()
        # Should pass validation and be converted to list
        self.assertEqual(config.product_releases, ["ab:v1.0.0"])

    def test_component_name_no_warning(self):
        """Test that using COMPONENT_NAME alone produces no deprecation warnings."""
        # Create a dummy lock file for validation
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "test.lock"
            lock_file.write_text("dummy content")

            # Mock environment variables with only COMPONENT_NAME
            env_vars = {
                "TOKEN": "test-token",
                "COMPONENT_ID": "test-component",
                "COMPONENT_NAME": "my-custom-component",
                "LOCK_FILE": str(lock_file),
            }
            with patch.dict(os.environ, env_vars, clear=False):
                # Clear any existing env var
                for key in ["OVERRIDE_NAME"]:
                    if key in os.environ:
                        del os.environ[key]

                # Load config
                config = load_config()

                # Should use COMPONENT_NAME value
                self.assertEqual(config.component_name, "my-custom-component")
                self.assertFalse(config.override_name)

    def test_override_name_deprecated_warning(self):
        """Test that OVERRIDE_NAME shows deprecation warning."""
        with self.assertLogs("sbomify_action", level="WARNING") as log:
            # Create a dummy lock file for validation
            with tempfile.TemporaryDirectory() as tmp_dir:
                lock_file = Path(tmp_dir) / "test.lock"
                lock_file.write_text("dummy content")

                # Mock environment variables with only deprecated OVERRIDE_NAME
                env_vars = {
                    "TOKEN": "test-token",
                    "COMPONENT_ID": "test-component",
                    "OVERRIDE_NAME": "true",
                    "LOCK_FILE": str(lock_file),
                }
                with patch.dict(os.environ, env_vars, clear=False):
                    # Clear any existing env var
                    for key in ["COMPONENT_NAME"]:
                        if key in os.environ:
                            del os.environ[key]

                    # Load config
                    config = load_config()

                    # Should have deprecation warning
                    self.assertTrue(config.override_name)
                    self.assertIsNone(config.component_name)

                    # Should have logged deprecation warning
                    log_output = "\n".join(log.output)
                    self.assertIn("OVERRIDE_NAME is deprecated", log_output)
                    self.assertIn("Please use COMPONENT_NAME instead", log_output)

    def test_component_name_takes_precedence_over_deprecated(self):
        """Test that COMPONENT_NAME takes precedence over deprecated OVERRIDE_NAME."""
        with self.assertLogs("sbomify_action", level="WARNING") as log:
            # Create a dummy lock file for validation
            with tempfile.TemporaryDirectory() as tmp_dir:
                lock_file = Path(tmp_dir) / "test.lock"
                lock_file.write_text("dummy content")

                # Mock environment variables with both set
                env_vars = {
                    "TOKEN": "test-token",
                    "COMPONENT_ID": "test-component",
                    "COMPONENT_NAME": "my-custom-component",
                    "OVERRIDE_NAME": "true",
                    "LOCK_FILE": str(lock_file),
                }
                with patch.dict(os.environ, env_vars, clear=False):
                    # Load config which should prefer COMPONENT_NAME
                    config = load_config()

                    # Should use COMPONENT_NAME value and ignore OVERRIDE_NAME
                    self.assertEqual(config.component_name, "my-custom-component")
                    self.assertFalse(config.override_name)

                    # Should have logged warnings
                    log_output = "\n".join(log.output)
                    self.assertIn("Both COMPONENT_NAME and OVERRIDE_NAME are set", log_output)
                    self.assertIn("Using COMPONENT_NAME and ignoring OVERRIDE_NAME", log_output)
                    self.assertIn("OVERRIDE_NAME is deprecated", log_output)

    def test_component_purl_loaded_from_env(self):
        """Test that COMPONENT_PURL is loaded from environment variable."""
        # Create a dummy lock file for validation
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "test.lock"
            lock_file.write_text("dummy content")

            # Mock environment variables with COMPONENT_PURL
            env_vars = {
                "TOKEN": "test-token",
                "COMPONENT_ID": "test-component",
                "COMPONENT_PURL": "pkg:pypi/my-package@1.0.0",
                "LOCK_FILE": str(lock_file),
            }
            with patch.dict(os.environ, env_vars, clear=False):
                # Load config
                config = load_config()

                # Should use COMPONENT_PURL value
                self.assertEqual(config.component_purl, "pkg:pypi/my-package@1.0.0")

    def test_component_purl_defaults_to_none(self):
        """Test that component_purl defaults to None when not specified."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
        )
        self.assertIsNone(config.component_purl)

    def test_upload_destinations_default_to_sbomify(self):
        """Test that upload_destinations defaults to ['sbomify'] when not specified."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
        )
        # __post_init__ should set default
        self.assertEqual(config.upload_destinations, ["sbomify"])

    def test_upload_destinations_custom_values(self):
        """Test that custom upload_destinations are preserved."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            upload_destinations=["dependency-track"],
        )
        self.assertEqual(config.upload_destinations, ["dependency-track"])

    def test_upload_destinations_multiple(self):
        """Test that multiple upload destinations are supported."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            upload_destinations=["sbomify", "dependency-track"],
        )
        self.assertEqual(config.upload_destinations, ["sbomify", "dependency-track"])

    def test_load_config_invalid_upload_destinations(self):
        """Test that invalid upload destinations cause exit."""
        # Create a dummy lock file for validation
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "test.lock"
            lock_file.write_text("dummy content")

            env_vars = {
                "TOKEN": "test-token",
                "COMPONENT_ID": "test-component",
                "LOCK_FILE": str(lock_file),
                "UPLOAD_DESTINATIONS": "sbomify,invalid-dest",
            }
            with patch.dict(os.environ, env_vars, clear=False):
                with self.assertRaises(SystemExit) as cm:
                    load_config()
                self.assertEqual(cm.exception.code, 1)

    def test_load_config_valid_upload_destinations(self):
        """Test that valid upload destinations are loaded correctly."""
        # Create a dummy lock file for validation
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "test.lock"
            lock_file.write_text("dummy content")

            env_vars = {
                "TOKEN": "test-token",
                "COMPONENT_ID": "test-component",
                "LOCK_FILE": str(lock_file),
                "UPLOAD_DESTINATIONS": "sbomify,dependency-track",
            }
            with patch.dict(os.environ, env_vars, clear=False):
                config = load_config()
                self.assertEqual(config.upload_destinations, ["sbomify", "dependency-track"])

    def test_sbom_format_defaults_to_cyclonedx(self):
        """Test that sbom_format defaults to 'cyclonedx' when not specified."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
        )
        self.assertEqual(config.sbom_format, "cyclonedx")

    def test_sbom_format_cyclonedx_valid(self):
        """Test that 'cyclonedx' is a valid SBOM format."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            sbom_format="cyclonedx",
        )
        # Should not raise any exception
        config.validate()
        self.assertEqual(config.sbom_format, "cyclonedx")

    def test_sbom_format_spdx_valid(self):
        """Test that 'spdx' is a valid SBOM format."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            sbom_format="spdx",
        )
        # Should not raise any exception
        config.validate()
        self.assertEqual(config.sbom_format, "spdx")

    def test_sbom_format_invalid_raises_error(self):
        """Test that invalid SBOM format raises ConfigurationError."""
        config = Config(
            token="test-token",
            component_id="test-component",
            sbom_file="/path/to/sbom.json",
            sbom_format="invalid-format",
        )
        with self.assertRaises(ConfigurationError) as cm:
            config.validate()
        self.assertIn("Invalid SBOM_FORMAT", str(cm.exception))
        self.assertIn("invalid-format", str(cm.exception))

    def test_load_config_sbom_format_from_env(self):
        """Test that SBOM_FORMAT is loaded from environment variable."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "test.lock"
            lock_file.write_text("dummy content")

            env_vars = {
                "TOKEN": "test-token",
                "COMPONENT_ID": "test-component",
                "LOCK_FILE": str(lock_file),
                "SBOM_FORMAT": "spdx",
            }
            with patch.dict(os.environ, env_vars, clear=False):
                config = load_config()
                self.assertEqual(config.sbom_format, "spdx")

    def test_load_config_sbom_format_case_insensitive(self):
        """Test that SBOM_FORMAT is case-insensitive."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "test.lock"
            lock_file.write_text("dummy content")

            env_vars = {
                "TOKEN": "test-token",
                "COMPONENT_ID": "test-component",
                "LOCK_FILE": str(lock_file),
                "SBOM_FORMAT": "SPDX",  # Uppercase
            }
            with patch.dict(os.environ, env_vars, clear=False):
                config = load_config()
                self.assertEqual(config.sbom_format, "spdx")

    def test_load_config_invalid_sbom_format_exits(self):
        """Test that invalid SBOM_FORMAT causes exit."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "test.lock"
            lock_file.write_text("dummy content")

            env_vars = {
                "TOKEN": "test-token",
                "COMPONENT_ID": "test-component",
                "LOCK_FILE": str(lock_file),
                "SBOM_FORMAT": "invalid",
            }
            with patch.dict(os.environ, env_vars, clear=False):
                with self.assertRaises(SystemExit) as cm:
                    load_config()
                self.assertEqual(cm.exception.code, 1)


class TestAdditionalPackagesOnlyMode(unittest.TestCase):
    """Test cases for additional-packages-only mode (--lock-file none / --sbom-file none)."""

    def test_is_additional_packages_only_lock_file_none(self):
        """Test that lock_file='none' triggers additional-packages-only mode."""
        config = Config(
            token="",
            component_id="",
            lock_file="none",
            upload=False,
        )
        self.assertTrue(config.is_additional_packages_only)

    def test_is_additional_packages_only_sbom_file_none(self):
        """Test that sbom_file='none' triggers additional-packages-only mode."""
        config = Config(
            token="",
            component_id="",
            sbom_file="none",
            upload=False,
        )
        self.assertTrue(config.is_additional_packages_only)

    def test_is_additional_packages_only_case_insensitive(self):
        """Test that 'None', 'NONE' etc. also trigger additional-packages-only mode."""
        for value in ["None", "NONE", "nOnE"]:
            config = Config(
                token="",
                component_id="",
                lock_file=value,
                upload=False,
            )
            self.assertTrue(config.is_additional_packages_only, f"Expected True for lock_file='{value}'")

    def test_is_additional_packages_only_false_for_regular_file(self):
        """Test that regular file paths do not trigger additional-packages-only mode."""
        config = Config(
            token="",
            component_id="",
            lock_file="/path/to/requirements.txt",
            upload=False,
        )
        self.assertFalse(config.is_additional_packages_only)

    def test_is_additional_packages_only_false_when_no_inputs(self):
        """Test that no inputs do not trigger additional-packages-only mode."""
        config = Config(
            token="",
            component_id="",
            upload=False,
        )
        self.assertFalse(config.is_additional_packages_only)

    @patch.dict(os.environ, {"ADDITIONAL_PACKAGES": "pkg:pypi/requests@2.31.0"})
    def test_validate_lock_file_none_with_packages_passes(self):
        """Test that lock_file='none' with additional packages configured passes validation."""
        config = Config(
            token="",
            component_id="",
            lock_file="none",
            upload=False,
        )
        # Should not raise
        config.validate()

    def test_validate_lock_file_none_without_packages_fails(self):
        """Test that lock_file='none' without additional packages raises ConfigurationError."""
        config = Config(
            token="",
            component_id="",
            lock_file="none",
            upload=False,
        )
        # Ensure no additional packages are configured
        with patch.dict(os.environ, {}, clear=False):
            # Remove any env vars that could provide packages
            for key in ["ADDITIONAL_PACKAGES", "ADDITIONAL_PACKAGES_FILE"]:
                os.environ.pop(key, None)

            with self.assertRaises(ConfigurationError) as cm:
                config.validate()
            self.assertIn("Additional packages only mode", str(cm.exception))

    @patch.dict(os.environ, {"ADDITIONAL_PACKAGES": "pkg:pypi/requests@2.31.0"})
    def test_validate_sbom_file_none_with_packages_passes(self):
        """Test that sbom_file='none' with additional packages configured passes validation."""
        config = Config(
            token="",
            component_id="",
            sbom_file="none",
            upload=False,
        )
        # Should not raise
        config.validate()

    @patch.dict(os.environ, {"ADDITIONAL_PACKAGES": "pkg:pypi/requests@2.31.0"})
    def test_build_config_lock_file_none_skips_path_expansion(self):
        """Test that build_config with lock_file='none' doesn't try to expand paths."""
        from sbomify_action.cli.main import build_config

        # Should not raise FileProcessingError
        config = build_config(
            lock_file="none",
            upload=False,
        )
        self.assertEqual(config.lock_file, "none")
        self.assertTrue(config.is_additional_packages_only)

    @patch.dict(os.environ, {"ADDITIONAL_PACKAGES": "pkg:pypi/requests@2.31.0"})
    def test_build_config_sbom_file_none_skips_path_expansion(self):
        """Test that build_config with sbom_file='none' doesn't try to expand paths."""
        from sbomify_action.cli.main import build_config

        # Should not raise FileProcessingError
        config = build_config(
            sbom_file="none",
            upload=False,
        )
        self.assertEqual(config.sbom_file, "none")
        self.assertTrue(config.is_additional_packages_only)


class TestBuildConfig(unittest.TestCase):
    """Test cases for the build_config function (new CLI helper)."""

    def test_build_config_with_all_args(self):
        """Test build_config with all arguments provided."""
        from sbomify_action.cli.main import build_config

        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            config = build_config(
                token="test-token",
                component_id="test-component",
                lock_file=str(lock_file),
                output_file="output.json",
                upload=False,
                upload_destinations=["sbomify"],
                augment=True,
                enrich=True,
                override_sbom_metadata=True,
                component_version="1.0.0",
                component_name="my-component",
                component_purl="pkg:pypi/my-package@1.0.0",
                product_releases='["product:v1.0.0"]',
                api_base_url="https://custom.api.com",
                sbom_format="spdx",
            )

            self.assertEqual(config.token, "test-token")
            self.assertEqual(config.component_id, "test-component")
            self.assertIn("requirements.txt", config.lock_file)
            self.assertEqual(config.output_file, "output.json")
            self.assertFalse(config.upload)
            self.assertEqual(config.upload_destinations, ["sbomify"])
            self.assertTrue(config.augment)
            self.assertTrue(config.enrich)
            self.assertTrue(config.override_sbom_metadata)
            self.assertEqual(config.component_version, "1.0.0")
            self.assertEqual(config.component_name, "my-component")
            self.assertEqual(config.component_purl, "pkg:pypi/my-package@1.0.0")
            # product_releases gets validated/parsed
            self.assertEqual(config.product_releases, ["product:v1.0.0"])
            self.assertEqual(config.api_base_url, "https://custom.api.com")
            self.assertEqual(config.sbom_format, "spdx")

    def test_build_config_non_sbom_bom_type_forces_verbatim(self):
        """A non-SBOM bom_type (VEX/CBOM) disables augment/enrich so the
        artifact is uploaded exactly as authored."""
        from sbomify_action.cli.main import build_config

        with tempfile.TemporaryDirectory() as tmp_dir:
            vex_file = Path(tmp_dir) / "x.vex.cdx.json"
            vex_file.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6"}')

            config = build_config(
                sbom_file=str(vex_file),
                upload=False,
                augment=True,
                enrich=True,
                bom_type="vex",
            )
            self.assertEqual(config.bom_type, "vex")
            self.assertFalse(config.augment)
            self.assertFalse(config.enrich)

    def test_build_config_sbom_keeps_augment_enrich(self):
        """A plain SBOM upload still augments and enriches."""
        from sbomify_action.cli.main import build_config

        with tempfile.TemporaryDirectory() as tmp_dir:
            sbom_file = Path(tmp_dir) / "sbom.cdx.json"
            sbom_file.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6"}')

            config = build_config(
                sbom_file=str(sbom_file),
                upload=False,
                augment=True,
                enrich=True,
            )
            self.assertTrue(config.augment)
            self.assertTrue(config.enrich)
            self.assertEqual(config.bom_type, "sbom")

    def test_build_config_defaults(self):
        """Test build_config uses correct defaults."""
        from sbomify_action.cli.main import SBOMIFY_PRODUCTION_API, build_config

        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            config = build_config(
                lock_file=str(lock_file),
                upload=False,
            )

            self.assertEqual(config.output_file, "sbom_output.json")
            self.assertFalse(config.upload)
            # Config.__post_init__ sets default to ["sbomify"] when None
            self.assertEqual(config.upload_destinations, ["sbomify"])
            self.assertFalse(config.augment)
            self.assertFalse(config.enrich)
            self.assertFalse(config.override_sbom_metadata)
            self.assertEqual(config.api_base_url, SBOMIFY_PRODUCTION_API)
            self.assertEqual(config.sbom_format, "cyclonedx")
            self.assertEqual(config.bom_type, "sbom")

    def test_build_config_non_string_bom_type_exits_cleanly(self):
        """A non-string bom_type from an untyped caller must exit via the
        ConfigurationError path, not crash with AttributeError on .lower()."""
        from sbomify_action.cli.main import build_config

        with tempfile.TemporaryDirectory() as tmp_dir:
            sbom_file = Path(tmp_dir) / "sbom.cdx.json"
            sbom_file.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6"}')

            with self.assertRaises(SystemExit):
                build_config(sbom_file=str(sbom_file), upload=False, bom_type=123)  # type: ignore[arg-type]

    def test_cli_bom_type_option_defaults_to_sbom(self):
        """The --bom-type click option itself defaults to 'sbom' so --help and
        the parsed value agree; unset must not reach the pipeline as None."""
        from sbomify_action.cli.main import cli

        param = next(p for p in cli.params if p.name == "bom_type")
        self.assertEqual(param.default, "sbom")

    def test_build_config_normalizes_sbom_format_case(self):
        """Test that build_config normalizes SBOM format to lowercase."""
        from sbomify_action.cli.main import build_config

        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            # Test various case variations
            for fmt in ["SPDX", "Spdx", "sPdX"]:
                config = build_config(
                    lock_file=str(lock_file),
                    upload=False,
                    sbom_format=fmt,
                )
                self.assertEqual(config.sbom_format, "spdx")

    def test_build_config_handles_empty_token(self):
        """Test build_config handles None/empty token correctly."""
        from sbomify_action.cli.main import build_config

        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            # None token should become empty string
            config = build_config(
                token=None,
                component_id=None,
                lock_file=str(lock_file),
                upload=False,
            )

            self.assertEqual(config.token, "")
            self.assertEqual(config.component_id, "")


class TestLoadConfigAndBuildConfigParity(unittest.TestCase):
    """Test that load_config and build_config produce equivalent results."""

    def test_load_config_and_build_config_parity(self):
        """Test that load_config produces same config as equivalent build_config call."""
        from sbomify_action.cli.main import build_config, load_config

        with tempfile.TemporaryDirectory() as tmp_dir:
            lock_file = Path(tmp_dir) / "requirements.txt"
            lock_file.write_text("requests==2.28.0")

            env_vars = {
                "TOKEN": "test-token",
                "COMPONENT_ID": "test-component",
                "LOCK_FILE": str(lock_file),
                "OUTPUT_FILE": "output.json",
                "UPLOAD": "false",
                "AUGMENT": "false",
                "ENRICH": "true",
                "SBOM_FORMAT": "cyclonedx",
            }

            with patch.dict(os.environ, env_vars, clear=False):
                config_from_env = load_config()

            config_from_args = build_config(
                token="test-token",
                component_id="test-component",
                lock_file=str(lock_file),
                output_file="output.json",
                upload=False,
                augment=False,
                enrich=True,
                sbom_format="cyclonedx",
            )

            # Key fields should match
            self.assertEqual(config_from_env.token, config_from_args.token)
            self.assertEqual(config_from_env.component_id, config_from_args.component_id)
            self.assertEqual(config_from_env.output_file, config_from_args.output_file)
            self.assertEqual(config_from_env.upload, config_from_args.upload)
            self.assertEqual(config_from_env.augment, config_from_args.augment)
            self.assertEqual(config_from_env.enrich, config_from_args.enrich)
            self.assertEqual(config_from_env.sbom_format, config_from_args.sbom_format)


if __name__ == "__main__":
    unittest.main()
