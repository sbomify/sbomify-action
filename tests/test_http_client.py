"""Tests for http_client module."""

import re
import unittest

from sbomify_action.exceptions import ConfigurationError
from sbomify_action.http_client import USER_AGENT, get_default_headers, validate_endpoint_url


class TestUserAgent(unittest.TestCase):
    """Tests for USER_AGENT constant."""

    def test_user_agent_format(self):
        """Test USER_AGENT has expected format."""
        self.assertIn("sbomify-action/", USER_AGENT)
        self.assertIn("(hello@sbomify.com)", USER_AGENT)

    def test_user_agent_has_version(self):
        """Test USER_AGENT includes a version."""
        # Format: sbomify-action/X.Y (hello@sbomify.com)
        parts = USER_AGENT.split("/")
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0], "sbomify-action")
        # Version part should exist and be a valid version string
        version_part = parts[1].split(" ")[0]
        self.assertTrue(len(version_part) > 0)
        # Verify it's either a valid semver-like version or "unknown"
        # Valid versions match patterns like "1.0", "1.0.0", "1.0.0-beta", etc.
        version_pattern = r"^\d+\.\d+(\.\d+)?(-[\w.]+)?$"
        is_valid_version = re.match(version_pattern, version_part) is not None
        is_unknown = version_part == "unknown"
        self.assertTrue(
            is_valid_version or is_unknown,
            f"Version '{version_part}' is neither a valid version pattern nor 'unknown'",
        )


class TestGetDefaultHeaders(unittest.TestCase):
    """Tests for get_default_headers function."""

    def test_default_headers_minimal(self):
        """Test get_default_headers with no arguments."""
        headers = get_default_headers()
        self.assertIn("User-Agent", headers)
        self.assertEqual(headers["User-Agent"], USER_AGENT)
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("Content-Type", headers)

    def test_default_headers_with_token(self):
        """Test get_default_headers with token."""
        headers = get_default_headers(token="test-token-123")
        self.assertIn("User-Agent", headers)
        self.assertIn("Authorization", headers)
        self.assertEqual(headers["Authorization"], "Bearer test-token-123")

    def test_default_headers_with_content_type(self):
        """Test get_default_headers with content_type."""
        headers = get_default_headers(content_type="application/json")
        self.assertIn("User-Agent", headers)
        self.assertIn("Content-Type", headers)
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_default_headers_with_all_options(self):
        """Test get_default_headers with all options."""
        headers = get_default_headers(token="my-secret-token", content_type="application/xml")
        self.assertEqual(headers["User-Agent"], USER_AGENT)
        self.assertEqual(headers["Authorization"], "Bearer my-secret-token")
        self.assertEqual(headers["Content-Type"], "application/xml")

    def test_default_headers_empty_token_not_included(self):
        """Test get_default_headers with empty string token."""
        headers = get_default_headers(token="")
        self.assertNotIn("Authorization", headers)

    def test_default_headers_none_values_not_included(self):
        """Test get_default_headers with explicit None values."""
        headers = get_default_headers(token=None, content_type=None)
        self.assertIn("User-Agent", headers)
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("Content-Type", headers)


class TestValidateEndpointUrl(unittest.TestCase):
    """validate_endpoint_url refuses URLs that would put credentials at risk."""

    def assert_rejected(self, url: str, *needles: str) -> str:
        with self.assertRaises(ConfigurationError) as cm:
            validate_endpoint_url(url, "SOME_URL")
        message = str(cm.exception)
        self.assertIn("SOME_URL", message)
        for needle in needles:
            self.assertIn(needle, message)
        return message

    def test_https_accepted(self):
        for url in ("https://app.sbomify.com", "https://dtrack.example.com:8443/api", "HTTPS://Example.COM/x"):
            with self.subTest(url=url):
                validate_endpoint_url(url, "SOME_URL")

    def test_http_to_loopback_accepted(self):
        for url in (
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://127.0.0.1:8000/api",
            "http://[::1]:8081/api",
            "http://dtrack.localhost/api",
        ):
            with self.subTest(url=url):
                validate_endpoint_url(url, "SOME_URL")

    def test_http_to_remote_host_rejected(self):
        message = self.assert_rejected("http://dtrack.example.com/api", "https://", "dtrack.example.com")
        self.assertIn("unencrypted", message)

    def test_http_to_lookalike_loopback_rejected(self):
        # The old check was a substring test on netloc, which these all passed.
        for url in (
            "http://localhost.evil.example",
            "http://127.0.0.1.nip.io",
            "http://evil.example/?localhost",
            "http://0.0.0.0:8000",
        ):
            with self.subTest(url=url):
                self.assert_rejected(url, "https://")

    def test_userinfo_rejected_without_echoing_it(self):
        for url in (
            "https://user:hunter2@dtrack.example.com",
            "https://hunter2@dtrack.example.com",
            "http://user:hunter2@localhost",
        ):
            with self.subTest(url=url):
                message = self.assert_rejected(url, "user:password@")
                self.assertNotIn("hunter2", message)

    def test_non_http_scheme_rejected(self):
        for url in ("ftp://dtrack.example.com", "file:///etc/passwd", "dtrack.example.com/api", ""):
            with self.subTest(url=url):
                self.assert_rejected(url, "http:// or https://")

    def test_unparseable_url_rejected(self):
        self.assert_rejected("http://[::1", "not a valid URL")

    def test_missing_host_rejected(self):
        self.assert_rejected("https://", "hostname")
        self.assert_rejected("https:///api", "hostname")

    def test_http_rejection_names_the_opt_in(self):
        with self.assertRaises(ConfigurationError) as cm:
            validate_endpoint_url("http://dtrack.corp", "SOME_URL", allow_http_setting="SOME_ALLOW_HTTP")
        self.assertIn("SOME_ALLOW_HTTP=true", str(cm.exception))

    def test_allow_http_accepts_remote_http_with_warning(self):
        with self.assertLogs("sbomify_action.http_client", "WARNING") as logs:
            validate_endpoint_url(
                "http://dtrack.corp/api", "SOME_URL", allow_http=True, allow_http_setting="SOME_ALLOW_HTTP"
            )
        self.assertIn("SOME_ALLOW_HTTP", logs.output[0])
        self.assertIn("unencrypted", logs.output[0])

    def test_allow_http_does_not_relax_other_checks(self):
        for url in ("ftp://dtrack.corp", "http://user:pw@dtrack.corp", "http://"):
            with self.subTest(url=url), self.assertRaises(ConfigurationError):
                validate_endpoint_url(url, "SOME_URL", allow_http=True)


if __name__ == "__main__":
    unittest.main()
