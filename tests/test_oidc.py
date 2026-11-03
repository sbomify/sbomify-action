"""Unit tests for OIDC trusted-publishing support (sbomify_action.oidc)."""

import unittest
from unittest.mock import Mock, patch

import requests

from sbomify_action.exceptions import OIDCBindingMissingError, OIDCExchangeError
from sbomify_action.oidc import (
    DEFAULT_OIDC_AUDIENCE,
    _scrub_secrets,
    default_audience_for,
    exchange_for_sbomify_token,
    is_github_oidc_available,
    obtain_sbomify_token_via_oidc,
    request_github_oidc_token,
)


def _gha_env(**overrides):
    base = {
        "GITHUB_ACTIONS": "true",
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://gha-runner.example.com/token",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-bearer",
    }
    base.update(overrides)
    # patch.dict needs both the values to set AND the names to clear if value is None.
    return {k: v for k, v in base.items() if v is not None}


class TestIsGithubOidcAvailable(unittest.TestCase):
    def test_all_env_present(self):
        with patch.dict("os.environ", _gha_env(), clear=True):
            self.assertTrue(is_github_oidc_available())

    def test_github_actions_unset(self):
        with patch.dict("os.environ", _gha_env(GITHUB_ACTIONS=""), clear=True):
            self.assertFalse(is_github_oidc_available())

    def test_github_actions_with_whitespace(self):
        """GITHUB_ACTIONS=' true ' (leading/trailing whitespace) is still truthy."""
        with patch.dict("os.environ", _gha_env(GITHUB_ACTIONS=" true "), clear=True):
            self.assertTrue(is_github_oidc_available())

    def test_github_actions_yes(self):
        """GITHUB_ACTIONS='yes' should be accepted (some self-hosted runners use this)."""
        with patch.dict("os.environ", _gha_env(GITHUB_ACTIONS="yes"), clear=True):
            self.assertTrue(is_github_oidc_available())

    def test_request_url_missing(self):
        env = _gha_env()
        env.pop("ACTIONS_ID_TOKEN_REQUEST_URL")
        with patch.dict("os.environ", env, clear=True):
            self.assertFalse(is_github_oidc_available())

    def test_request_token_missing(self):
        env = _gha_env()
        env.pop("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        with patch.dict("os.environ", env, clear=True):
            self.assertFalse(is_github_oidc_available())

    def test_outside_github_actions(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(is_github_oidc_available())


class TestRequestGithubOidcToken(unittest.TestCase):
    @patch("sbomify_action.oidc.requests.get")
    def test_success(self, mock_get):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"value": "the.jwt.here"}
        mock_get.return_value = mock_response

        with patch.dict("os.environ", _gha_env(), clear=True):
            token = request_github_oidc_token("sbomify.com")

        self.assertEqual(token, "the.jwt.here")
        call = mock_get.call_args
        self.assertEqual(call.args[0], "https://gha-runner.example.com/token")
        self.assertEqual(call.kwargs["params"], {"audience": "sbomify.com"})
        self.assertEqual(call.kwargs["headers"]["Authorization"], "Bearer runner-bearer")

    def test_env_missing_raises(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(OIDCExchangeError):
                request_github_oidc_token("sbomify.com")

    @patch("sbomify_action.oidc.requests.get")
    def test_non_2xx_raises(self, mock_get):
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 500
        mock_response.text = "boom"
        mock_get.return_value = mock_response

        with patch.dict("os.environ", _gha_env(), clear=True):
            with self.assertRaises(OIDCExchangeError):
                request_github_oidc_token("sbomify.com")

    @patch("sbomify_action.oidc.requests.get")
    def test_missing_value_field_raises(self, mock_get):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"other": "field"}
        mock_get.return_value = mock_response

        with patch.dict("os.environ", _gha_env(), clear=True):
            with self.assertRaises(OIDCExchangeError):
                request_github_oidc_token("sbomify.com")

    @patch("sbomify_action.oidc.requests.get")
    def test_connection_error_raises_exchange_error(self, mock_get):
        mock_get.side_effect = requests.ConnectionError("dns failure")
        with patch.dict("os.environ", _gha_env(), clear=True):
            with self.assertRaises(OIDCExchangeError) as ctx:
                request_github_oidc_token("sbomify.com")
        self.assertIn("Failed to reach", str(ctx.exception))


class TestExchangeForSbomifyToken(unittest.TestCase):
    @patch("sbomify_action.oidc.requests.post")
    def test_success(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "short-lived-token",
            "expires_in": 900,
            "component_id": "comp-1",
            "token_type": "Bearer",
        }
        mock_post.return_value = mock_response

        token, ttl = exchange_for_sbomify_token("oidc.jwt.here", "comp-1", "https://app.sbomify.com")

        self.assertEqual(token, "short-lived-token")
        self.assertEqual(ttl, 900)

        call = mock_post.call_args
        self.assertEqual(
            call.args[0],
            "https://app.sbomify.com/api/v1/auth/oidc/github/exchange",
        )
        self.assertEqual(call.kwargs["json"], {"component_id": "comp-1"})
        self.assertEqual(call.kwargs["headers"]["Authorization"], "Bearer oidc.jwt.here")

    @patch("sbomify_action.oidc.requests.post")
    def test_trailing_slash_normalized(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "x", "expires_in": 900}
        mock_post.return_value = mock_response

        exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com/")

        self.assertEqual(
            mock_post.call_args.args[0],
            "https://app.sbomify.com/api/v1/auth/oidc/github/exchange",
        )

    @patch("sbomify_action.oidc.requests.post")
    def test_403_raises_binding_missing(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.json.return_value = {"detail": "no binding for repo 123/456"}
        mock_post.return_value = mock_response

        with self.assertRaises(OIDCBindingMissingError) as ctx:
            exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")

        msg = str(ctx.exception)
        self.assertIn("comp-1", msg)
        self.assertIn("Trusted Publishing", msg)

    @patch("sbomify_action.oidc.requests.post")
    def test_401_raises_exchange_error(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"detail": "Invalid signature"}
        mock_post.return_value = mock_response

        with self.assertRaises(OIDCExchangeError) as ctx:
            exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")
        self.assertIn("401", str(ctx.exception))

    @patch("sbomify_action.oidc.requests.post")
    def test_404_raises_exchange_error(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"detail": "Component not found"}
        mock_post.return_value = mock_response

        with self.assertRaises(OIDCExchangeError) as ctx:
            exchange_for_sbomify_token("jwt", "missing-comp", "https://app.sbomify.com")
        self.assertIn("missing-comp", str(ctx.exception))

    @patch("sbomify_action.oidc.requests.post")
    def test_429_raises_exchange_error(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.json.return_value = {"detail": "Rate limited"}
        mock_post.return_value = mock_response

        with self.assertRaises(OIDCExchangeError) as ctx:
            exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")
        self.assertIn("rate-limited", str(ctx.exception))

    @patch("sbomify_action.oidc.time.sleep")
    @patch("sbomify_action.oidc.requests.post")
    def test_503_retries_then_raises(self, mock_post, _mock_sleep):
        """Two consecutive 503s — give up after one retry."""
        five_oh_three = Mock()
        five_oh_three.status_code = 503
        five_oh_three.json.return_value = {"detail": "JWKS unreachable"}
        mock_post.return_value = five_oh_three

        with self.assertRaises(OIDCExchangeError):
            exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")
        self.assertEqual(mock_post.call_count, 2)

    @patch("sbomify_action.oidc.time.sleep")
    @patch("sbomify_action.oidc.requests.post")
    def test_503_then_success_recovers(self, mock_post, _mock_sleep):
        """503 followed by 200 on retry — should succeed."""
        five_oh_three = Mock(status_code=503, json=Mock(return_value={"detail": "JWKS unreachable"}))
        ok = Mock(status_code=200, json=Mock(return_value={"access_token": "t", "expires_in": 900}))
        mock_post.side_effect = [five_oh_three, ok]

        token, ttl = exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")
        self.assertEqual(token, "t")
        self.assertEqual(ttl, 900)
        self.assertEqual(mock_post.call_count, 2)

    @patch("sbomify_action.oidc.time.sleep")
    @patch("sbomify_action.oidc.requests.post")
    def test_503_then_request_exception_on_retry_raises(self, mock_post, _mock_sleep):
        """503 then a transport-level failure on retry should be reported."""
        five_oh_three = Mock(status_code=503, json=Mock(return_value={}))
        mock_post.side_effect = [five_oh_three, requests.ConnectionError("dns")]

        with self.assertRaises(OIDCExchangeError) as ctx:
            exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")
        self.assertIn("retry", str(ctx.exception).lower())

    @patch("sbomify_action.oidc.requests.post")
    def test_connection_error_raises_exchange_error(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("nope")
        with self.assertRaises(OIDCExchangeError) as ctx:
            exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")
        self.assertIn("Failed to reach", str(ctx.exception))

    @patch("sbomify_action.oidc.requests.post")
    def test_response_without_access_token_raises(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"expires_in": 900}
        mock_post.return_value = mock_response

        with self.assertRaises(OIDCExchangeError):
            exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")


class TestObtainSbomifyTokenViaOidc(unittest.TestCase):
    @patch("sbomify_action.oidc.requests.post")
    @patch("sbomify_action.oidc.requests.get")
    def test_end_to_end(self, mock_get, mock_post):
        # GH OIDC token request
        mock_get_response = Mock()
        mock_get_response.ok = True
        mock_get_response.json.return_value = {"value": "github.oidc.jwt"}
        mock_get.return_value = mock_get_response

        # sbomify exchange
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {
            "access_token": "sbomify-short-token",
            "expires_in": 900,
        }
        mock_post.return_value = mock_post_response

        with patch.dict("os.environ", _gha_env(), clear=True):
            token = obtain_sbomify_token_via_oidc(
                component_id="comp-xyz",
                api_base_url="https://app.sbomify.com",
            )

        self.assertEqual(token, "sbomify-short-token")
        # Default audience is sbomify.com
        self.assertEqual(mock_get.call_args.kwargs["params"]["audience"], DEFAULT_OIDC_AUDIENCE)
        # OIDC JWT was forwarded to the exchange endpoint
        self.assertEqual(
            mock_post.call_args.kwargs["headers"]["Authorization"],
            "Bearer github.oidc.jwt",
        )

    @patch("sbomify_action.oidc.requests.post")
    @patch("sbomify_action.oidc.requests.get")
    def test_custom_audience(self, mock_get, mock_post):
        mock_get.return_value = Mock(ok=True, json=Mock(return_value={"value": "jwt"}))
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={"access_token": "t", "expires_in": 900}),
        )

        with patch.dict("os.environ", _gha_env(), clear=True):
            obtain_sbomify_token_via_oidc(
                component_id="comp-xyz",
                api_base_url="https://self-hosted.example.com",
                audience="self-hosted.example.com",
            )

        self.assertEqual(mock_get.call_args.kwargs["params"]["audience"], "self-hosted.example.com")


class TestDefaultAudienceFor(unittest.TestCase):
    def test_production_keeps_legacy_audience(self):
        self.assertEqual(default_audience_for("https://app.sbomify.com"), "sbomify.com")
        self.assertEqual(default_audience_for("https://app.sbomify.com/"), "sbomify.com")

    def test_stage_derives_from_hostname(self):
        self.assertEqual(default_audience_for("https://stage.sbomify.com"), "stage.sbomify.com")

    def test_self_hosted_derives_from_hostname(self):
        self.assertEqual(default_audience_for("https://sbom.example.com"), "sbom.example.com")

    def test_missing_url_falls_back_to_constant(self):
        self.assertEqual(default_audience_for(None), DEFAULT_OIDC_AUDIENCE)
        self.assertEqual(default_audience_for(""), DEFAULT_OIDC_AUDIENCE)


class TestScrubSecrets(unittest.TestCase):
    def test_bearer_redacted(self):
        out = _scrub_secrets("got Bearer abc123.def456")
        self.assertNotIn("abc123", out)
        self.assertIn("[REDACTED]", out)

    def test_jwt_redacted(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature_part"
        out = _scrub_secrets(f"token leaked: {jwt} oops")
        self.assertNotIn(jwt, out)
        self.assertIn("[REDACTED-JWT]", out)

    def test_no_secret_unchanged(self):
        self.assertEqual(_scrub_secrets("plain error message"), "plain error message")


class TestExpiresInTolerance(unittest.TestCase):
    @patch("sbomify_action.oidc.requests.post")
    def test_non_numeric_expires_in_does_not_crash(self, mock_post):
        """If backend returns expires_in='15m' or similar, we still extract the token."""
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={"access_token": "t", "expires_in": "15m"}),
        )
        token, ttl = exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")
        self.assertEqual(token, "t")
        self.assertEqual(ttl, 0)  # Falls back to 0 rather than raising ValueError.

    @patch("sbomify_action.oidc.requests.post")
    def test_missing_expires_in(self, mock_post):
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={"access_token": "t"}),
        )
        token, ttl = exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")
        self.assertEqual(token, "t")
        self.assertEqual(ttl, 0)

    @patch("sbomify_action.oidc.requests.post")
    def test_non_string_access_token_rejected(self, mock_post):
        """A numeric access_token should be rejected rather than silently coerced."""
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={"access_token": 12345, "expires_in": 900}),
        )
        with self.assertRaises(OIDCExchangeError):
            exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")


class TestErrorBodyRedaction(unittest.TestCase):
    @patch("sbomify_action.oidc.requests.post")
    def test_jwt_in_error_detail_is_redacted(self, mock_post):
        leaky_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig"
        mock_post.return_value = Mock(
            status_code=403,
            json=Mock(return_value={"detail": f"rejected token {leaky_jwt}"}),
        )
        with self.assertRaises(OIDCBindingMissingError) as ctx:
            exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")
        self.assertNotIn(leaky_jwt, str(ctx.exception))
        self.assertIn("[REDACTED-JWT]", str(ctx.exception))

    @patch("sbomify_action.oidc.requests.get")
    def test_bearer_in_gh_response_text_is_redacted(self, mock_get):
        mock_get.return_value = Mock(
            ok=False,
            status_code=500,
            text="Internal error: header was 'Bearer runner.secret.value'",
        )
        with patch.dict("os.environ", _gha_env(), clear=True):
            with self.assertRaises(OIDCExchangeError) as ctx:
                request_github_oidc_token("sbomify.com")
        self.assertNotIn("runner.secret.value", str(ctx.exception))
        self.assertIn("[REDACTED]", str(ctx.exception))


class TestGithubOidcHeaders(unittest.TestCase):
    @patch("sbomify_action.oidc.requests.get")
    def test_uses_project_user_agent(self, mock_get):
        mock_get.return_value = Mock(ok=True, json=Mock(return_value={"value": "jwt"}))
        with patch.dict("os.environ", _gha_env(), clear=True):
            request_github_oidc_token("sbomify.com")
        headers = mock_get.call_args.kwargs["headers"]
        self.assertIn("User-Agent", headers)
        self.assertIn("sbomify-action", headers["User-Agent"])
        self.assertEqual(headers["Authorization"], "Bearer runner-bearer")
        self.assertEqual(headers["Accept"], "application/json")


class TestObtainAudienceDefault(unittest.TestCase):
    @patch("sbomify_action.oidc.requests.post")
    @patch("sbomify_action.oidc.requests.get")
    def test_audience_derived_from_api_base_url_when_unset(self, mock_get, mock_post):
        mock_get.return_value = Mock(ok=True, json=Mock(return_value={"value": "jwt"}))
        mock_post.return_value = Mock(status_code=200, json=Mock(return_value={"access_token": "t", "expires_in": 900}))
        with patch.dict("os.environ", _gha_env(), clear=True):
            obtain_sbomify_token_via_oidc(
                component_id="comp-x",
                api_base_url="https://stage.sbomify.com",
                audience=None,
            )
        self.assertEqual(mock_get.call_args.kwargs["params"]["audience"], "stage.sbomify.com")


if __name__ == "__main__":
    unittest.main()


class TestProviderSlugIsValidated(unittest.TestCase):
    """The slug is interpolated into the URL a credential is issued at."""

    def test_a_bare_slug_is_accepted(self):
        """The real callers pass constants like "github"."""
        from sbomify_action.oidc import _PROVIDER_SLUG_RE

        for slug in ("github", "gitlab", "azure-devops", "buildkite2"):
            self.assertTrue(_PROVIDER_SLUG_RE.fullmatch(slug), slug)

    def test_a_slug_that_could_retarget_the_request_is_refused(self):
        """No caller passes these today, and that is the only thing stopping them."""
        for slug in ("../../admin", "a/b", "github/../evil", "GitHub", "", "git hub", "github%2f"):
            with self.subTest(slug=slug):
                with self.assertRaises(OIDCExchangeError) as ctx:
                    exchange_for_sbomify_token("jwt", "component", "https://app.sbomify.com", provider_slug=slug)
                self.assertIn("Refusing to build an OIDC exchange URL", str(ctx.exception))

    def test_the_default_still_reaches_the_github_endpoint(self):
        """Validation must not change where a normal exchange goes."""
        with patch("sbomify_action.oidc.requests.post") as mock_post:
            mock_post.return_value = Mock(status_code=200, json=lambda: {"access_token": "t", "expires_in": 900})
            exchange_for_sbomify_token("jwt", "component", "https://app.sbomify.com")
        assert mock_post.call_args.args[0] == "https://app.sbomify.com/api/v1/auth/oidc/github/exchange"
