"""Unit tests for OIDC trusted-publishing support (sbomify_action.oidc)."""

import unittest
from unittest.mock import Mock, patch

from sbomify_action.exceptions import OIDCBindingMissingError, OIDCExchangeError
from sbomify_action.oidc import (
    DEFAULT_OIDC_AUDIENCE,
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

    @patch("sbomify_action.oidc.requests.post")
    def test_503_raises_exchange_error(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 503
        mock_response.json.return_value = {"detail": "JWKS unreachable"}
        mock_post.return_value = mock_response

        with self.assertRaises(OIDCExchangeError):
            exchange_for_sbomify_token("jwt", "comp-1", "https://app.sbomify.com")

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


if __name__ == "__main__":
    unittest.main()
