"""Regression tests for GitHub authentication on the license-database fetch.

The license database lives in this repo's GitHub releases. Unauthenticated, the
releases API allows 60 requests/hour per IP; CI runners share IPs, so the call
intermittently 403s:

    WARNING Failed to fetch releases: 403 Client Error: rate limit exceeded for
            url: https://api.github.com/repos/sbomify/sbomify-action/releases

The failure is soft -- assets come back empty, the database is skipped, and
enrichment continues with the other sources -- so it surfaces as an integration
test that fails for no visible reason rather than as an error.
"""

from __future__ import annotations

import os
from unittest.mock import patch

from sbomify_action._enrichment.sources.license_db import _github_auth_headers


class TestGitHubAuthHeaders:
    def test_no_token_sends_no_header(self):
        """Behaviour without a token must be unchanged: anonymous request."""
        with patch.dict(os.environ, {}, clear=True):
            assert _github_auth_headers() == {}

    def test_github_token_is_used(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghs_example"}, clear=True):
            assert _github_auth_headers() == {"Authorization": "Bearer ghs_example"}

    def test_gh_token_is_accepted_as_a_fallback(self):
        """`gh` CLI environments export GH_TOKEN rather than GITHUB_TOKEN."""
        with patch.dict(os.environ, {"GH_TOKEN": "gho_example"}, clear=True):
            assert _github_auth_headers() == {"Authorization": "Bearer gho_example"}

    def test_github_token_wins_when_both_are_set(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "a", "GH_TOKEN": "b"}, clear=True):
            assert _github_auth_headers() == {"Authorization": "Bearer a"}

    def test_empty_token_is_treated_as_absent(self):
        """An unset secret expands to an empty string in CI, which must not
        produce an `Authorization: Bearer ` header -- GitHub rejects that with
        401, which would be worse than staying anonymous."""
        with patch.dict(os.environ, {"GITHUB_TOKEN": ""}, clear=True):
            assert _github_auth_headers() == {}


class TestReleasesRequestIsAuthenticated:
    def test_release_lookup_sends_the_header(self):
        """The header must actually reach the releases call, not just exist."""
        import sbomify_action._enrichment.sources.license_db as mod

        mod._release_assets_cache = None
        source = mod.LicenseDBSource()

        class _Resp:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return []

        class _Session:
            def __init__(self):
                self.headers_seen = None

            def get(self, url, params=None, timeout=None, headers=None):
                self.headers_seen = headers
                return _Resp()

        session = _Session()
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghs_example"}, clear=True):
            source._get_release_assets(session)

        assert session.headers_seen == {"Authorization": "Bearer ghs_example"}
        mod._release_assets_cache = None
