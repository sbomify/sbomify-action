"""Pytest configuration and shared fixtures for all tests."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def disable_sentry_for_tests(monkeypatch):
    """Disable Sentry telemetry for all tests.

    This fixture runs automatically for every test to prevent Sentry events
    from being sent during test runs. Tests that specifically need to test
    Sentry functionality (like test_sentry_filtering.py) should override
    this by setting TELEMETRY=true in their own fixtures or patches.
    """
    monkeypatch.setenv("TELEMETRY", "false")


@pytest.fixture(autouse=True)
def mock_tea_client(request):
    """Prevent TeaSource from making real network calls in non-TEA tests.

    libtea uses its own HTTP transport, so mocking requests.Session does not
    intercept TEA network calls. This fixture patches TeaClient.from_well_known
    globally so that only tests in test_tea_*.py (which patch it themselves)
    make deliberate use of the client.
    """
    if request.module.__name__.startswith("tests.test_tea_") or request.module.__name__.startswith("test_tea_"):
        yield
        return
    mock_client = MagicMock()
    mock_client.search_product_releases.return_value = MagicMock(results=())
    with patch("sbomify_action._enrichment.sources.tea.TeaClient.from_well_known", return_value=mock_client):
        yield
