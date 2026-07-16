"""Pytest configuration and shared fixtures for all tests."""

import pytest


@pytest.fixture(autouse=True)
def offline_action_pin(monkeypatch):
    """Keep emitted sbomify-action pin resolution offline in all tests.

    ``apply_plan`` and the review preview resolve the latest release and its
    commit SHA from GitHub at run time; without this every such test would
    make real network calls. Stub only the network boundaries
    (``_resolve_latest_release_tag`` and ``_resolve_tag_sha``) so the real
    ``resolve_action_ref`` still runs and falls back to the tag-pinned
    (offline) ref. The lru_cache is cleared around each test so the stubbed
    result never bleeds across tests. Tests exercising the online path
    re-stub these themselves after clearing the cache.
    """
    from sbomify_action.cli.wizard import ci_emitter

    ci_emitter.resolve_action_ref.cache_clear()
    monkeypatch.setattr(ci_emitter, "_resolve_latest_release_tag", lambda: None)
    monkeypatch.setattr(ci_emitter, "_resolve_tag_sha", lambda version: None)
    yield
    ci_emitter.resolve_action_ref.cache_clear()


@pytest.fixture(autouse=True)
def disable_sentry_for_tests(monkeypatch):
    """Disable Sentry telemetry for all tests.

    This fixture runs automatically for every test to prevent Sentry events
    from being sent during test runs. Tests that specifically need to test
    Sentry functionality (like test_sentry_filtering.py) should override
    this by setting TELEMETRY=true in their own fixtures or patches.
    """
    monkeypatch.setenv("TELEMETRY", "false")
