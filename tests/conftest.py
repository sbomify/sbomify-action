"""Pytest configuration and shared fixtures for all tests."""

from pathlib import Path

import pytest
import sentry_sdk
from sentry_sdk.envelope import Envelope
from sentry_sdk.transport import Transport


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


class NoNetworkTransport(Transport):
    """A Sentry transport that keeps every envelope in this process.

    Sentry's own transport is chosen from the options at ``init`` time and
    then owns a background worker with a live connection pool. Replacing it
    is the only place where "no test may talk to Sentry" can be stated once
    and hold for the whole suite.
    """

    def __init__(self, options: dict | None = None) -> None:
        super().__init__(options)
        self.envelopes: list[Envelope] = []

    def capture_envelope(self, envelope: Envelope) -> None:
        self.envelopes.append(envelope)


@pytest.fixture(autouse=True)
def disable_sentry_for_tests(monkeypatch):
    """Keep Sentry off, and keep it in the process when a test turns it on.

    Two layers, because one was not enough.

    TELEMETRY=false is the first, and it covers every test that does not care
    about Sentry. It is not enough on its own: the tests in
    test_sentry_filtering.py exist to exercise ``initialize_sentry``, so they
    have to switch telemetry back on. Several do it with
    ``patch.dict(os.environ, {...}, clear=True)``, which wipes the whole
    environment -- TELEMETRY, so telemetry defaults back to on, and SENTRY_DSN,
    so ``initialize_sentry`` falls back to the production DSN compiled into it.
    Six of those seven tests knew to put SENTRY_DSN back. The seventh did not,
    and shipped a real exception to the live project on every CI run for a
    month before anyone read the project and asked why the top issue was
    "Test exception in TeamCity".

    Adding the key to the seventh test fixes that test. It does not fix the
    next one, because the failure mode is a forgotten dict key in a file whose
    whole subject is turning telemetry on. So the second layer is the
    transport: every ``sentry_sdk.init`` in this suite gets one that appends
    to a list. A test that forgets the DSN now sees no events instead of a
    live project seeing all of them, and the assertion it was making still
    works, because ``before_send`` and the client options are untouched.
    """
    monkeypatch.setenv("TELEMETRY", "false")

    real_init = sentry_sdk.init

    def init_without_network(*args, **kwargs):
        kwargs["transport"] = NoNetworkTransport()
        return real_init(*args, **kwargs)

    monkeypatch.setattr(sentry_sdk, "init", init_without_network)


@pytest.fixture(autouse=True)
def _no_runtime_fetching(monkeypatch, request):
    """Stop the suite from downloading tool runtimes over the network.

    Generators call ``ensure_runtime`` before shelling out, so a test that
    stubs only the subprocess still reaches for an 83MB syft. That went
    unnoticed because a developer machine accumulates a runtime cache and
    quietly serves it -- the tests looked hermetic while depending on state
    no clean runner has.

    tests/test_runtimes.py exercises the fetcher itself and binds
    ``ensure_runtime`` at import, so it is unaffected by this and needs no
    exemption.
    """
    for module in ("cyclonedx_cargo", "cyclonedx_gomod", "cdxgen", "syft"):
        monkeypatch.setattr(
            f"sbomify_action._generation.generators.{module}.ensure_runtime",
            lambda name: Path("/nonexistent-runtime-bin"),
            raising=False,
        )


@pytest.fixture(autouse=True)
def _no_persistent_enrichment_cache(monkeypatch):
    """Keep the on-disk enrichment cache out of the suite.

    Same hazard as ``_no_runtime_fetching`` above: the cache lives in the
    developer's real ``~/.cache/sbomify`` and is shared by every run, so
    without this a test that mocks an HTTP response is silently served a
    previous run's answer instead -- and the suite passes on a machine that
    has accumulated state while failing on a clean one. It also writes to the
    developer's home directory as a side effect of running the tests.

    Disabled rather than redirected so a test that wants the cache has to ask
    for it. tests/test_enrichment_cache.py re-enables it against a tmp_path.
    """
    from sbomify_action._enrichment import cache

    monkeypatch.setenv("SBOMIFY_ENRICHMENT_CACHE", "off")
    cache.close()
    yield
    cache.close()
