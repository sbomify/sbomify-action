"""Tests for the persistent enrichment cache and its wiring into the registry."""

from __future__ import annotations

import time
from typing import List, Optional

import pytest
import requests
from packageurl import PackageURL

from sbomify_action._enrichment import cache
from sbomify_action._enrichment.metadata import NormalizedMetadata
from sbomify_action._enrichment.registry import SourceRegistry


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    """Point the cache at a temp dir and reset module state around each test."""
    monkeypatch.setenv("SBOMIFY_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("SBOMIFY_ENRICHMENT_CACHE", raising=False)
    monkeypatch.delenv("SBOMIFY_ENRICHMENT_CACHE_TTL", raising=False)
    monkeypatch.delenv("SBOMIFY_ENRICHMENT_CACHE_MISS_TTL", raising=False)
    cache.close()
    yield
    cache.close()


class RecordingSource:
    """A source that records how many times it was actually asked."""

    def __init__(
        self,
        result: Optional[NormalizedMetadata] = None,
        exc: Optional[Exception] = None,
        name: str = "recording-source",
    ):
        self.calls: List[str] = []
        self._result = result
        self._exc = exc
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return 10

    def supports(self, purl: PackageURL) -> bool:
        return True

    def fetch(self, purl: PackageURL, session: requests.Session) -> Optional[NormalizedMetadata]:
        self.calls.append(purl.to_string())
        if self._exc is not None:
            raise self._exc
        return self._result


def _metadata(**kwargs) -> NormalizedMetadata:
    base = dict(licenses=["MIT"], supplier="Acme", source="recording-source")
    base.update(kwargs)
    return NormalizedMetadata(**base)


PURL = PackageURL.from_string("pkg:pypi/example@1.0.0")


class TestRoundTrip:
    def test_stores_and_returns_metadata(self):
        cache.set("src", "pkg:pypi/example@1.0.0", _metadata())
        hit, got = cache.get("src", "pkg:pypi/example@1.0.0")
        assert hit is True
        assert got is not None
        assert got.licenses == ["MIT"]
        assert got.supplier == "Acme"

    def test_miss_is_distinguishable_from_cached_none(self):
        """(True, None) is a known-absent package; (False, None) is nothing cached.

        The registry needs the difference to decide whether to hit the network.
        """
        assert cache.get("src", "never-seen") == (False, None)
        cache.set("src", "known-absent", None)
        assert cache.get("src", "known-absent") == (True, None)

    def test_entries_are_scoped_per_source(self):
        cache.set("source-a", "same-key", _metadata(supplier="A"))
        cache.set("source-b", "same-key", _metadata(supplier="B"))
        assert cache.get("source-a", "same-key")[1].supplier == "A"
        assert cache.get("source-b", "same-key")[1].supplier == "B"

    def test_round_trip_preserves_collection_fields(self):
        cache.set("src", "k", _metadata(licenses=["MIT", "Apache-2.0"], hashes={"sha256": "abc"}))
        got = cache.get("src", "k")[1]
        assert got.licenses == ["MIT", "Apache-2.0"]
        assert got.hashes == {"sha256": "abc"}


class TestExpiry:
    def test_hit_expires_after_its_ttl(self, monkeypatch):
        cache.set("src", "k", _metadata())
        assert cache.get("src", "k")[0] is True, "should be cached before the clock moves"

        monkeypatch.setenv("SBOMIFY_ENRICHMENT_CACHE_TTL", "1")
        monkeypatch.setattr(time, "time", lambda: 1e12)
        assert cache.get("src", "k") == (False, None)

    def test_miss_expires_on_its_own_shorter_ttl(self, monkeypatch):
        """A newly published package must not stay 'absent' for the hit TTL."""
        cache.set("src", "k", None)
        # Long hit TTL, zero-length miss TTL: the negative entry must still go.
        monkeypatch.setenv("SBOMIFY_ENRICHMENT_CACHE_TTL", "99999999")
        monkeypatch.setenv("SBOMIFY_ENRICHMENT_CACHE_MISS_TTL", "1")
        monkeypatch.setattr(time, "time", lambda: 1e12)
        assert cache.get("src", "k") == (False, None)

    def test_miss_ttl_default_is_much_shorter_than_hit_ttl(self):
        assert cache.DEFAULT_MISS_TTL_SECONDS < cache.DEFAULT_HIT_TTL_SECONDS

    def test_ttl_zero_expires_immediately_rather_than_never(self, monkeypatch):
        """0 is a plausible way to bypass one half of the cache.

        Guarding the comparison on truthiness would read it as "no expiry",
        which is the opposite of what was asked for.
        """
        cache.set("src", "k", _metadata())
        monkeypatch.setenv("SBOMIFY_ENRICHMENT_CACHE_TTL", "0")
        assert cache.get("src", "k") == (False, None)

    def test_negative_ttl_falls_back_to_the_default(self, monkeypatch):
        cache.set("src", "k", _metadata())
        monkeypatch.setenv("SBOMIFY_ENRICHMENT_CACHE_TTL", "-5")
        assert cache.get("src", "k")[0] is True


class TestDisabling:
    def test_env_var_disables_reads_and_writes(self, monkeypatch):
        monkeypatch.setenv("SBOMIFY_ENRICHMENT_CACHE", "off")
        cache.close()
        cache.set("src", "k", _metadata())
        assert cache.get("src", "k") == (False, None)


class TestRegistryIntegration:
    def test_second_lookup_does_not_hit_the_source(self):
        source = RecordingSource(result=_metadata())
        registry = SourceRegistry()
        registry.register(source)
        session = requests.Session()

        first = registry.fetch_metadata(PURL, session)
        second = registry.fetch_metadata(PURL, session)

        assert len(source.calls) == 1, "second lookup should have been served from cache"
        assert first.supplier == second.supplier == "Acme"

    def test_negative_result_is_cached_so_absent_packages_are_asked_once(self):
        source = RecordingSource(result=None)
        registry = SourceRegistry()
        registry.register(source)
        session = requests.Session()

        registry.fetch_metadata(PURL, session)
        registry.fetch_metadata(PURL, session)

        assert len(source.calls) == 1

    def test_a_raising_source_is_not_cached_as_no_data(self):
        """The important one: a timeout or a 429 must not become a cached miss.

        If it did, one throttled run would suppress that package's enrichment
        for the whole miss TTL, silently producing less complete SBOMs.
        """
        source = RecordingSource(exc=requests.exceptions.Timeout("upstream slow"))
        registry = SourceRegistry()
        registry.register(source)
        session = requests.Session()

        assert registry.fetch_metadata(PURL, session) is None
        assert cache.get(source.name, PURL.to_string()) == (False, None)

        # A later run must therefore try again rather than trust the failure.
        registry.fetch_metadata(PURL, session)
        assert len(source.calls) == 2


class TestTransientFailuresAreNotPersisted:
    """A transient failure must never be remembered as "this package has no data".

    Most sources swallow timeouts and return None rather than raising, so
    without TransientSourceError the registry cannot tell a throttled response
    from a definitive miss -- and one rate-limited run would suppress that
    package's enrichment for the whole miss TTL.
    """

    def test_transient_error_is_not_cached(self):
        from sbomify_action._enrichment.exceptions import TransientSourceError

        source = RecordingSource(exc=TransientSourceError("HTTP 429"))
        registry = SourceRegistry()
        registry.register(source)
        session = requests.Session()

        assert registry.fetch_metadata(PURL, session) is None
        assert cache.get(source.name, PURL.to_string()) == (False, None)

        registry.fetch_metadata(PURL, session)
        assert len(source.calls) == 2, "a transient failure must not stop the next run retrying"

    @pytest.mark.parametrize("status", [429, 500, 503])
    def test_clearlydefined_raises_rather_than_returning_none(self, status):
        """These used to fall through and be cached as a miss."""
        from unittest.mock import Mock

        from sbomify_action._enrichment.exceptions import TransientSourceError
        from sbomify_action._enrichment.sources.clearlydefined import ClearlyDefinedSource, clear_cache

        clear_cache()
        session = Mock()
        response = Mock()
        response.status_code = status
        session.get.return_value = response

        with pytest.raises(TransientSourceError):
            ClearlyDefinedSource().fetch(PackageURL.from_string("pkg:pypi/requests@2.32.3"), session)

    def test_a_404_is_still_a_cacheable_miss(self):
        """Only transient failures are exempt; a genuine absence still caches."""
        from unittest.mock import Mock

        from sbomify_action._enrichment.sources.clearlydefined import ClearlyDefinedSource, clear_cache

        clear_cache()
        session = Mock()
        response = Mock()
        response.status_code = 404
        session.get.return_value = response

        assert ClearlyDefinedSource().fetch(PackageURL.from_string("pkg:pypi/nope@1.0"), session) is None


class TestCachesEverySource:
    """The cache is keyed on the source name, so it is not specific to any one."""

    def test_each_registered_source_is_cached_independently(self):
        # Distinct names so they get distinct cache keys.
        sources = [RecordingSource(result=_metadata(supplier=f"s{i}"), name=f"source-{i}") for i in range(3)]

        registry = SourceRegistry()
        for s in sources:
            registry.register(s)
        session = requests.Session()

        registry.fetch_metadata(PURL, session)
        registry.fetch_metadata(PURL, session)

        assert [len(s.calls) for s in sources] == [1, 1, 1], "every source should be served from cache the second time"
        assert cache.stats()["entries"] == 3

    def test_real_source_names_are_all_cacheable(self):
        """Smoke test over the names the enricher actually registers."""
        for name in (
            "license-db",
            "pypi.org",
            "deps.dev",
            "ecosyste.ms",
            "crates.io",
            "conan.io",
            "pub.dev",
            "sources.debian.org",
            "purl",
            "clearlydefined.io",
            "repology.org",
            "sbomify-lifecycle-db",
        ):
            cache.set(name, "pkg:generic/x@1", _metadata(supplier=name))
            hit, got = cache.get(name, "pkg:generic/x@1")
            assert hit and got.supplier == name


class TestStats:
    def test_counts_positive_and_negative_entries(self):
        cache.set("src", "a", _metadata())
        cache.set("src", "b", None)
        assert cache.stats() == {"entries": 2, "positive": 1, "negative": 1}

    def test_clear_empties_the_cache(self):
        cache.set("src", "a", _metadata())
        cache.clear()
        assert cache.stats()["entries"] == 0
