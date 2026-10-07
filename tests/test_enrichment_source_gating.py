"""A source is worth a network call only if it can fill something missing.

The early stop needed *all three* core fields -- description, licenses,
supplier -- before it would stop asking. clearlydefined sits at priority 75
and can essentially only supply licences, so it was consulted whenever
`description` or `supplier` was missing, neither of which it can supply,
and its licence arrived redundant.

Across a 251-project run that filled the persistent cache with 1,178
clearlydefined entries, 1,020 of them holding real licence data, while
contributing zero fields to the finished SBOMs. Those lookups are not free:
a cold one runs to a 25-second upstream deadline, and five consecutive
failures latch the source off for the rest of the run -- so the wasted calls
were also spending the budget that should have been there when licences
really were missing.
"""

from typing import NoReturn

import requests
from packageurl import PackageURL

from sbomify_action._enrichment.metadata import NormalizedMetadata
from sbomify_action._enrichment.registry import SourceRegistry, _can_contribute, _still_missing


class _Source:
    def __init__(self, name, priority, returns, provides=None):
        self._name, self._priority, self._returns = name, priority, returns
        self._provides = provides
        self.called = False

    name = property(lambda self: self._name)
    priority = property(lambda self: self._priority)

    @property
    def provides(self):
        return self._provides

    def supports(self, _purl):
        return True

    def fetch(self, _purl, _session):
        self.called = True
        return self._returns


PURL = PackageURL.from_string("pkg:maven/org.example/thing@1.0.0")


def _registry(*sources):
    registry = SourceRegistry()
    for source in sources:
        registry.register(source)
    return registry


def test_a_licence_only_source_is_skipped_when_the_licence_is_present(monkeypatch):
    """The clearlydefined case: consulted for gaps it cannot fill."""
    monkeypatch.setattr("sbomify_action._enrichment.registry.cache.get", lambda *_a: (False, None))
    monkeypatch.setattr("sbomify_action._enrichment.registry.cache.set", lambda *_a: None)

    primary = _Source("deps.dev", 30, NormalizedMetadata(licenses=["MIT"], source="deps.dev"))
    licence_only = _Source(
        "clearlydefined.io", 75, NormalizedMetadata(licenses=["MIT"]), provides=frozenset({"licenses"})
    )

    _registry(primary, licence_only).fetch_metadata(PURL, requests.Session())

    assert primary.called
    assert not licence_only.called, "nothing it supplies was missing"


def test_it_is_still_consulted_when_the_licence_is_missing(monkeypatch):
    """Which is the case it exists for, and where the JVM needs it.

    36% of Java components in the survey carried no licence at all.
    """
    monkeypatch.setattr("sbomify_action._enrichment.registry.cache.get", lambda *_a: (False, None))
    monkeypatch.setattr("sbomify_action._enrichment.registry.cache.set", lambda *_a: None)

    primary = _Source("deps.dev", 30, NormalizedMetadata(description="a thing", source="deps.dev"))
    licence_only = _Source(
        "clearlydefined.io", 75, NormalizedMetadata(licenses=["Apache-2.0"]), provides=frozenset({"licenses"})
    )

    result = _registry(primary, licence_only).fetch_metadata(PURL, requests.Session())

    assert licence_only.called, "the licence was missing; this is exactly when to ask"
    assert result is not None and result.licenses == ["Apache-2.0"]


def test_a_source_that_declares_nothing_is_always_consulted(monkeypatch):
    """Undeclared means unknown, which must behave as it always did."""
    monkeypatch.setattr("sbomify_action._enrichment.registry.cache.get", lambda *_a: (False, None))
    monkeypatch.setattr("sbomify_action._enrichment.registry.cache.set", lambda *_a: None)

    primary = _Source("deps.dev", 30, NormalizedMetadata(licenses=["MIT"], source="deps.dev"))
    undeclared = _Source("ecosyste.ms", 40, NormalizedMetadata(description="x"))

    _registry(primary, undeclared).fetch_metadata(PURL, requests.Session())

    assert undeclared.called


def test_still_missing_reports_unfilled_fields():
    assert "licenses" in _still_missing(None)
    filled = NormalizedMetadata(licenses=["MIT"], description="d", supplier="s")
    missing = _still_missing(filled)
    assert "licenses" not in missing
    assert "homepage" in missing


def test_can_contribute_is_permissive_without_a_declaration():
    class Bare:
        name = "bare"

    assert _can_contribute(Bare(), {"licenses"})
    assert _can_contribute(Bare(), set())


class TestYoctoPurlsNeverReachARegistry:
    """A purl we invented has nowhere to be looked up.

    `_yocto/purl.py` mints `pkg:yocto/<recipe>@<version>` so a Yocto recipe has
    a stable identifier. No registry carries that type, and ecosyste.ms gated on
    a blocklist, so every recipe went out as an HTTP request that could only
    come back empty.

    Measured on the published core-image-sato-sdk reference image: 2,206 purls,
    478 distinct, 421 of them pkg:yocto. Cold, those 421 cost about twelve
    minutes and enriched nothing, and all of it runs before the SBOM is
    uploaded.
    """

    def test_ecosystems_declines_the_type_we_mint(self):
        from sbomify_action._enrichment.sources.ecosystems import EcosystemsSource
        from sbomify_action._yocto.purl import generate_yocto_purl

        purl = PackageURL.from_string(generate_yocto_purl("busybox", "1.36.1"))

        assert EcosystemsSource().supports(purl) is False

    def test_a_yocto_recipe_costs_no_http_request(self, monkeypatch, tmp_path):
        """The gate has to hold across every source, not just the one that had it.

        The claim is about the wire, not the answer. A local source may well
        have something to say about a recipe, now or later, so this records
        what was requested rather than asserting on what came back. Recording
        also survives a source that swallows the error: raising alone would let
        a suppressed exception read as a pass.
        """
        from sbomify_action._enrichment.enricher import Enricher
        from sbomify_action._yocto.purl import generate_yocto_purl

        monkeypatch.setenv("SBOMIFY_CACHE_DIR", str(tmp_path))

        requested: list[str] = []

        # `Session.get` and `Session.post` both go through `Session.request`,
        # so patching that one method catches every verb, and the URL is the
        # second positional argument rather than something to guess at.
        def record(_self: object, _method: object, url: object = None, **kwargs: object) -> NoReturn:
            requested.append(str(url if url is not None else kwargs.get("url")))
            raise RuntimeError("no network in this test")

        monkeypatch.setattr(requests.Session, "request", record)

        with Enricher() as enricher:
            enricher.fetch_metadata(generate_yocto_purl("openssl", "3.3.1"))

        assert requested == []

    def test_the_ecosystems_a_registry_does_carry_still_go(self):
        """The gate is for our own type, not a reason to stop enriching."""
        from sbomify_action._enrichment.sources.ecosystems import EcosystemsSource

        source = EcosystemsSource()
        for purl_str in ("pkg:pypi/requests@2.31.0", "pkg:npm/left-pad@1.3.0", "pkg:cargo/serde@1.0.0"):
            assert source.supports(PackageURL.from_string(purl_str)) is True
