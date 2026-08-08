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
