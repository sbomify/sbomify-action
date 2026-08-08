"""An unharvested coordinate is an answer, not a sign the service is unwell.

ClearlyDefined never 404s. A coordinate it has not examined comes back as an
empty definition, which clearly-cached reports as ``harvested: false``. That
used to raise a TransientSourceError *and* count towards the circuit breaker,
so five sparsely-covered packages in a row disabled the source for the whole
run -- including for every well-covered package that came after.

Measured across 251 projects, twice: clearlydefined contributed zero fields,
while `dotnet/runtime` alone logged 278 "skipped after 5 consecutive" lines.
The service was healthy throughout -- probed directly, clearly-cached returns
a declared MIT licence for `nuget/Newtonsoft.Json@13.0.3` in under a second,
which is one of the packages that run failed to enrich.

The breaker still exists, and still trips on the things it is for: 5xx, 429,
timeouts, and bodies that cannot be read.
"""

from unittest.mock import Mock

import pytest
from packageurl import PackageURL

from sbomify_action._enrichment.exceptions import TransientSourceError
from sbomify_action._enrichment.sources import clearlydefined as cd
from sbomify_action._enrichment.sources.clearlydefined import (
    TRANSIENT_FAILURE_LIMIT,
    ClearlyDefinedSource,
    clear_cache,
)

UNHARVESTED = {"declared": None, "parties": [], "homepage": None, "source_url": None, "harvested": False}
HARVESTED = {
    "declared": "MIT",
    "parties": [],
    "homepage": None,
    "source_url": None,
    "harvested": True,
}


def _session(payload, status=200):
    session = Mock()
    response = Mock()
    response.status_code = status
    response.json.return_value = payload
    session.get.return_value = response
    return session


def _purl(n):
    return PackageURL.from_string(f"pkg:nuget/Package{n}@1.0.0")


def test_unharvested_coordinates_do_not_open_the_breaker():
    """Well past the limit, and the source is still willing to be asked."""
    clear_cache()
    session = _session(UNHARVESTED)
    source = ClearlyDefinedSource()

    for i in range(TRANSIENT_FAILURE_LIMIT * 3):
        with pytest.raises(TransientSourceError):
            source.fetch(_purl(i), session)

    assert cd._circuit_open is False
    assert cd._consecutive_failures == 0


def test_a_harvested_package_after_many_unharvested_ones_still_answers():
    """The case that cost a whole run.

    A .NET repository is mostly coordinates ClearlyDefined has never examined,
    with the occasional well-known package among them. Under the old counting
    the well-known one arrived after the breaker had already latched.
    """
    clear_cache()
    source = ClearlyDefinedSource()

    for i in range(TRANSIENT_FAILURE_LIMIT * 2):
        with pytest.raises(TransientSourceError):
            source.fetch(_purl(i), _session(UNHARVESTED))

    result = source.fetch(PackageURL.from_string("pkg:nuget/Newtonsoft.Json@13.0.3"), _session(HARVESTED))

    assert result is not None
    assert result.licenses == ["MIT"]


@pytest.mark.parametrize("status", [429, 500, 503])
def test_the_breaker_still_trips_on_service_failures(status):
    """What the breaker is actually for is unchanged."""
    clear_cache()
    session = _session({}, status=status)
    source = ClearlyDefinedSource()

    for i in range(TRANSIENT_FAILURE_LIMIT):
        with pytest.raises(TransientSourceError):
            source.fetch(_purl(i), session)

    assert cd._circuit_open is True


def test_a_body_that_cannot_be_read_still_counts():
    """A service answering with nonsense is worth backing off from.

    Distinct from an unharvested coordinate, which is a coherent answer that
    happens to say "not yet".
    """
    clear_cache()
    malformed = {"declared": {"unexpected": "shape"}, "harvested": True}
    source = ClearlyDefinedSource()

    for i in range(TRANSIENT_FAILURE_LIMIT):
        with pytest.raises(TransientSourceError):
            source.fetch(_purl(i), _session(malformed))

    assert cd._circuit_open is True


def test_a_404_still_clears_the_streak():
    """A definite absence is an answer, so it counts as the service working."""
    clear_cache()
    source = ClearlyDefinedSource()

    for i in range(TRANSIENT_FAILURE_LIMIT - 1):
        with pytest.raises(TransientSourceError):
            source.fetch(_purl(i), _session({}, status=503))
    assert cd._consecutive_failures == TRANSIENT_FAILURE_LIMIT - 1

    assert source.fetch(PackageURL.from_string("pkg:nuget/Gone@1.0"), _session(None, status=404)) is None

    assert cd._consecutive_failures == 0
    assert cd._circuit_open is False


def test_an_unharvested_answer_clears_an_earlier_failure_streak():
    """Responding correctly is evidence of health, harvested or not.

    Otherwise a run of real failures stays armed while the service is
    demonstrably answering again, and the next single failure trips a breaker
    that should have been reset.
    """
    clear_cache()
    source = ClearlyDefinedSource()

    for i in range(TRANSIENT_FAILURE_LIMIT - 1):
        with pytest.raises(TransientSourceError):
            source.fetch(_purl(i), _session({}, status=503))
    assert cd._consecutive_failures == TRANSIENT_FAILURE_LIMIT - 1

    with pytest.raises(TransientSourceError):
        source.fetch(PackageURL.from_string("pkg:nuget/Fresh@1.0"), _session(UNHARVESTED))

    assert cd._consecutive_failures == 0
    assert cd._circuit_open is False


@pytest.mark.parametrize("bad", ["false", 0, 1, None, []])
def test_a_non_boolean_harvested_flag_is_malformed_not_unharvested(bad):
    """It says the body is unreadable, which is a service problem.

    Classifying it as "not yet harvested" would exempt it from the breaker now
    that unharvested coordinates do not count, and would report a garbled
    response as a coverage gap.
    """
    clear_cache()
    payload = dict(HARVESTED, harvested=bad)
    source = ClearlyDefinedSource()

    for i in range(TRANSIENT_FAILURE_LIMIT):
        with pytest.raises(TransientSourceError) as excinfo:
            source.fetch(_purl(i), _session(payload))
        assert "not yet harvested" not in str(excinfo.value)

    assert cd._circuit_open is True
