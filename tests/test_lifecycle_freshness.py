"""Structural checks on the hand-maintained CLE lifecycle tables.

These run offline on every CI run. The monthly lifecycle-staleness workflow adds
a network check for releases we have not noticed yet; everything here is a fact
that must hold regardless of what upstream says, so it belongs in the normal
suite where it fails fast.

The point is that stale lifecycle data is otherwise invisible: get_distro_lifecycle
returns None for an unknown release and enrich_os_component just adds no CLE
properties, so a distro we have never heard of produces a quietly emptier SBOM
rather than an error.
"""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

import pytest
import requests
from packageurl import PackageURL

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbomify_action._enrichment.lifecycle_data import (  # noqa: E402
    DISTRO_LIFECYCLE,
    PACKAGE_LIFECYCLE,
)
from sbomify_action._enrichment.sources.lifecycle import (  # noqa: E402
    LifecycleSource,
    clear_cache,
)
from scripts.check_lifecycle_staleness import (  # noqa: E402
    check_local_invariants,
    parse_lifecycle_date,
)


class TestLifecycleInvariants:
    """The invariant suite, as a single assertion with a readable failure."""

    def test_no_invariant_failures(self):
        problems = check_local_invariants()
        assert not problems, "Lifecycle data invariants failed:\n" + "\n".join(f"  - {p}" for p in problems)

    def test_every_distro_has_a_supported_release(self):
        """Catch a distro whose every tracked release has expired.

        This is the openSUSE Leap failure: the table sat at 15.5/15.6 long after
        both had gone EOL, so every openSUSE user got lifecycle data saying they
        were unsupported no matter which release they actually ran.
        """
        today = date.today()
        stale = []
        for name, cycles in DISTRO_LIFECYCLE.items():
            if name == "wolfi":
                continue  # rolling release, deliberately has no cycles
            live = any(
                dates.get("end_of_life") is None or (parse_lifecycle_date(dates["end_of_life"]) or today) >= today
                for dates in cycles.values()
            )
            if not live:
                stale.append(name)
        assert not stale, f"Distros with no non-EOL release tracked: {', '.join(sorted(stale))}"


class TestDateFormats:
    """Every date must be one of the three formats the module documents."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("2026-04-23", date(2026, 4, 23)),
            ("2026-04", date(2026, 4, 30)),  # partial dates resolve to the last day
            ("2026-12", date(2026, 12, 31)),
            ("2027-Q3", date(2027, 9, 30)),
            ("2027-Q4", date(2027, 12, 31)),
        ],
    )
    def test_parses_supported_formats(self, value, expected):
        assert parse_lifecycle_date(value) == expected

    @pytest.mark.parametrize("value", ["", "2026", "not-a-date", "2026-13", "2026-Q5", "26-04-23"])
    def test_rejects_unsupported_formats(self, value):
        assert parse_lifecycle_date(value) is None

    def test_all_distro_dates_parse(self):
        bad = [
            f"{name} {cycle} {field}={dates[field]!r}"
            for name, cycles in DISTRO_LIFECYCLE.items()
            for cycle, dates in cycles.items()
            for field in ("release_date", "end_of_support", "end_of_life")
            if dates.get(field) is not None and parse_lifecycle_date(dates[field]) is None
        ]
        assert not bad, "Unparseable distro dates: " + "; ".join(bad)

    def test_all_package_dates_parse(self):
        bad = [
            f"{name} {cycle} {field}={dates[field]!r}"
            for name, entry in PACKAGE_LIFECYCLE.items()
            for cycle, dates in entry.get("cycles", {}).items()
            for field in ("release_date", "end_of_support", "end_of_life")
            if dates.get(field) is not None and parse_lifecycle_date(dates[field]) is None
        ]
        assert not bad, "Unparseable package dates: " + "; ".join(bad)


class TestPackageMatchingSafety:
    """Guard the name_patterns against matching things they should not.

    A pattern that is too broad is worse than a missing entry: it attaches a
    runtime's lifecycle dates to an unrelated library, so the SBOM asserts an
    EOL date that is simply wrong.

    These go through LifecycleSource.fetch() with a real PackageURL rather than
    the get_package_lifecycle() helper, because that is the path enrichment
    takes and it does not match identically: the source also tests the
    namespace (so pkg:composer/laravel/framework matches on "laravel") and
    applies the purl_types filter unconditionally, where the helper skips that
    filter whenever it is handed no type. A helper-level test can therefore
    pass while real enrichment matches differently.
    """

    # Distros package thousands of npm libraries as node-<name> (Debian) or
    # nodejs-<name> (Fedora/RHEL); their versions are library versions, not Node
    # runtime versions. yargs really is on 18.x and commander on 14.x, which
    # collide head-on with live Node cycles -- a bare node-* glob would date
    # them as EOL Node releases.
    NAME_COLLISIONS = [
        "pkg:deb/debian/node-tar@6.1.0",
        "pkg:deb/debian/node-gyp@9.0.0",
        "pkg:deb/debian/node-yargs@18.0.0",
        "pkg:deb/debian/node-commander@14.0.1",
        "pkg:rpm/fedora/nodejs-mocha@10.2.0",
        "pkg:rpm/fedora/nodejs-yargs@18.0.0",
        # Dart/Flutter packages on pub are not the SDKs.
        "pkg:pub/dartdoc@8.0.0",
    ]

    @staticmethod
    def _fetch(purl_string: str):
        clear_cache()
        return LifecycleSource().fetch(PackageURL.from_string(purl_string), requests.Session())

    @pytest.mark.parametrize("purl_string", NAME_COLLISIONS)
    def test_patterns_do_not_match_unrelated_packages(self, purl_string):
        # supports() is the matching step itself, so this holds whatever the
        # version is -- a name that must never match cannot start matching just
        # because a new cycle gets added to the table.
        assert not LifecycleSource().supports(PackageURL.from_string(purl_string)), (
            f"{purl_string} matched a runtime lifecycle entry's name_patterns"
        )

    @pytest.mark.parametrize(
        "purl_string",
        [
            *NAME_COLLISIONS,
            # OpenStack Swift shares its name with the Swift language, so it
            # does match the entry; it stays dateless only because its 2.x
            # versions do not overlap Swift's cycles. See the warning on the
            # swift entry about adding 2.x cycles to it.
            "pkg:pypi/swift@2.35.0",
        ],
    )
    def test_unrelated_packages_get_no_dates(self, purl_string):
        assert self._fetch(purl_string) is None, f"{purl_string} wrongly picked up a runtime lifecycle entry"

    @pytest.mark.parametrize(
        "purl_string,expected_eol",
        [
            ("pkg:deb/debian/nodejs@22.11.0", "2027-04-30"),
            ("pkg:apk/alpine/node@20.1.0", "2026-04-30"),
            ("pkg:deb/ubuntu/libnode115@22.11.0", "2027-04-30"),
            ("pkg:deb/ubuntu/python3.12@3.12.7", "2028-10-31"),
            # The Dart SDK as distros ship it; pkg:pub/... is a Dart package.
            ("pkg:apk/alpine/dart@3.11.0", "2026-05-08"),
        ],
    )
    def test_matches_the_runtimes_it_should(self, purl_string, expected_eol):
        metadata = self._fetch(purl_string)
        assert metadata is not None, f"{purl_string} should have matched"
        assert metadata.cle_eol == expected_eol
