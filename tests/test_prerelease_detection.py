"""Recognising a prerelease, and telling sbomify about it.

sbomify's Release model carries ``is_prerelease`` as a first-class indexed
field and the client has accepted the argument since releases were added --
but the wrapper between them dropped it, so every release the action created
was recorded as final. An alpha tagged into a product release was indexed
alongside every genuine one.

The version strings below are real, from resolving 500 popular open source
projects to their releases.
"""

import pytest

from sbomify_action.release_version import is_prerelease


class TestSeparatedMarkers:
    """The obvious spelling, which nearly any check would catch."""

    @pytest.mark.parametrize(
        "version",
        [
            "v2.0.0-rc.1",
            "1.0.0-alpha",
            "2.3.4-beta.2",
            "3.14.0-110.0.dev",
            "v1.0.0-preview3",
            "1.2.3-SNAPSHOT",
            "v1.0.0-nightly",
            "4.0.0-canary.5",
            "1.0.0-milestone2",
        ],
    )
    def test_recognised(self, version):
        assert is_prerelease(version)

    def test_a_marker_in_build_metadata_does_not_count(self):
        """`2.0.0+preview` is version 2.0.0.

        This case was on the wrong side of the list when it was written. SemVer
        is explicit that build metadata is ignored for precedence, so a marker
        after the `+` describes the build, not the release. Reading it as a
        prerelease would demote a GA release over the contents of a field that
        is defined not to affect ordering.
        """
        assert not is_prerelease("2.0.0+preview")


class TestWeldedMarkers:
    """The spelling that gets missed, and the reason this exists.

    None of these contain a hyphen, and all of them sort above every stable
    release of their project under a numeric comparison.
    """

    @pytest.mark.parametrize(
        ("version", "project"),
        [
            ("6.1a1", "django"),
            ("6.1b1", "django"),
            ("6.1rc1", "django"),
            ("0.92RC0", "hadoop"),
            ("1.0m1", "a milestone build"),
        ],
    )
    def test_recognised(self, version, project):
        assert is_prerelease(version), f"{version} ({project}) read as a final release"


class TestFinalReleases:
    @pytest.mark.parametrize(
        "version",
        [
            "1.2.3",
            "v1.2.3",
            "26.7.0",
            "8.21.0",
            "4.2.17.Final",
            "3.2.1.RELEASE",
            "v26.7.3.19-stable",
            "2.0.4",
            "10.5.0",
            "1.53.1",
        ],
    )
    def test_not_a_prerelease(self, version):
        assert not is_prerelease(version)

    def test_a_trailing_letter_is_not_a_beta(self):
        """A revision suffix in several ecosystems; there is no number after it."""
        assert not is_prerelease("1.2.3b")
        assert not is_prerelease("1.0a")

    def test_a_hash_is_not_a_prerelease(self):
        """ "beta" and "dev" appear inside hex by chance; the separator rule holds."""
        assert not is_prerelease("0.0.0+gbetadead")
        assert not is_prerelease("sha256:deadbeef1234")

    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_nothing_to_judge(self, value):
        assert not is_prerelease(value)


class TestItReachesTheBackend:
    """The wrapper that dropped the argument is the actual bug."""

    def test_the_wrapper_passes_it_through(self, monkeypatch):
        from sbomify_action._processors import releases_api

        seen = {}

        class _Client:
            def create_release(self, product_id, version, *, is_prerelease=None):
                seen.update(product_id=product_id, version=version, is_prerelease=is_prerelease)
                return "rel_1"

        monkeypatch.setattr(releases_api, "_client", lambda *a, **k: _Client())

        releases_api.create_release("https://api", "tok", "prod_1", "6.1a1", is_prerelease=True)

        assert seen["is_prerelease"] is True

    def test_none_when_not_a_prerelease(self, monkeypatch):
        """None, not False -- the backend's own default should stand.

        The client omits the field entirely when it is None, so None is how a
        caller says nothing. False would assert "this is final" about every
        version we merely failed to read, which is a claim rather than an
        absence.
        """
        from sbomify_action._processors import releases_api

        seen = {}

        class _Client:
            def create_release(self, product_id, version, *, is_prerelease=None):
                seen["is_prerelease"] = is_prerelease
                return "rel_1"

        monkeypatch.setattr(releases_api, "_client", lambda *a, **k: _Client())

        releases_api.create_release("https://api", "tok", "prod_1", "1.2.3")

        assert seen["is_prerelease"] is None


class TestBuildMetadataIsNotAPrerelease:
    """SemVer build metadata is ignored for precedence, and is where hex lives.

    `\\d(?:a|b|rc|m)\\d+$` matched the tail of ordinary build metadata, so a GA
    release carrying a short SHA was recorded as a prerelease and vanished from
    any view filtering prereleases out -- the mirror of the bug this fixes.
    """

    @pytest.mark.parametrize(
        "version",
        [
            "1.0.0+build.9a12",
            "1.2.3+sha.1b234",
            "0.0.0+g1a234",
            "2.0.0+20130313144700",
            "1.0.0+exp.sha.5114f85",
        ],
    )
    def test_metadata_does_not_make_it_a_prerelease(self, version):
        assert not is_prerelease(version)

    def test_a_real_prerelease_with_metadata_still_counts(self):
        """The marker is in the release part, where it belongs."""
        assert is_prerelease("1.0.0-rc.1+build.9a12")
        assert is_prerelease("6.1a1+g1234")
