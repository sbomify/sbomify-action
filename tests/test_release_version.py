"""Turning a release tag into a version a registry would recognise.

Every accepted case here is a real tag from a real project, taken from
resolving 500 popular open source repositories to their releases. That is the
only way to discover that Hadoop tags `rel/release-3.5.0` and curl writes its
version with underscores.
"""

import pytest

from sbomify_action.release_version import (
    names_another_package,
    normalize_release_version,
    tag_from_ci,
    version_from_release_tag,
)

CI_VARS = ("GITHUB_REF_TYPE", "GITHUB_REF_NAME", "GITHUB_REF", "CI_COMMIT_TAG", "BITBUCKET_TAG")


@pytest.fixture(autouse=True)
def _no_ambient_ci(monkeypatch):
    """These tests run in CI, whose own variables would otherwise answer."""
    for name in CI_VARS:
        monkeypatch.delenv(name, raising=False)


class TestReadingTheTag:
    def test_a_tag_build(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REF_NAME", "v1.2.3")
        assert tag_from_ci() == "v1.2.3"

    def test_a_branch_build_has_no_released_version(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REF_TYPE", "branch")
        monkeypatch.setenv("GITHUB_REF_NAME", "main")
        assert tag_from_ci() is None

    def test_refs_tags_is_understood(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REF", "refs/tags/v4.5.6")
        assert tag_from_ci() == "v4.5.6"

    def test_refs_heads_is_not_a_tag(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
        assert tag_from_ci() is None

    @pytest.mark.parametrize("var", ["CI_COMMIT_TAG", "BITBUCKET_TAG"])
    def test_gitlab_and_bitbucket(self, monkeypatch, var):
        monkeypatch.setenv(var, "v7.8.9")
        assert tag_from_ci() == "v7.8.9"

    def test_nothing_set(self):
        assert tag_from_ci() is None


class TestNormalising:
    @pytest.mark.parametrize(
        ("tag", "repo", "expected"),
        [
            # Already clean: the common case, 403 of 446 projects.
            ("v1.2.3", "requests", "1.2.3"),
            ("1.2.3", "requests", "1.2.3"),
            ("v26.7.0", "sbomify-action", "26.7.0"),
            # Project name in front of the version.
            ("curl-8_21_0", "curl", "8.21.0"),
            ("camel-4.22.0", "camel", "4.22.0"),
            ("clojure-1.12.5", "clojure", "1.12.5"),
            ("OTP-29.0.5", "otp", "29.0.5"),
            ("dio_v5.11.0", "dio", "5.11.0"),
            ("http-v1.5.0", "http", "1.5.0"),
            # npm-style scoping.
            ("svelte@5.56.8", "svelte", "5.56.8"),
            ("astro@7.2.0", "astro", "7.2.0"),
            # Generic prefixes, with and without a path.
            ("release-3.9.5", "zookeeper", "3.9.5"),
            ("rel/release-3.5.0", "hadoop", "3.5.0"),
            ("releases/lucene/10.5.0", "lucene", "10.5.0"),
            # A finality suffix is part of the version, not noise.
            ("netty-4.2.17.Final", "netty", "4.2.17.Final"),
            ("3.2.1.RELEASE", "spring-framework", "3.2.1.RELEASE"),
            # A qualifier the project chose is preserved rather than trimmed.
            ("v26.7.3.19-stable", "clickhouse", "26.7.3.19-stable"),
        ],
    )
    def test_real_tags(self, tag, repo, expected):
        assert normalize_release_version(tag, repo) == expected

    def test_a_tag_with_no_version_gives_nothing(self):
        """So the caller falls back to the tag rather than to an invention."""
        assert normalize_release_version("stable", "django") is None
        assert normalize_release_version("", "django") is None

    def test_the_repo_name_is_optional(self):
        """Generic prefixes still reduce without knowing the project."""
        assert normalize_release_version("v1.2.3") == "1.2.3"
        assert normalize_release_version("release-3.9.5") == "3.9.5"


class TestATagThatNamesSomethingElse:
    @pytest.mark.parametrize(
        ("tag", "repo"),
        [
            ("meta-v1.3.0", "sdk"),
            ("xdg_directories-v1.1.0", "packages"),
            ("web_socket_channel-v3.0.3", "http"),
            ("sea-orm-cli@2.0.1", "sea-orm"),
            ("desktop-v0.60.99", "posthog"),
        ],
    )
    def test_recognised(self, tag, repo):
        assert names_another_package(tag, repo)

    @pytest.mark.parametrize(
        ("tag", "repo"),
        [
            ("curl-8_21_0", "curl"),
            ("OTP-29.0.5", "otp"),
            ("release-3.9.5", "zookeeper"),
            ("rel/release-3.5.0", "hadoop"),
            ("v1.2.3", "anything"),
            ("1.2.3", "anything"),
        ],
    )
    def test_not_another_package(self, tag, repo):
        assert not names_another_package(tag, repo)

    def test_unknown_repo_name_never_accuses(self):
        assert not names_another_package("meta-v1.3.0", None)


class TestTheDecision:
    def test_a_branch_build_yields_nothing(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REF_TYPE", "branch")
        assert version_from_release_tag("curl", normalize=True) == (None, None)

    def test_normalisation_off_keeps_the_tag_verbatim(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REF_NAME", "curl-8_21_0")

        version, warning = version_from_release_tag("curl", normalize=False)

        assert version == "curl-8_21_0"
        assert warning is None

    def test_normalisation_on(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REF_NAME", "curl-8_21_0")

        assert version_from_release_tag("curl", normalize=True) == ("8.21.0", None)

    def test_a_foreign_tag_warns_and_changes_nothing(self, monkeypatch):
        """Stamping meta's version onto the Dart SDK would be worse than none."""
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REF_NAME", "meta-v1.3.0")

        version, warning = version_from_release_tag("sdk", normalize=True)

        assert version is None
        assert warning is not None
        assert "different package" in warning
        assert "COMPONENT_VERSION" in warning

    def test_a_foreign_tag_warns_even_without_normalisation(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REF_NAME", "meta-v1.3.0")

        version, warning = version_from_release_tag("sdk", normalize=False)

        assert version is None and warning is not None

    def test_an_unparseable_tag_falls_back_to_itself(self, monkeypatch):
        """Never invent: if there is no version in it, use what the project wrote."""
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REF_NAME", "milestone")

        version, warning = version_from_release_tag(None, normalize=True)

        assert version == "milestone"
        assert warning is None


class TestAConfiguredVersionThatIsTheTag:
    """The wizard's workflow strips refs/tags/ into COMPONENT_VERSION, so the
    version arrives *configured* and every judgement about the tag would
    otherwise be skipped.

    An earlier version of this called normalize_release_version directly on
    that path and turned `meta-v1.3.0` -- a per-package tag in dart-lang/sdk --
    into a clean `1.3.0` stamped on the whole repository, with no warning.
    Laundering a foreign tag into something authoritative-looking is worse
    than leaving it alone.
    """

    def test_a_foreign_tag_is_refused_not_laundered(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REF_NAME", "meta-v1.3.0")

        version, warning = version_from_release_tag("sdk", normalize=True)

        assert version is None, "a per-package tag must not become the repo's version"
        assert warning is not None
        # The dangerous outcome specifically: a clean-looking version.
        assert normalize_release_version("meta-v1.3.0", "sdk") == "1.3.0"
        assert version != "1.3.0", "normalisation must not run on a foreign tag"

    def test_the_project_s_own_tag_still_normalises(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REF_NAME", "curl-8_21_0")

        assert version_from_release_tag("curl", normalize=True) == ("8.21.0", None)


class TestProjectNamesContainingDigits:
    """A digit in the project's name used to split the tag in the wrong place.

    `_TAG`'s non-greedy prefix stopped at the first digit *anywhere*, so
    bzip2-1.0.8 parsed as prefix "bzip", core "2", suffix "-1.0.8". That
    normalised to "2-1.0.8" and, because "bzip" is not "bzip2", was refused as
    a release of a different package -- on the project's own tag, and with
    normalisation off, since the refusal path runs either way.
    """

    @pytest.mark.parametrize(
        ("tag", "repo", "expected"),
        [
            ("bzip2-1.0.8", "bzip2", "1.0.8"),
            ("log4j-2.25.0", "log4j", "2.25.0"),
            ("libxml2-2.13.0", "libxml2", "2.13.0"),
            ("sqlite3-3.45.0", "sqlite3", "3.45.0"),
            ("s2n-tls-1.5.0", "s2n-tls", "1.5.0"),
            ("socket.io@4.8.3", "socket.io", "4.8.3"),
        ],
    )
    def test_the_version_is_the_version(self, tag, repo, expected):
        assert normalize_release_version(tag, repo) == expected

    @pytest.mark.parametrize(
        ("tag", "repo"),
        [
            ("bzip2-1.0.8", "bzip2"),
            ("log4j-2.25.0", "log4j"),
            ("sqlite3-3.45.0", "sqlite3"),
        ],
    )
    def test_not_mistaken_for_another_package(self, tag, repo):
        assert not names_another_package(tag, repo)


class TestPathScopedTags:
    """Taking only the last path segment let monorepo tags past the guard.

    `otelhttp/v1.20.0` is the Go multi-module convention, not a corner case,
    and it looked like a bare version with no prefix at all.
    """

    @pytest.mark.parametrize(
        ("tag", "repo"),
        [
            ("otelhttp/v1.20.0", "opentelemetry-go-contrib"),
            ("packages/meta/v1.3.0", "sdk"),
            ("bridges/otelslog/v0.5.0", "opentelemetry-go-contrib"),
        ],
    )
    def test_a_submodule_tag_is_another_package(self, tag, repo):
        assert names_another_package(tag, repo)

    @pytest.mark.parametrize(
        ("tag", "repo"),
        [
            ("rel/release-3.5.0", "hadoop"),
            ("releases/lucene/10.5.0", "lucene"),
            ("gson-parent-2.9.1", "gson"),
        ],
    )
    def test_a_generic_or_own_path_is_not(self, tag, repo):
        assert not names_another_package(tag, repo)
