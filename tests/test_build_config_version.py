"""How build_config decides the component version.

The decision itself is tested in test_release_version.py; this covers the
wiring, which is where the behaviour a user actually sees is assembled: when
the tag is consulted at all, when a configured value is left alone, and what
the audit trail is told.

Every test clears the CI tag variables. Without that these would pass or fail
depending on whether the suite itself was run from a tag-triggered build,
which is exactly the kind of ambient dependency that makes a green run
meaningless.
"""

import pytest

from sbomify_action.cli.main import build_config

CI_VARS = (
    "GITHUB_REF_TYPE",
    "GITHUB_REF_NAME",
    "GITHUB_REF",
    "GITHUB_REPOSITORY",
    "CI_COMMIT_TAG",
    "CI_PROJECT_PATH",
    "BITBUCKET_TAG",
    "BITBUCKET_REPO_FULL_NAME",
    "VERSION_FROM_RELEASE_TAG",
    "NORMALIZE_VERSION",
    "SBOM_VERSION",
)


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    for name in CI_VARS:
        monkeypatch.delenv(name, raising=False)


def _config(tmp_path, **kwargs):
    lock = tmp_path / "uv.lock"
    lock.write_text("")
    defaults = {
        "token": "tok",
        "component_id": "comp-1",
        "lock_file": str(lock),
        "output_file": str(tmp_path / "out.json"),
        "upload": False,
    }
    defaults.update(kwargs)
    return build_config(**defaults)


def _on_tag(monkeypatch, tag: str, repo: str = "acme/widget"):
    monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
    monkeypatch.setenv("GITHUB_REF_NAME", tag)
    monkeypatch.setenv("GITHUB_REPOSITORY", repo)


class TestDerivationIsOptIn:
    def test_a_tag_build_does_nothing_by_default(self, tmp_path, monkeypatch):
        """The default must not change any existing user's version."""
        _on_tag(monkeypatch, "v1.2.3")

        config = _config(tmp_path)

        assert config.component_version is None
        assert config.component_version_source is None

    def test_opted_in_uses_the_tag(self, tmp_path, monkeypatch):
        _on_tag(monkeypatch, "v1.2.3")
        monkeypatch.setenv("VERSION_FROM_RELEASE_TAG", "true")

        config = _config(tmp_path)

        assert config.component_version == "v1.2.3"
        assert config.component_version_source == "release tag"

    def test_opted_in_on_a_branch_build_still_yields_nothing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GITHUB_REF_TYPE", "branch")
        monkeypatch.setenv("GITHUB_REF_NAME", "main")
        monkeypatch.setenv("VERSION_FROM_RELEASE_TAG", "true")

        config = _config(tmp_path)

        assert config.component_version is None


class TestNormalization:
    def test_off_by_default(self, tmp_path, monkeypatch):
        _on_tag(monkeypatch, "curl-8_21_0", repo="curl/curl")
        monkeypatch.setenv("VERSION_FROM_RELEASE_TAG", "true")

        config = _config(tmp_path)

        assert config.component_version == "curl-8_21_0"

    def test_on(self, tmp_path, monkeypatch):
        _on_tag(monkeypatch, "curl-8_21_0", repo="curl/curl")
        monkeypatch.setenv("VERSION_FROM_RELEASE_TAG", "true")
        monkeypatch.setenv("NORMALIZE_VERSION", "true")

        config = _config(tmp_path)

        assert config.component_version == "8.21.0"
        assert "normalized" in (config.component_version_source or "")

    def test_a_configured_version_that_is_the_tag_is_normalized(self, tmp_path, monkeypatch):
        """The wizard's workflow sets COMPONENT_VERSION from the tag."""
        _on_tag(monkeypatch, "curl-8_21_0", repo="curl/curl")
        monkeypatch.setenv("NORMALIZE_VERSION", "true")

        config = _config(tmp_path, component_version="curl-8_21_0")

        assert config.component_version == "8.21.0"

    def test_a_configured_version_that_is_not_the_tag_is_untouched(self, tmp_path, monkeypatch):
        """A deliberate label is not ours to rewrite, however tag-shaped."""
        _on_tag(monkeypatch, "v9.9.9", repo="acme/widget")
        monkeypatch.setenv("NORMALIZE_VERSION", "true")

        config = _config(tmp_path, component_version="my-build-42")

        assert config.component_version == "my-build-42"
        assert config.component_version_source is None


class TestAForeignTag:
    def test_is_not_used(self, tmp_path, monkeypatch):
        _on_tag(monkeypatch, "meta-v1.3.0", repo="dart-lang/sdk")
        monkeypatch.setenv("VERSION_FROM_RELEASE_TAG", "true")

        config = _config(tmp_path)

        assert config.component_version is None

    def test_is_not_laundered_when_configured(self, tmp_path, monkeypatch):
        """The bug this guards: normalization made a foreign tag look clean.

        meta-v1.3.0 became 1.3.0 with no warning -- one package's version
        stamped on the whole repository, in a form that looks authoritative.
        """
        _on_tag(monkeypatch, "meta-v1.3.0", repo="dart-lang/sdk")
        monkeypatch.setenv("NORMALIZE_VERSION", "true")

        config = _config(tmp_path, component_version="meta-v1.3.0")

        assert config.component_version == "meta-v1.3.0"
        assert config.component_version != "1.3.0"


class TestProductRelease:
    def test_normalized_with_the_component_version(self, tmp_path, monkeypatch):
        """A release and the SBOM attached to it should agree on the version."""
        _on_tag(monkeypatch, "curl-8_21_0", repo="curl/curl")
        monkeypatch.setenv("NORMALIZE_VERSION", "true")

        config = _config(
            tmp_path,
            component_version="curl-8_21_0",
            product_releases='["prod-1:curl-8_21_0"]',
        )

        assert config.product_releases == ["prod-1:8.21.0"]
        assert config.component_version == "8.21.0"

    def test_left_alone_without_normalization(self, tmp_path, monkeypatch):
        _on_tag(monkeypatch, "curl-8_21_0", repo="curl/curl")

        config = _config(tmp_path, product_releases='["prod-1:curl-8_21_0"]')

        assert config.product_releases == ["prod-1:curl-8_21_0"]

    def test_a_deliberate_release_name_is_not_rewritten(self, tmp_path, monkeypatch):
        _on_tag(monkeypatch, "curl-8_21_0", repo="curl/curl")
        monkeypatch.setenv("NORMALIZE_VERSION", "true")

        config = _config(tmp_path, product_releases='["prod-1:christmas-build"]')

        assert config.product_releases == ["prod-1:christmas-build"]
