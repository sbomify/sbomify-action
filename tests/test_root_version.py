"""F6: a root version a consumer can actually use.

Measured over 500 open source projects, only 27% of SBOMs carried a root
version that meant anything: 35% said "latest", 22% were a bare content hash
and 14% had nothing at all.
"""

import subprocess

import pytest

from sbomify_action._augmentation.root_version import (
    is_placeholder_version,
    resolve_root_version,
)

CI_VARS = (
    "GITHUB_REF_TYPE",
    "GITHUB_REF_NAME",
    "GITHUB_REF",
    "GITHUB_SHA",
    "CI_COMMIT_TAG",
    "CI_COMMIT_SHA",
    "BITBUCKET_TAG",
    "BITBUCKET_COMMIT",
)


@pytest.fixture(autouse=True)
def _no_ambient_ci(monkeypatch):
    """These tests run in CI, whose own variables would otherwise answer."""
    for name in CI_VARS:
        monkeypatch.delenv(name, raising=False)


def _repo(tmp_path, *, tag: str | None = None):
    """A real git repository, because the code shells out to a real git."""
    run = lambda *a: subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("config", "user.email", "t@example.invalid")
    run("config", "user.name", "Test")
    # Signing is on globally for this project's authors, and a test repo has
    # no key to sign with -- `git tag` exits 128 rather than creating one.
    run("config", "commit.gpgsign", "false")
    run("config", "tag.gpgSign", "false")
    (tmp_path / "f").write_text("x")
    run("add", "f")
    run("commit", "-qm", "one")
    if tag:
        run("tag", tag)
    return tmp_path


class TestPlaceholderDetection:
    @pytest.mark.parametrize("value", ["latest", "LATEST", "unknown", "none", "n/a", "", "  ", None, "0.0.0"])
    def test_values_that_say_nothing(self, value):
        assert is_placeholder_version(value)

    def test_a_content_hash_says_nothing_either(self):
        """syft names a directory by hashing it: stable, and meaningless."""
        assert is_placeholder_version("sha256:" + "a" * 64)
        assert is_placeholder_version("b" * 40)

    @pytest.mark.parametrize("value", ["1.2.3", "v1.2.3", "22.2.0-next.1", "15.2.0", "2024.1"])
    def test_real_versions_are_left_alone(self, value):
        assert not is_placeholder_version(value)


class TestResolution:
    def test_a_tag_is_used_verbatim(self, tmp_path):
        """If the project published a version, there is nothing to invent."""
        repo = _repo(tmp_path, tag="v1.2.3")
        assert resolve_root_version(repo) == "v1.2.3"

    def test_an_untagged_commit_becomes_a_traceable_non_release(self, tmp_path):
        repo = _repo(tmp_path)
        got = resolve_root_version(repo)
        assert got is not None
        assert got.startswith("0.0.0+g"), got
        assert len(got) == len("0.0.0+g") + 8

    def test_the_derived_version_names_the_actual_commit(self, tmp_path):
        repo = _repo(tmp_path)
        head = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()

        assert resolve_root_version(repo) == f"0.0.0+g{head[:8]}"

    def test_a_ci_tag_wins_over_the_checkout(self, tmp_path, monkeypatch):
        """A shallow CI clone often has no tags fetched, but CI knows."""
        repo = _repo(tmp_path, tag="v9.9.9")
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REF_NAME", "v1.0.0")

        assert resolve_root_version(repo) == "v1.0.0"

    @pytest.mark.parametrize(
        ("env", "value"),
        [("CI_COMMIT_TAG", "v2.0.0"), ("BITBUCKET_TAG", "v3.0.0")],
    )
    def test_gitlab_and_bitbucket_tags(self, monkeypatch, env, value):
        """Both set these only on a tag build, so presence is the signal."""
        monkeypatch.setenv(env, value)
        assert resolve_root_version(None) == value

    def test_refs_tags_prefix_is_stripped(self, monkeypatch):
        monkeypatch.setenv("GITHUB_REF", "refs/tags/v4.5.6")
        assert resolve_root_version(None) == "v4.5.6"

    def test_a_branch_ref_is_not_a_tag(self, monkeypatch):
        """refs/heads/main must not become the version."""
        monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
        monkeypatch.setenv("GITHUB_SHA", "abcdef1234567890" * 2)

        assert resolve_root_version(None) == "0.0.0+gabcdef12"

    def test_nothing_knowable_returns_none(self, tmp_path):
        """A tarball with no .git and no CI. The caller warns instead."""
        assert resolve_root_version(tmp_path) is None

    def test_a_missing_directory_is_not_an_error(self):
        assert resolve_root_version("/nonexistent/path/anywhere") is None

    def test_no_directory_at_all_is_not_an_error(self):
        """A container image has no checkout to ask."""
        assert resolve_root_version(None) is None

    def test_a_git_that_cannot_run_is_not_an_error(self, tmp_path, monkeypatch):
        """A checkout owned by another uid is the normal case in a container."""

        def boom(*_a, **_k):
            raise OSError("git missing")

        monkeypatch.setattr(subprocess, "run", boom)
        assert resolve_root_version(tmp_path) is None
