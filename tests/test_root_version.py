"""F6: a root version a consumer can actually use.

Measured over 500 open source projects, only 27% of SBOMs carried a root
version that meant anything: 35% said "latest", 22% were a bare content hash
and 14% had nothing at all.
"""

import subprocess

import pytest

from sbomify_action._augmentation import root_version
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
    tmp_path.mkdir(parents=True, exist_ok=True)
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


class TestAHostileCheckoutCannotRunCode:
    """The checkout is the subject of the scan, so it is not trusted input.

    git reads the repository's own .git/config, and core.fsmonitor names a
    command git executes. The honest position, measured rather than asserted:
    the two commands this module runs do *not* refresh the index and so never
    invoke it. The guard exists because `git describe --dirty` -- one plausible
    edit away -- does refresh the index, and would turn a version lookup into
    code execution with nothing else changing.

    So these tests pin the guard itself, and prove on a command that *does*
    refresh the index that the guard is what stops it.
    """

    @staticmethod
    def _armed(tmp_path):
        """A repository whose own config runs a payload on index refresh."""
        repo = _repo(tmp_path / "repo")
        canary = tmp_path / "PWNED"
        payload = tmp_path / "payload.sh"
        payload.write_text(f"#!/bin/sh\ntouch {canary}\nexit 0\n")
        payload.chmod(0o755)
        subprocess.run(
            ["git", "-C", str(repo), "config", "core.fsmonitor", str(payload)],
            check=True,
            capture_output=True,
        )
        return repo, canary

    def test_the_payload_really_does_fire_without_the_guard(self, tmp_path):
        """Establishes the threat is real before asserting we stop it.

        Without this, the test below would pass just as happily against a
        payload that never runs under any circumstances.
        """
        repo, canary = self._armed(tmp_path)

        subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True)

        assert canary.exists(), "the scenario is not a threat, so the next test proves nothing"

    def test_the_guard_stops_it_on_a_command_that_refreshes_the_index(self, tmp_path):
        repo, canary = self._armed(tmp_path)

        root_version._git(repo, "status", "--porcelain")

        assert not canary.exists(), "the repository's own config executed a command"

    def test_every_git_call_carries_the_guard(self, tmp_path, monkeypatch):
        """The two commands used today are safe; this is what keeps them so."""
        seen: list[list[str]] = []

        def capture(cmd, **kwargs):
            seen.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(subprocess, "run", capture)
        resolve_root_version(tmp_path)

        assert seen, "no git call was made"
        for cmd in seen:
            assert "core.fsmonitor=" in cmd, cmd
            assert "--no-optional-locks" in cmd, cmd

    def test_the_version_is_still_derived_from_such_a_repo(self, tmp_path):
        """Hardening must not cost the answer -- degrading to None would do."""
        repo, _ = self._armed(tmp_path)

        got = resolve_root_version(repo)

        assert got is not None and got.startswith("0.0.0+g")

    def test_no_index_lock_is_left_in_someone_elses_tree(self, tmp_path):
        repo = _repo(tmp_path / "repo")

        resolve_root_version(repo)

        assert not (repo / ".git" / "index.lock").exists()
