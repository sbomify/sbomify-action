"""The release digest pin: scripts/pin_release_image.sh writes it,
scripts/draft_release.sh commits it and drafts the release in release.yml, and
scripts/verify_release_pin.sh gates every v* tag on it.

The registry is faked with a ``docker`` on PATH that prints $SERVED for
``docker buildx imagetools inspect``, and GitHub with a ``gh`` that prints
$RELEASES for ``gh api`` and logs every other call to $GH_LOG.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PINNED_FILES = ("action.yml", "pipe.yml", "bitbucket-pipelines.yml")
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
VERSION = "26.10.3"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    for name in PINNED_FILES:
        shutil.copy(ROOT / name, tmp_path / name)
    fake = tmp_path / "bin" / "docker"
    fake.parent.mkdir()
    fake.write_text('#!/bin/sh\nprintf %s "$SERVED"\n')
    fake.chmod(0o755)
    return tmp_path


def run(repo: Path, script: str, *args: str, served: str = DIGEST, **extra: str) -> subprocess.CompletedProcess[str]:
    env = {"PATH": f"{repo / 'bin'}:/usr/bin:/bin", "SERVED": served, **extra}
    return subprocess.run(
        [ROOT / "scripts" / script, *args], cwd=repo, env=env, capture_output=True, text=True, check=False
    )


def test_pin_replaces_only_latest(repo: Path) -> None:
    assert run(repo, "pin_release_image.sh", VERSION, DIGEST).returncode == 0
    for name, image in zip(
        PINNED_FILES,
        ("docker://ghcr.io/sbomify/sbomify-action", "sbomifyhub/sbomify-action", "docker://sbomifyhub/sbomify-action"),
    ):
        before = (ROOT / name).read_text()
        assert (repo / name).read_text() == before.replace(f"{image}:latest", f"{image}:{VERSION}@{DIGEST}"), name
        assert f"{image}:latest" in before, name


@pytest.mark.parametrize(
    ("version", "digest"),
    [
        ("26.10", DIGEST),
        ("v26.10.3", DIGEST),  # the tag, not the version
        ("26.10.3|x", DIGEST),  # would end the sed replacement
        (VERSION, "a" * 64),  # no sha256: prefix
        (VERSION, "sha256:" + "A" * 64),
        (VERSION, DIGEST[:-1]),
    ],
)
def test_pin_rejects_bad_input(repo: Path, version: str, digest: str) -> None:
    result = run(repo, "pin_release_image.sh", version, digest)
    assert result.returncode == 1
    assert "::error::" in result.stdout
    for name in PINNED_FILES:
        assert (repo / name).read_text() == (ROOT / name).read_text(), name


def test_verify_passes_on_correct_pin(repo: Path) -> None:
    run(repo, "pin_release_image.sh", VERSION, DIGEST)
    result = run(repo, "verify_release_pin.sh", VERSION)
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize(
    ("pin", "verify", "served"),
    [
        (None, VERSION, DIGEST),  # still :latest
        (VERSION, "26.10.4", DIGEST),  # tag is not the version pinned
        (VERSION, VERSION, OTHER),  # registry serves another digest
    ],
)
def test_verify_fails(repo: Path, pin: str | None, verify: str, served: str) -> None:
    if pin:
        run(repo, "pin_release_image.sh", pin, DIGEST)
    result = run(repo, "verify_release_pin.sh", verify, served=served)
    assert result.returncode == 1
    assert "::error::" in result.stdout


def test_verify_fails_when_pipe_pins_another_digest(repo: Path) -> None:
    run(repo, "pin_release_image.sh", VERSION, DIGEST)
    pipe = repo / "pipe.yml"
    pipe.write_text(pipe.read_text().replace(DIGEST, OTHER))
    assert run(repo, "verify_release_pin.sh", VERSION).returncode == 1


GIT_ENV = {
    "GIT_AUTHOR_NAME": "test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
}
TAG = f"v{VERSION}"
BRANCH = f"refs/heads/release/{TAG}"
URL = "https://github.com/sbomify/sbomify-action/releases/tag/untagged-1"
CREATE = f"release create {TAG} --draft --target {{pin}} --title {TAG} --generate-notes"


def git(repo: Path, *args: str) -> str:
    env = {"PATH": "/usr/bin:/bin", **GIT_ENV}
    return subprocess.run(["git", *args], cwd=repo, env=env, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def clone(repo: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """``repo`` as release.yml's pin job sees it: a checkout with a GitHub origin."""
    origin = tmp_path_factory.mktemp("origin")
    git(origin, "init", "--bare", "--quiet")
    git(repo, "init", "--quiet")
    git(repo, "add", *PINNED_FILES)
    git(repo, "commit", "--quiet", "-m", "base")
    git(repo, "remote", "add", "origin", str(origin))
    fake = repo / "bin" / "gh"
    fake.write_text(
        '#!/bin/sh\n[ "$1" = api ] && { printf %s "$RELEASES"; exit; }\n'
        f'echo "$*" >> "$GH_LOG"\n[ -z "$GH_FAIL" ] || exit 1\necho {URL}\n'
    )
    fake.chmod(0o755)
    return repo


def draft(
    clone: Path, digest: str = DIGEST, releases: tuple[tuple[bool, str], ...] = (), **extra: str
) -> subprocess.CompletedProcess[str]:
    """Run draft_release.sh with GitHub listing ``releases`` (draft, target) as v26.10.3, after v26.10.2."""
    listed = [{"tag_name": "v26.10.2", "draft": False, "target_commitish": "master", "html_url": "old"}]
    listed += [{"tag_name": TAG, "draft": d, "target_commitish": t, "html_url": "existing"} for d, t in releases]
    gh_log = str(clone / "bin" / "gh.log")
    return run(
        clone, "draft_release.sh", VERSION, digest, RELEASES=json.dumps(listed), GH_LOG=gh_log, **GIT_ENV, **extra
    )


def branch_head(clone: Path) -> str:
    return git(clone, "ls-remote", "origin", BRANCH).split()[0]


def gh_calls(clone: Path) -> list[str]:
    log = clone / "bin" / "gh.log"
    return log.read_text().splitlines() if log.exists() else []


def first_attempt(clone: Path, **kwargs: str) -> str:
    """Run once, then check out the base again as "Re-run failed jobs" does. Returns release/vX's head."""
    base = git(clone, "rev-parse", "HEAD")
    draft(clone, **kwargs)
    git(clone, "reset", "--hard", "--quiet", base)
    return branch_head(clone)


def test_draft_release_commits_pin_and_drafts(clone: Path) -> None:
    base = git(clone, "rev-parse", "HEAD")
    result = draft(clone)
    assert result.returncode == 0, result.stdout + result.stderr
    pin = branch_head(clone)
    assert git(clone, "rev-parse", f"{pin}^") == base
    assert f"sbomify-action:{VERSION}@{DIGEST}" in git(clone, "show", f"{pin}:action.yml")
    assert gh_calls(clone) == [CREATE.format(pin=pin)]
    assert f"Draft: {URL}" in result.stdout


def test_draft_release_rerun_reuses_pushed_branch(clone: Path) -> None:
    """Re-running after the draft failed would commit at a later date, and pushing
    that commit over the branch the first attempt pushed is not a fast-forward."""
    pin = first_attempt(clone, GH_FAIL="1")
    result = draft(clone, GIT_COMMITTER_DATE="2030-01-01T00:00:00Z")
    assert result.returncode == 0, result.stdout + result.stderr
    assert branch_head(clone) == pin
    assert gh_calls(clone) == [CREATE.format(pin=pin)] * 2


def test_draft_release_refuses_branch_with_another_pin(clone: Path) -> None:
    pin = first_attempt(clone, digest=OTHER)
    result = draft(clone)
    assert result.returncode == 1
    assert "::error::" in result.stdout
    assert branch_head(clone) == pin
    assert len(gh_calls(clone)) == 1


def test_draft_release_reuses_its_draft(clone: Path) -> None:
    pin = first_attempt(clone, GH_FAIL="1")
    result = draft(clone, releases=((True, pin),))
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(gh_calls(clone)) == 1  # the first attempt's
    assert "Draft: existing" in result.stdout


@pytest.mark.parametrize(
    "existing",
    [
        ((True, "0" * 40),),  # stale draft of an older pin
        ((False, "{pin}"),),  # already published
        ((True, "{pin}"), (True, "{pin}")),  # which one?
    ],
)
def test_draft_release_refuses_other_release(clone: Path, existing: tuple[tuple[bool, str], ...]) -> None:
    pin = first_attempt(clone, GH_FAIL="1")
    result = draft(clone, releases=tuple((d, t.format(pin=pin)) for d, t in existing))
    assert result.returncode == 1
    assert "::error::" in result.stdout
    assert len(gh_calls(clone)) == 1
