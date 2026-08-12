"""A bare package.json must still produce an SBOM.

cdxgen cannot read one on its own. Measured on express v5.2.1, whose 28
runtime dependencies are declared and whose lock file is gitignored: cdxgen
exits 0 and produces **zero** components, with or without --required-only.
Resolve the manifest into a lock file first and the same command returns 67 --
the transitive closure of those 28.

This is the common case, not a corner. A JavaScript library gitignores its
lock file because the consuming application resolves it, so most libraries on
GitHub arrive as a manifest and nothing else. eslint and express both produced
empty documents for exactly this reason.

The versions that come out are a resolution performed now rather than a record
of what the project committed to, which is why the document carries a notice
and a remedy saying so. That is the trade this makes: an answer to "what would
I install today" beats an empty document, provided it cannot be mistaken for
the other thing.
"""

import subprocess
from pathlib import Path

import pytest

from sbomify_action._generation import utils
from sbomify_action._generation.utils import resolve_npm_lockfile


@pytest.fixture
def project(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "thing", "dependencies": {"left-pad": "^1.0.0"}}')
    return tmp_path


class TestWhenItRuns:
    def test_it_resolves_a_manifest_with_no_lockfile(self, project, monkeypatch):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            (project / "bun.lock").write_text("{}")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(utils.shutil, "which", lambda n: "/usr/bin/bun" if n == "bun" else None)
        monkeypatch.setattr(utils.subprocess, "run", fake_run)

        created = resolve_npm_lockfile(project)

        assert created == project / "bun.lock"
        assert calls[0][:2] == ["bun", "install"]
        assert "--lockfile-only" in calls[0], "resolving must not download package contents"

    @pytest.mark.parametrize(
        "existing", ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "npm-shrinkwrap.json"]
    )
    def test_it_does_nothing_when_the_project_committed_a_lockfile(self, project, monkeypatch, existing):
        """The committed file is the authoritative one and the registry has
        already promoted the input to it. Resolving again would replace a
        record with a guess."""
        (project / existing).write_text("{}")
        monkeypatch.setattr(
            utils.subprocess, "run", lambda *a, **k: pytest.fail("resolved despite a committed lock file")
        )

        assert resolve_npm_lockfile(project) is None


class TestWhenItDeclines:
    def test_without_bun_it_leaves_things_as_they_were(self, project, monkeypatch):
        monkeypatch.setattr(utils.shutil, "which", lambda n: None)
        assert resolve_npm_lockfile(project) is None

    def test_a_failed_resolution_is_not_a_new_way_to_break(self, project, monkeypatch):
        """Offline, a private registry, or a manifest bun will not resolve.
        The generator carries on and fails the way it did before."""
        monkeypatch.setattr(utils.shutil, "which", lambda n: "/usr/bin/bun")

        def boom(cmd, **kwargs):
            raise subprocess.CalledProcessError(1, cmd, stderr="no such package")

        monkeypatch.setattr(utils.subprocess, "run", boom)

        assert resolve_npm_lockfile(project) is None

    def test_a_timeout_is_handled(self, project, monkeypatch):
        monkeypatch.setattr(utils.shutil, "which", lambda n: "/usr/bin/bun")

        def slow(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 300)

        monkeypatch.setattr(utils.subprocess, "run", slow)

        assert resolve_npm_lockfile(project) is None

    def test_success_without_a_lockfile_on_disk_returns_nothing(self, project, monkeypatch):
        """bun reporting success but writing nothing must not hand back a path
        the caller will later try to delete."""
        monkeypatch.setattr(utils.shutil, "which", lambda n: "/usr/bin/bun")
        monkeypatch.setattr(utils.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0, "", ""))

        assert resolve_npm_lockfile(project) is None


def test_the_generator_removes_what_it_created(tmp_path, monkeypatch):
    """The lock file is a working file. Leaving it in a checkout invites
    someone to commit a resolution nobody chose."""
    from sbomify_action._generation.generators.cdxgen import CdxgenFsGenerator
    from sbomify_action._generation.protocol import GenerationInput

    (tmp_path / "package.json").write_text('{"name": "thing"}')
    created = tmp_path / "bun.lock"

    monkeypatch.setattr("sbomify_action._generation.generators.cdxgen.ensure_runtime", lambda n: Path("/x"))
    monkeypatch.setattr(
        "sbomify_action._generation.generators.cdxgen.resolve_npm_lockfile",
        lambda d: (created.write_text("{}"), created)[1],
    )

    def fail(*a, **k):
        raise Exception("cdxgen exploded")

    monkeypatch.setattr("sbomify_action._generation.generators.cdxgen.run_command", fail)

    generator = CdxgenFsGenerator()
    with pytest.raises(Exception):
        generator.generate(
            GenerationInput(
                lock_file=str(tmp_path / "package.json"),
                output_file=str(tmp_path / "out.json"),
                output_format="cyclonedx",
            )
        )

    assert not created.exists(), "a lock file we created was left behind after a failure"


class TestItNeverDeletesSomeoneElsesFile:
    """The caller unlinks whatever this returns, so returning a file it did not
    create destroys a committed lock file."""

    def test_a_committed_bun_lockb_stops_it_running(self, project, monkeypatch):
        (project / "bun.lockb").write_bytes(b"binary lock")
        monkeypatch.setattr(
            utils.subprocess, "run", lambda *a, **k: pytest.fail("resolved despite a committed bun.lockb")
        )

        assert resolve_npm_lockfile(project) is None
        assert (project / "bun.lockb").exists()

    def test_a_pre_existing_file_is_never_returned_for_deletion(self, project, monkeypatch):
        """Belt and braces for the name list being incomplete: even if the
        early return is bypassed, ownership decides what may be removed."""
        (project / "bun.lockb").write_bytes(b"binary lock")
        monkeypatch.setattr(utils.shutil, "which", lambda n: "/usr/bin/bun")
        monkeypatch.setattr(utils, "_js_lock_files", lambda: ("package-lock.json",))
        monkeypatch.setattr(utils.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0, "", ""))

        assert resolve_npm_lockfile(project) is None, "handed back a file it did not create"
        assert (project / "bun.lockb").exists()

    def test_a_file_it_did_create_is_returned(self, project, monkeypatch):
        monkeypatch.setattr(utils.shutil, "which", lambda n: "/usr/bin/bun")

        def writes_lock(cmd, **kwargs):
            (project / "bun.lock").write_text("{}")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(utils.subprocess, "run", writes_lock)

        assert resolve_npm_lockfile(project) == project / "bun.lock"
