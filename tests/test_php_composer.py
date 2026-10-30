"""PHP: the Composer toolchain, and when it is worth fetching.

sbom-tools has published a php bundle -- cdxgen with a PHP runtime and
Composer -- for some time, but nothing in this repository declared it. So
`bundle_for("composer")` returned None, `can_provide` said no, and a PHP
project with no committed composer.lock fell through to syft, which wrote a
document with zero components and exited 0.

That is the common case rather than a corner: PHP libraries gitignore
composer.lock, leaving the consuming application to resolve it.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from sbomify_action._generation import utils
from sbomify_action._generation.generators import cdxgen as cdxgen_module
from sbomify_action._generation.generators.cdxgen import CdxgenFsGenerator
from sbomify_action._generation.protocol import GenerationInput
from sbomify_action._generation.utils import combined_output, composer_root_version, resolve_composer_lockfile
from sbomify_action.exceptions import SBOMGenerationError
from sbomify_action.runtimes import can_provide
from sbomify_action.tool_manifest import bundle_for, load_bundles


@pytest.fixture
def no_version_in_env(monkeypatch):
    """Neither an explicit version nor a tag-triggered build."""
    for name in (
        "COMPONENT_VERSION",
        "GITHUB_REF_TYPE",
        "GITHUB_REF_NAME",
        "GITHUB_REF",
        "CI_COMMIT_TAG",
        "BITBUCKET_TAG",
        "CIRCLE_TAG",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def composer_runs(monkeypatch):
    """Composer on PATH, with every call recorded and a composer.lock written."""
    calls: list[tuple[list[str], dict]] = []

    def fake_run(cmd, **kwargs):
        home = (kwargs.get("env") or {}).get("HOME")
        calls.append((cmd, {**kwargs, "home_existed": bool(home) and Path(home).is_dir()}))
        (Path(kwargs["cwd"]) / "composer.lock").write_text('{"packages": []}')
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.delenv("SBOMIFY_FETCH_RUNTIMES", raising=False)
    monkeypatch.setattr(utils, "ensure_php_installed", lambda: None)
    monkeypatch.setattr(utils.shutil, "which", lambda n: "/usr/bin/composer" if n == "composer" else None)
    monkeypatch.setattr(utils.subprocess, "run", fake_run)
    return calls


class TestTheBundleIsDeclared:
    def test_composer_resolves_to_the_php_bundle(self):
        bundle = bundle_for("composer")
        assert bundle is not None, "nothing would ever fetch Composer"
        assert bundle.name == "php"

    def test_php_resolves_to_the_php_bundle(self):
        bundle = bundle_for("php")
        assert bundle is not None
        assert bundle.name == "php"

    def test_the_generator_can_say_it_is_able_to_provide_composer(self, monkeypatch):
        """can_provide is what a generator asks before claiming an input.

        Pinned rather than inherited: can_provide is also false when fetching
        is opted out, so a suite run with SBOMIFY_FETCH_RUNTIMES=0 -- an
        air-gapped build, say -- would fail here for a reason that has nothing
        to do with whether the bundle is declared, which is what this asserts.
        """
        monkeypatch.delenv("SBOMIFY_FETCH_RUNTIMES", raising=False)
        assert can_provide("composer")

    def test_nothing_is_fetched_when_fetching_is_opted_out(self, monkeypatch):
        """The other half: opting out still means opting out."""
        monkeypatch.setenv("SBOMIFY_FETCH_RUNTIMES", "0")
        assert not can_provide("composer")

    def test_the_bundle_does_not_re_provide_cdxgen_or_syft(self):
        """It carries both, but [bundle.cdxgen] already claims cdxgen.

        load_bundles refuses two providers for one tool, so declaring them
        here would break every manifest load, not just PHP.
        """
        php = load_bundles()["php"]
        assert "cdxgen" not in php.provides
        assert "syft" not in php.provides


class TestWhenItIsFetched:
    @staticmethod
    def _run(tmp_path, monkeypatch, filename: str, body: str) -> list[str]:
        fetched: list[str] = []
        monkeypatch.delenv("SBOMIFY_FETCH_RUNTIMES", raising=False)
        monkeypatch.setattr(utils, "ensure_php_installed", lambda: fetched.append("php"))
        monkeypatch.setattr(utils.shutil, "which", lambda n: "/usr/bin/composer")
        monkeypatch.setattr(utils.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0, "", ""))
        monkeypatch.setattr(cdxgen_module, "ensure_runtime", lambda _tool: None)
        monkeypatch.setattr(cdxgen_module, "run_command", lambda *a, **k: None)

        source = tmp_path / filename
        source.write_text(body)
        output = tmp_path / "o.json"
        output.write_text('{"components": []}')

        CdxgenFsGenerator().generate(
            GenerationInput(lock_file=str(source), output_file=str(output), output_format="cyclonedx")
        )
        return fetched

    def test_a_manifest_fetches_composer(self, tmp_path, monkeypatch):
        """Without it cdxgen stops at "No composer version found"."""
        assert self._run(tmp_path, monkeypatch, "composer.json", '{"require": {}}') == ["php"]

    def test_a_lock_file_does_not(self, tmp_path, monkeypatch):
        """cdxgen parses composer.lock as data and never shells out.

        The same distinction the .NET gate draws: pay for a toolchain only
        where it changes the answer.
        """
        assert self._run(tmp_path, monkeypatch, "composer.lock", '{"packages": []}') == []

    @pytest.mark.parametrize("name", ["package.json", "go.mod", "Cargo.toml"])
    def test_other_ecosystems_do_not(self, tmp_path, monkeypatch, name):
        assert self._run(tmp_path, monkeypatch, name, "{}") == []


class TestTheRootVersionComposerIsToldAbout:
    """Composer asks git what version this package is, and git refuses a
    workspace owned by another UID. It then assumes 1.0.0, and any project
    depending on its own version stops resolving -- laravel/framework goes
    from 72 components to none, reported as success.
    """

    def test_an_explicit_component_version_is_used(self, monkeypatch, no_version_in_env):
        monkeypatch.setenv("COMPONENT_VERSION", "13.24.0")
        assert composer_root_version() == "13.24.0"

    def test_a_release_tag_is_used_when_nothing_is_explicit(self, monkeypatch, no_version_in_env):
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REF_NAME", "v13.24.0")
        assert composer_root_version() == "13.24.0"

    def test_an_explicit_version_outranks_the_tag(self, monkeypatch, no_version_in_env):
        monkeypatch.setenv("COMPONENT_VERSION", "9.9.9")
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REF_NAME", "v13.24.0")
        assert composer_root_version() == "9.9.9"

    def test_a_tag_that_spells_the_version_oddly_is_normalized(self, monkeypatch, no_version_in_env):
        """curl-8_21_0 is a real tag; Composer would not accept it verbatim."""
        monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
        monkeypatch.setenv("GITHUB_REF_NAME", "curl-8_21_0")
        assert composer_root_version() == "8.21.0"

    def test_nothing_is_claimed_when_the_build_is_not_a_release(self, no_version_in_env):
        """A branch build has no version, and inventing one would change how
        Composer resolves -- worse than leaving it at Composer's own default."""
        assert composer_root_version() is None

    @pytest.mark.parametrize("junk", ["latest", "main", "9bad36e9d1a8", "", "   "])
    def test_a_value_composer_would_not_accept_is_refused(self, monkeypatch, no_version_in_env, junk):
        """COMPONENT_VERSION is free-form: users put branch names and SHAs in
        it. Composer feeds the root version into resolution, so passing one of
        those through would break projects that currently work."""
        monkeypatch.setenv("COMPONENT_VERSION", junk)
        assert composer_root_version() is None


class TestTheVersionReachesComposer:
    """Composer resolves the manifest now, not cdxgen, so that is where the
    root version has to go."""

    def test_a_manifest_run_carries_the_root_version(self, tmp_path, monkeypatch, no_version_in_env, composer_runs):
        monkeypatch.setenv("COMPONENT_VERSION", "13.24.0")
        (tmp_path / "composer.json").write_text('{"require": {}}')

        resolve_composer_lockfile(tmp_path)

        assert composer_runs[0][1]["env"]["COMPOSER_ROOT_VERSION"] == "13.24.0"

    def test_nothing_is_set_when_no_version_is_known(self, tmp_path, monkeypatch, no_version_in_env, composer_runs):
        monkeypatch.delenv("COMPOSER_ROOT_VERSION", raising=False)
        (tmp_path / "composer.json").write_text('{"require": {}}')

        resolve_composer_lockfile(tmp_path)

        assert "COMPOSER_ROOT_VERSION" not in composer_runs[0][1]["env"]

    def test_a_lock_file_run_does_not_need_it(self, tmp_path, monkeypatch, no_version_in_env, composer_runs):
        """cdxgen reads composer.lock as data; nothing resolves, so Composer
        never runs."""
        monkeypatch.setenv("COMPONENT_VERSION", "13.24.0")
        monkeypatch.setattr(cdxgen_module, "ensure_runtime", lambda _tool: None)
        monkeypatch.setattr(cdxgen_module, "run_command", lambda *a, **k: None)
        (tmp_path / "composer.lock").write_text('{"packages": []}')
        (tmp_path / "o.json").write_text('{"components": []}')

        CdxgenFsGenerator().generate(
            GenerationInput(
                lock_file=str(tmp_path / "composer.lock"),
                output_file=str(tmp_path / "o.json"),
                output_format="cyclonedx",
            )
        )

        assert composer_runs == []


class TestComposerJsonIsResolvedWithoutRunningTheProject:
    """cdxgen runs with --no-install-deps, so it no longer runs `composer
    update` itself -- which ran the root package's scripts, code from the
    repository being scanned. A bare composer.json gave cdxgen nothing, and in
    the image the run aborted. sbomify resolves the lock instead, the way it
    already does for a bare package.json, with the project's scripts and
    plugins switched off.
    """

    def test_the_projects_scripts_and_plugins_do_not_run(self, tmp_path, composer_runs):
        (tmp_path / "composer.json").write_text('{"require": {}}')

        created = resolve_composer_lockfile(tmp_path)

        assert created == tmp_path / "composer.lock"
        cmd, kwargs = composer_runs[0]
        assert cmd[:2] == ["composer", "update"]
        assert "--no-scripts" in cmd, "the root package's scripts are code from the scanned repository"
        assert "--no-plugins" in cmd, "plugins are code too, and a repository can commit vendor/"
        assert "--no-install" in cmd, "resolving must not download package contents"
        assert kwargs["cwd"] == str(tmp_path)

    def test_a_committed_lock_is_left_alone(self, tmp_path, monkeypatch):
        (tmp_path / "composer.json").write_text('{"require": {}}')
        (tmp_path / "composer.lock").write_text('{"packages": []}')
        monkeypatch.setattr(utils.subprocess, "run", lambda *a, **k: pytest.fail("resolved despite a committed lock"))

        assert resolve_composer_lockfile(tmp_path) is None
        assert (tmp_path / "composer.lock").read_text() == '{"packages": []}'

    def test_a_failed_resolution_says_what_to_commit(self, tmp_path, monkeypatch):
        (tmp_path / "composer.json").write_text('{"require": {"nope/nope": "^1"}}')
        monkeypatch.setattr(utils, "ensure_php_installed", lambda: None)
        monkeypatch.setattr(utils.shutil, "which", lambda n: "/usr/bin/composer")

        def boom(cmd, **kwargs):
            raise subprocess.CalledProcessError(
                2, cmd, output="", stderr="Your requirements could not be resolved to an installable set of packages."
            )

        monkeypatch.setattr(utils.subprocess, "run", boom)

        with pytest.raises(SBOMGenerationError) as error:
            resolve_composer_lockfile(tmp_path)

        assert "could not be resolved to an installable set" in str(error.value), "Composer's reason was lost"
        assert "Commit a composer.lock" in str(error.value)

    def test_without_composer_it_says_what_to_commit(self, tmp_path, monkeypatch):
        """No PHP runtime for this host, and none installed. The run still
        fails, as it did, but says how to make it work without Composer."""
        (tmp_path / "composer.json").write_text('{"require": {}}')

        def unavailable():
            raise SBOMGenerationError("Install composer and put it on PATH.")

        monkeypatch.setattr(utils, "ensure_php_installed", unavailable)

        with pytest.raises(SBOMGenerationError, match="Commit a composer.lock"):
            resolve_composer_lockfile(tmp_path)

    def test_the_generator_reports_it_and_never_runs_cdxgen(self, tmp_path, monkeypatch):
        (tmp_path / "composer.json").write_text('{"require": {}}')
        monkeypatch.setattr(cdxgen_module, "ensure_runtime", lambda _tool: None)
        monkeypatch.setattr(cdxgen_module, "run_command", lambda *a, **k: pytest.fail("cdxgen ran without a lock"))

        def unresolvable(directory):
            raise SBOMGenerationError("Composer could not resolve composer.json. Commit a composer.lock.")

        monkeypatch.setattr(cdxgen_module, "resolve_composer_lockfile", unresolvable)

        result = CdxgenFsGenerator().generate(
            GenerationInput(
                lock_file=str(tmp_path / "composer.json"),
                output_file=str(tmp_path / "o.json"),
                output_format="cyclonedx",
            )
        )

        assert not result.success
        assert "Commit a composer.lock" in str(result.error_message)

    def test_a_symlinked_lock_is_refused(self, tmp_path, monkeypatch):
        """A dangling link is not a file, so it looked like no lock at all.
        Composer would then write through it, and the cleanup would delete
        whatever it pointed at."""
        (tmp_path / "composer.json").write_text('{"require": {}}')
        (tmp_path / "composer.lock").symlink_to(tmp_path.parent / "outside-the-project")
        monkeypatch.setattr(utils.subprocess, "run", lambda *a, **k: pytest.fail("resolved through a symlink"))

        with pytest.raises(SBOMGenerationError, match="symlink"):
            resolve_composer_lockfile(tmp_path)

        assert not (tmp_path.parent / "outside-the-project").exists()

    def test_a_symlink_to_a_real_file_is_refused_too(self, tmp_path, monkeypatch):
        (tmp_path / "composer.json").write_text('{"require": {}}')
        (tmp_path / "elsewhere.lock").write_text('{"packages": []}')
        (tmp_path / "composer.lock").symlink_to(tmp_path / "elsewhere.lock")
        monkeypatch.setattr(utils.subprocess, "run", lambda *a, **k: pytest.fail("resolved through a symlink"))

        with pytest.raises(SBOMGenerationError, match="symlink"):
            resolve_composer_lockfile(tmp_path)

    def test_a_lock_that_is_not_a_regular_file_inside_the_project_is_not_used(
        self, tmp_path, composer_runs, monkeypatch
    ):
        """Checked again after Composer runs, before the caller registers the
        file for deletion: whatever is there now must be ours to delete."""
        outside = tmp_path.parent / f"{tmp_path.name}-outside.lock"
        outside.write_text("not ours")
        (tmp_path / "composer.json").write_text('{"require": {}}')

        def leaves_a_link(cmd, **kwargs):
            (tmp_path / "composer.lock").symlink_to(outside)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        monkeypatch.setattr(utils.subprocess, "run", leaves_a_link)

        with pytest.raises(SBOMGenerationError, match="regular"):
            resolve_composer_lockfile(tmp_path)

        assert outside.read_text() == "not ours"

    def test_the_generator_removes_the_lock_it_created(self, tmp_path, monkeypatch, composer_runs):
        """A working file. Left in the checkout, it would also stop the SBOM
        saying its versions were inferred."""
        (tmp_path / "composer.json").write_text('{"require": {}}')
        monkeypatch.setattr(cdxgen_module, "ensure_runtime", lambda _tool: None)
        seen = []
        monkeypatch.setattr(
            cdxgen_module, "run_command", lambda cmd, *a, **k: seen.append((tmp_path / "composer.lock").exists())
        )

        CdxgenFsGenerator().generate(
            GenerationInput(
                lock_file=str(tmp_path / "composer.json"),
                output_file=str(tmp_path / "o.json"),
                output_format="cyclonedx",
            )
        )

        assert seen == [True], "cdxgen must run with the resolved lock in place"
        assert not (tmp_path / "composer.lock").exists()


class TestTheManifestCannotSteerTheResolution:
    """composer.json comes from the repository being scanned, and resolving it
    reaches the network from inside CI. So it resolves against Packagist, over
    TLS, with none of the job's secrets, or not at all."""

    @staticmethod
    def _manifest(tmp_path, **fields):
        (tmp_path / "composer.json").write_text(json.dumps({"require": {}, **fields}))

    def test_nothing_resolves_when_fetching_is_opted_out(self, tmp_path, monkeypatch, composer_runs):
        """The same gate the package.json resolution has."""
        monkeypatch.setenv("SBOMIFY_FETCH_RUNTIMES", "0")
        self._manifest(tmp_path)

        with pytest.raises(SBOMGenerationError, match="Commit a composer.lock"):
            resolve_composer_lockfile(tmp_path)

        assert composer_runs == []

    def test_the_jobs_secrets_do_not_reach_composer(self, tmp_path, monkeypatch, composer_runs):
        secrets = ("TOKEN", "DTRACK_API_KEY", "GITHUB_TOKEN", "COMPOSER_AUTH", "COMPOSER")
        for name in secrets:
            monkeypatch.setenv(name, "s3cret")
        monkeypatch.setenv("HOME", "/home/runner")
        self._manifest(tmp_path)

        resolve_composer_lockfile(tmp_path)

        env = composer_runs[0][1]["env"]
        assert not set(secrets) & env.keys()
        assert "s3cret" not in env.values()
        assert env["PATH"] == os.environ["PATH"], "composer and php are found on PATH"

    def test_it_gets_a_scratch_home_that_is_removed_afterwards(self, tmp_path, monkeypatch, composer_runs):
        """Not the runner's home, where a global config.json or auth.json
        could add repositories or credentials."""
        monkeypatch.setenv("HOME", "/home/runner")
        self._manifest(tmp_path)

        resolve_composer_lockfile(tmp_path)

        env = composer_runs[0][1]["env"]
        assert env["HOME"] != "/home/runner"
        assert env["COMPOSER_HOME"].startswith(env["HOME"])
        assert env["COMPOSER_CACHE_DIR"].startswith(env["HOME"])
        assert composer_runs[0][1]["home_existed"]
        assert not Path(env["HOME"]).exists()

    def test_a_proxy_still_reaches_it(self, tmp_path, monkeypatch, composer_runs):
        """A runner behind a proxy cannot reach Packagist without it."""
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.internal:3128")
        self._manifest(tmp_path)

        resolve_composer_lockfile(tmp_path)

        assert composer_runs[0][1]["env"]["HTTPS_PROXY"] == "http://proxy.internal:3128"

    @pytest.mark.parametrize(
        "config",
        [{"disable-tls": True}, {"disable-tls": "1"}, {"secure-http": False}, {"secure-http": "0"}],
    )
    def test_a_manifest_that_weakens_tls_is_refused(self, tmp_path, composer_runs, config):
        """Composer reads disable-tls and secure-http from the project with no
        environment or command-line override, so the only safe answer is no."""
        self._manifest(tmp_path, config=config)

        with pytest.raises(SBOMGenerationError, match="Commit a composer.lock"):
            resolve_composer_lockfile(tmp_path)

        assert composer_runs == []

    @pytest.mark.parametrize("config", [{}, {"secure-http": True}, {"disable-tls": False}, {"sort-packages": True}])
    def test_tls_left_alone_resolves(self, tmp_path, composer_runs, config):
        self._manifest(tmp_path, config=config)

        assert resolve_composer_lockfile(tmp_path) == tmp_path / "composer.lock"

    @pytest.mark.parametrize(
        "key,value",
        [
            # Trust: a CA bundle the repository supplies lets anyone on the
            # network path serve packages under it.
            ("cafile", "certs/ca.pem"),
            ("capath", "certs/"),
            # Credentials, sent wherever the manifest says.
            ("http-basic", {"repo.example": {"username": "u", "password": "p"}}),
            ("client-certificate", {"repo.example": {"local_cert": "client.pem"}}),
            ("custom-headers", {"repo.example": ["Authorization: Bearer x"]}),
            # Which hosts get treated as GitHub, and so get GitHub tokens.
            ("github-domains", ["github.internal.example"]),
            # Package metadata the repository supplies, read as if it came
            # from Packagist.
            ("cache-repo-dir", ".composer-cache/repo"),
        ],
    )
    def test_a_manifest_that_sets_trust_hosts_or_credentials_is_refused(self, tmp_path, composer_runs, key, value):
        self._manifest(tmp_path, config={key: value})

        with pytest.raises(SBOMGenerationError, match="Commit a composer.lock") as error:
            resolve_composer_lockfile(tmp_path)

        assert key in str(error.value), "the refusal must say which setting it objects to"
        assert composer_runs == []

    def test_harmless_config_still_resolves(self, tmp_path, composer_runs):
        """A denylist, so the settings projects actually commit keep working."""
        self._manifest(
            tmp_path,
            config={
                "sort-packages": True,
                "platform": {"php": "8.4.1"},
                "allow-plugins": {"symfony/flex": True},
                "optimize-autoloader": True,
            },
        )

        assert resolve_composer_lockfile(tmp_path) == tmp_path / "composer.lock"

    @pytest.mark.parametrize(
        "repositories",
        [
            [{"type": "vcs", "url": "https://git.internal.example/acme/widget.git"}],
            {"internal": {"type": "composer", "url": "http://10.0.0.5"}},
            [{"type": "path", "url": "../elsewhere"}],
            {"packagist.org": False},
        ],
    )
    def test_a_manifest_with_its_own_repositories_is_refused(self, tmp_path, composer_runs, repositories):
        """They can point anywhere, including hosts inside the runner's network."""
        self._manifest(tmp_path, repositories=repositories)

        with pytest.raises(SBOMGenerationError, match="repositories"):
            resolve_composer_lockfile(tmp_path)

        assert composer_runs == []

    def test_an_empty_repositories_list_resolves(self, tmp_path, composer_runs):
        self._manifest(tmp_path, repositories=[])

        assert resolve_composer_lockfile(tmp_path) == tmp_path / "composer.lock"

    def test_a_manifest_that_cannot_be_read_is_refused(self, tmp_path, composer_runs):
        """What cannot be checked is not resolved."""
        (tmp_path / "composer.json").write_text('{"require": ')

        with pytest.raises(SBOMGenerationError, match="Commit a composer.lock"):
            resolve_composer_lockfile(tmp_path)

        assert composer_runs == []


class TestTheErrorSurvivesTheReport:
    """cdxgen splits one message across two streams: the marker on stderr and
    the reason on stdout. Reporting only stderr produced the bare, useless
    "Error running composer:" that made this bug expensive to find.
    """

    def test_both_streams_are_kept(self):
        assert combined_output("Error running composer:", "Problem 1\n  - ext-session is missing") == (
            "Error running composer:\nProblem 1\n  - ext-session is missing"
        )

    def test_stdout_is_not_discarded_just_because_stderr_spoke(self):
        assert "the reason" in combined_output("a marker", "the reason")

    def test_indentation_survives(self):
        """Composer says what is wrong in the shape of the text, and the
        first line of a stream is as entitled to its indent as any other."""
        assert combined_output("marker", "    - ext-session is missing") == "marker\n    - ext-session is missing"

    def test_leading_blank_lines_do_not(self):
        """Trimming them is the whole reason not to leave the front alone:
        joined streams otherwise open with a gap."""
        assert combined_output("marker", "\n\n  Problem 1") == "marker\n  Problem 1"

    def test_trailing_whitespace_goes(self):
        assert combined_output("marker", "reason  \n\n") == "marker\nreason"

    @pytest.mark.parametrize(
        "stderr,stdout,expected",
        [
            ("only stderr", "", "only stderr"),
            ("", "only stdout", "only stdout"),
            ("", "", ""),
            (None, None, ""),
            ("  \n ", "real", "real"),
        ],
    )
    def test_one_stream_or_neither(self, stderr, stdout, expected):
        assert combined_output(stderr, stdout) == expected
