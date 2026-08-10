"""PHP: the Composer toolchain, and when it is worth fetching.

sbom-tools has published a php bundle -- cdxgen with a PHP runtime and
Composer -- for some time, but nothing in this repository declared it. So
`bundle_for("composer")` returned None, `can_provide` said no, and a PHP
project with no committed composer.lock fell through to syft, which wrote a
document with zero components and exited 0.

That is the common case rather than a corner: PHP libraries gitignore
composer.lock, leaving the consuming application to resolve it.
"""

import pytest

from sbomify_action._generation.generators import cdxgen as cdxgen_module
from sbomify_action._generation.generators.cdxgen import CdxgenFsGenerator
from sbomify_action._generation.protocol import GenerationInput
from sbomify_action._generation.utils import combined_output, composer_root_version
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
    ):
        monkeypatch.delenv(name, raising=False)


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
        monkeypatch.setattr(cdxgen_module, "ensure_php_installed", lambda: fetched.append("php"))
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


class TestTheVersionReachesCdxgen:
    @staticmethod
    def _env_passed_to_cdxgen(tmp_path, monkeypatch, filename: str) -> dict | None:
        seen: dict = {}
        monkeypatch.setattr(cdxgen_module, "ensure_php_installed", lambda: None)
        monkeypatch.setattr(cdxgen_module, "ensure_runtime", lambda _tool: None)
        monkeypatch.setattr(cdxgen_module, "run_command", lambda *a, **k: seen.update(k))

        source = tmp_path / filename
        source.write_text('{"require": {}}')
        output = tmp_path / "o.json"
        output.write_text('{"components": []}')

        CdxgenFsGenerator().generate(
            GenerationInput(lock_file=str(source), output_file=str(output), output_format="cyclonedx")
        )
        return seen.get("env")

    def test_a_manifest_run_carries_the_root_version(self, tmp_path, monkeypatch, no_version_in_env):
        monkeypatch.setenv("COMPONENT_VERSION", "13.24.0")
        assert self._env_passed_to_cdxgen(tmp_path, monkeypatch, "composer.json") == {
            "COMPOSER_ROOT_VERSION": "13.24.0"
        }

    def test_nothing_is_set_when_no_version_is_known(self, tmp_path, monkeypatch, no_version_in_env):
        assert self._env_passed_to_cdxgen(tmp_path, monkeypatch, "composer.json") is None

    def test_a_lock_file_run_does_not_need_it(self, tmp_path, monkeypatch, no_version_in_env):
        """cdxgen reads composer.lock as data; nothing resolves, so the root
        version cannot matter."""
        monkeypatch.setenv("COMPONENT_VERSION", "13.24.0")
        assert self._env_passed_to_cdxgen(tmp_path, monkeypatch, "composer.lock") is None


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
