"""What the Discover screen ticks on arrival.

The rule is "the shallowest depth that has anything selectable", which is right
for a monorepo and wrong for a project whose only lockfiles are its own tooling.

curl is the case. At curl-8_21_0 nothing supported sits at the root -- it is a
C project -- so the candidates are `.github/scripts/requirements.txt`,
`tests/requirements.txt`, `tests/http/requirements.txt` and a Windows solution
template. The shallowest is `tests/requirements.txt`, and the run produced a
one-component SBOM named "curl" describing curl's test harness.

Measured over 353 repositories: 60 have no root-level input, and 29 of those
default to a tooling directory.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from sbomify_action.cli.wizard.screens.discover import DiscoverScreen, _is_tooling
from sbomify_action.cli.wizard.state import DiscoveredLockfile


def _lf(rel: str, *, nested: str | None = None) -> DiscoveredLockfile:
    return DiscoveredLockfile(
        path=Path("/repo") / rel,
        rel_path=Path(rel),
        ecosystem="python",
        suggested_name="x",
        nested_repo=nested,
    )


def _ticked(*paths_or_lockfiles) -> set[str]:
    """The rel_paths _default_selected would tick for this discovery.

    `wizard` is a read-only property that asserts the running app is a
    WizardApp, so the stub is supplied by subclassing rather than assignment --
    which keeps the real _default_selected under test instead of a copy.
    """
    discovered = [p if isinstance(p, DiscoveredLockfile) else _lf(p) for p in paths_or_lockfiles]

    class _Stubbed(DiscoverScreen):
        @property
        def wizard(self):  # type: ignore[override]
            return SimpleNamespace(state=SimpleNamespace(discovered=discovered))

    screen = _Stubbed.__new__(_Stubbed)
    return {str(discovered[i].rel_path) for i in screen._default_selected()}


class TestToolingDetection:
    @pytest.mark.parametrize(
        "path",
        [
            "tests/requirements.txt",
            "test/go.mod",
            "docs/Gemfile.lock",
            "doc/requirements.txt",
            ".github/scripts/requirements.txt",
            "ci/github-script/package-lock.json",
            "scripts/sbom/requirements.txt",
            "examples/build.gradle",
            "benchmark/EFCore.Benchmarks/EFCore.Benchmarks.csproj",
            "DOCS/requirements.txt",
        ],
    )
    def test_recognised_as_tooling(self, path):
        assert _is_tooling(Path(path))

    @pytest.mark.parametrize(
        "path",
        [
            "uv.lock",
            "package.json",
            "src/uv.lock",
            "packages/web/package.json",
            # A monorepo package that happens to be called docs is a real
            # component, not the repository's documentation.
            "packages/docs/package.json",
            "apps/examples/go.mod",
        ],
    )
    def test_not_tooling(self, path):
        assert not _is_tooling(Path(path))

    def test_a_root_file_is_never_tooling(self):
        """Only a *directory* makes something tooling; a root file is the project."""
        assert not _is_tooling(Path("requirements.txt"))


class TestDefaultSelection:
    def test_curl(self):
        """The real discovery for curl-8_21_0.

        Depth alone ticked `tests/requirements.txt` and produced a
        one-component SBOM named "curl" describing curl's test harness.

        The pick now is curl's own Windows solution, four levels down. It is
        not obviously a *good* answer -- curl is a C project and that solution
        carries no package references -- but it is curl, where the test
        requirements were never going to be. An empty document from it is
        F2's problem to surface, and an honest one; a populated document
        describing pytest and its plugins is neither.
        """
        ticked = _ticked(
            ".github/scripts/requirements.txt",
            "projects/Windows/tmpl/curl.sln",
            "tests/requirements.txt",
            "tests/http/requirements.txt",
        )

        assert ticked == {"projects/Windows/tmpl/curl.sln"}

    def test_depth_still_loses_to_being_the_project(self):
        """The whole change in one line: shallower tooling does not win."""
        assert _ticked("tests/uv.lock", "src/a/b/c/package.json") == {"src/a/b/c/package.json"}

    def test_everything_is_tooling(self):
        """The invariant holds -- something is ticked, and the note says why."""
        ticked = _ticked("tests/requirements.txt", "docs/package.json")

        assert ticked, "the screen must never arrive with nothing selectable"
        assert ticked == {"tests/requirements.txt", "docs/package.json"}

    def test_a_real_lockfile_wins_over_a_shallower_tooling_one(self):
        """The case the old rule got wrong: depth alone picked the tooling."""
        assert _ticked("docs/requirements.txt", "src/backend/uv.lock") == {"src/backend/uv.lock"}

    def test_a_root_lockfile_is_unaffected(self):
        assert _ticked("uv.lock", "tests/requirements.txt") == {"uv.lock"}

    def test_every_lockfile_at_the_shallowest_real_depth_is_ticked(self):
        """A polyglot root still gets both of its lockfiles."""
        assert _ticked("uv.lock", "package.json", "tests/requirements.txt") == {"uv.lock", "package.json"}

    def test_nested_repos_are_still_excluded(self):
        assert _ticked(_lf("vendor/thing/go.mod", nested="vendored"), _lf("uv.lock")) == {"uv.lock"}

    def test_tooling_and_nested_together(self):
        """Both exclusions apply, and the real input still wins."""
        ticked = _ticked(
            _lf("third_party/wasmer/Cargo.toml", nested="vendored"),
            _lf("docs/requirements.txt"),
            _lf("packages/app/pubspec.lock"),
        )
        assert ticked == {"packages/app/pubspec.lock"}

    def test_only_nested_repos_selects_nothing(self):
        """Unchanged: nested repos belong to another repository entirely."""
        assert _ticked(_lf("vendor/a/go.mod", nested="vendored")) == set()

    def test_no_discovery_at_all(self):
        assert _ticked() == set()
