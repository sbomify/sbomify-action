"""LOCK_FILE names a file, and the file a project uses changes.

A repository moves from npm to pnpm, from poetry to uv, from Pipenv to
either, and the workflow pinning the old name fails with "Specified input file
not found" -- true about the name, useless about the project, whose
dependencies are in the file sitting next to it.

Substituting is only safe when it is unambiguous and announced. These tests
are mostly about the cases where it must refuse.
"""

import pytest

from sbomify_action.cli.main import _expand_lock_file_or_substitute
from sbomify_action.exceptions import FileProcessingError


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_the_named_file_is_used_when_it_is_there(project):
    (project / "package-lock.json").write_text("{}")
    assert _expand_lock_file_or_substitute("package-lock.json").endswith("package-lock.json")


def test_it_substitutes_the_ecosystem_lock_file_that_exists(project):
    """The npm-to-pnpm migration, which is the case that breaks pinned workflows."""
    (project / "pnpm-lock.yaml").write_text("{}")
    assert _expand_lock_file_or_substitute("package-lock.json").endswith("pnpm-lock.yaml")


def test_it_substitutes_across_python_package_managers(project):
    (project / "uv.lock").write_text("")
    assert _expand_lock_file_or_substitute("poetry.lock").endswith("uv.lock")


def test_it_refuses_to_guess_between_two_candidates(project):
    """Two lock files for one ecosystem have no obvious winner, and picking
    one is how a document ends up describing the wrong tree."""
    (project / "pnpm-lock.yaml").write_text("{}")
    (project / "yarn.lock").write_text("")
    with pytest.raises(FileProcessingError):
        _expand_lock_file_or_substitute("package-lock.json")


def test_it_does_not_cross_ecosystems(project):
    """A missing package-lock.json is not an invitation to describe the Python."""
    (project / "poetry.lock").write_text("")
    with pytest.raises(FileProcessingError):
        _expand_lock_file_or_substitute("package-lock.json")


def test_nothing_to_substitute_keeps_the_original_error(project):
    with pytest.raises(FileProcessingError):
        _expand_lock_file_or_substitute("package-lock.json")


def test_an_unrecognised_name_is_not_second_guessed(project):
    (project / "pnpm-lock.yaml").write_text("{}")
    with pytest.raises(FileProcessingError):
        _expand_lock_file_or_substitute("something-of-my-own.txt")


def test_the_substitution_is_announced(project, caplog):
    (project / "pnpm-lock.yaml").write_text("{}")
    with caplog.at_level("WARNING"):
        _expand_lock_file_or_substitute("package-lock.json")
    assert "USING A DIFFERENT INPUT THAN THE ONE YOU CONFIGURED" in caplog.text
    assert "pnpm-lock.yaml" in caplog.text


def test_a_lock_file_is_preferred_over_a_manifest(project):
    """ALL_LOCK_FILES contains manifests too, so without a preference a
    missing package-lock.json could be "substituted" by package.json --
    quietly trading a recorded resolution for an inferred one, which is the
    exact swap this change exists to make visible."""
    (project / "package.json").write_text("{}")
    (project / "pnpm-lock.yaml").write_text("{}")

    assert _expand_lock_file_or_substitute("package-lock.json").endswith("pnpm-lock.yaml")


def test_falling_back_to_a_manifest_says_it_is_a_downgrade(project, caplog):
    """When the manifest is all there is, substituting is still better than
    failing -- but the reader has to be told the versions stopped being a
    record."""
    (project / "package.json").write_text("{}")

    with caplog.at_level("WARNING"):
        result = _expand_lock_file_or_substitute("package-lock.json")

    assert result.endswith("package.json")
    assert "manifest rather than a lock file" in caplog.text


def test_two_manifests_are_still_ambiguous(project):
    (project / "pyproject.toml").write_text("")
    (project / "requirements.txt").write_text("")
    with pytest.raises(FileProcessingError):
        _expand_lock_file_or_substitute("poetry.lock")


def test_it_searches_the_action_workspace_too(tmp_path, monkeypatch):
    """path_expansion looks in /github/workspace as well as the working
    directory, because inside a GitHub Action they are not the same. The
    substitution claimed parity and checked only two of the three, so it could
    refuse a file the caller could plainly see -- in exactly the environment
    where LOCK_FILE is most likely to be pinned and stale."""
    # sys.modules, because `sbomify_action.cli` re-exports the click
    # command as `main` and shadows the submodule of the same name.
    import sys

    _m = sys.modules["sbomify_action.cli.main"]

    workspace = tmp_path / "gh"
    workspace.mkdir()
    (workspace / "pnpm-lock.yaml").write_text("{}")

    elsewhere = tmp_path / "somewhere-else"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setattr(_m, "GITHUB_WORKSPACE", str(workspace))

    assert _expand_lock_file_or_substitute("package-lock.json").endswith("pnpm-lock.yaml")
