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
