"""pyproject.toml is not automatically a Poetry project.

`LOCK_FILE_COMMANDS` mapped `pyproject.toml` straight to the `poetry`
subcommand, which needs a `poetry.lock`. For a PEP 621 project built with
setuptools, hatchling, flit, pdm or maturin there is no such lock file, so
cyclonedx-py exited 1 with:

    error: CRITICAL | CDX > Could not open lock file: /workspace/poetry.lock

Inside the container a generator that claims an input and then fails is
fatal, so those projects produced no SBOM at all -- 13 of 25 popular Python
repositories measured, django, numpy, pandas, scikit-learn, scrapy,
sqlalchemy, transformers, pip, black and requests among them.

cyclonedx-py has four subcommands -- environment, requirements, pipenv,
poetry -- and none reads a PEP 621 manifest. So the honest answer is to
decline and let cdxgen, which does, take the input.
"""

import pytest

from sbomify_action._generation.generators.cyclonedx_py import (
    CycloneDXPyGenerator,
    _is_poetry_project,
)
from sbomify_action._generation.protocol import GenerationInput

POETRY = """\
[tool.poetry]
name = "widget"

[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"
"""

SETUPTOOLS = """\
[project]
name = "widget"
version = "1.0.0"

[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"
"""

HATCHLING = """\
[project]
name = "widget"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
"""

FLIT = """\
[project]
name = "widget"

[build-system]
requires = ["flit_core >=3.2,<4"]
build-backend = "flit_core.buildapi"
"""

POETRY_WITHOUT_BACKEND = """\
[build-system]
requires = ["poetry-core"]
"""

LEGACY_POETRY = """\
[tool.poetry]
name = "widget"
version = "0.1.0"
"""

# Poetry's pre-1.1 backend module, still declared by projects that have not
# retouched their build-system table since.
LEGACY_BACKEND = """\
[project]
name = "widget"

[build-system]
requires = ["some-other-builder"]
build-backend = "poetry.masonry.api"
"""

# PEP 503 treats "poetry_core" and "poetry-core" as the same distribution and
# both spellings appear in the wild, so the requires check normalises.
UNDERSCORE_REQUIREMENT = """\
[project]
name = "widget"

[build-system]
requires = ["poetry_core>=1.0.0"]
"""

# The bare distribution, from before poetry-core was split out.
BARE_POETRY_REQUIREMENT = """\
[project]
name = "widget"

[build-system]
requires = ["poetry>=1.0"]
"""

# Cased and space-padded, because a requirement string is free text.
ODD_CASING = """\
[project]
name = "widget"

[build-system]
requires = ["  Poetry-Core >= 1.0.0  "]
"""


def _pyproject(tmp_path, body):
    path = tmp_path / "pyproject.toml"
    path.write_text(body)
    return path


@pytest.mark.parametrize(
    "body,expected",
    [
        (POETRY, True),
        (POETRY_WITHOUT_BACKEND, True),
        (LEGACY_POETRY, True),
        (LEGACY_BACKEND, True),
        (UNDERSCORE_REQUIREMENT, True),
        (BARE_POETRY_REQUIREMENT, True),
        (ODD_CASING, True),
        (SETUPTOOLS, False),
        (HATCHLING, False),
        (FLIT, False),
    ],
)
def test_recognises_which_projects_poetry_can_read(tmp_path, body, expected):
    assert _is_poetry_project(_pyproject(tmp_path, body)) is expected


def test_a_malformed_pyproject_is_not_assumed_to_be_poetry(tmp_path):
    """Handing an unparseable file to Poetry cannot end well; hand it on."""
    assert _is_poetry_project(_pyproject(tmp_path, "[project\nname = ")) is False


def test_a_missing_pyproject_is_not_assumed_to_be_poetry(tmp_path):
    assert _is_poetry_project(tmp_path / "nope.toml") is False


def _generate(tmp_path, body):
    path = _pyproject(tmp_path, body)
    generator = CycloneDXPyGenerator()
    return generator.generate(
        GenerationInput(lock_file=str(path), output_file=str(tmp_path / "out.json"), output_format="cyclonedx")
    )


def test_a_pep621_project_is_declined_rather_than_failed(tmp_path):
    """Declining hands on; failing is fatal in the container.

    This is the whole point: the same input that produced nothing now
    reaches a generator that can read it.
    """
    result = _generate(tmp_path, SETUPTOOLS)

    assert result.declined, "a failure here aborts the run inside the container"
    assert not result.success
    assert "manifest, not a lock file" in result.error_message


@pytest.mark.parametrize("body", [HATCHLING, FLIT])
def test_other_pep621_backends_are_declined_too(tmp_path, body):
    assert _generate(tmp_path, body).declined


def test_a_poetry_project_is_still_claimed(tmp_path, monkeypatch):
    """The working path must keep working."""
    ran = {}

    def fake_run(cmd, _name, timeout=None):
        ran["cmd"] = list(cmd)

    monkeypatch.setattr("sbomify_action._generation.generators.cyclonedx_py.run_command", fake_run)

    result = _generate(tmp_path, POETRY)

    assert result.success
    assert not result.declined
    assert "poetry" in ran["cmd"]
