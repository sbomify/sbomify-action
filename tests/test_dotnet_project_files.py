"""A .NET project is usually a .csproj and nothing else.

`packages.lock.json` only exists if a project opts into NuGet lock files,
which most do not. Of ten .NET repositories surveyed, five had no recognised
input at all, and the other five matched on a stray file belonging to
something else -- `quartznet` was described as 627 JavaScript packages from
a `package-lock.json`, `FluentValidation` as 13 Python packages from
`docs/requirements.txt`. So .NET was nominally supported and almost never
actually detected.

cdxgen reads a project file directly, without the SDK and without a lock
file. Verified against AutoMapper, which commits no lock file: 10 components
from its PackageReference set.
"""

import pytest

from sbomify_action._generation.generators.cdxgen import CdxgenFsGenerator
from sbomify_action._generation.protocol import GenerationInput
from sbomify_action._generation.utils import (
    get_lock_file_ecosystem,
    is_supported_input,
)
from sbomify_action.cli.wizard.discovery import discover


@pytest.mark.parametrize("name", ["AutoMapper.csproj", "App.fsproj", "Legacy.vbproj", "Solution.sln"])
def test_project_files_are_recognised_as_dotnet(name):
    assert is_supported_input(name)
    assert get_lock_file_ecosystem(name) == "dotnet"


@pytest.mark.parametrize("name", ["README.md", "notes.txt", "Makefile", "project.csproj.bak"])
def test_unrelated_files_are_not(name):
    """Suffix matching must not become a catch-all."""
    assert not is_supported_input(name)


def test_cdxgen_claims_a_project_file(tmp_path):
    project = tmp_path / "AutoMapper.csproj"
    project.write_text("<Project />")

    claimed = CdxgenFsGenerator().supports(
        GenerationInput(lock_file=str(project), output_file=str(tmp_path / "o.json"), output_format="cyclonedx")
    )

    assert claimed


def test_the_wizard_offers_a_csproj(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "AutoMapper.csproj").write_text("<Project />")

    found = discover(tmp_path)

    assert [str(f.rel_path) for f in found] == ["src/AutoMapper.csproj"]
    assert found[0].ecosystem == "dotnet"


def test_a_lock_file_still_outranks_the_project_file(tmp_path):
    """Where a project does opt into NuGet lock files, that is the better read."""
    (tmp_path / "App.csproj").write_text("<Project />")
    (tmp_path / "packages.lock.json").write_text("{}")

    found = discover(tmp_path)

    assert [str(f.rel_path) for f in found] == ["packages.lock.json"]


def test_a_solution_outranks_a_project(tmp_path):
    """The solution describes the whole tree; a single project is a slice of it."""
    (tmp_path / "Everything.sln").write_text("")
    (tmp_path / "One.csproj").write_text("<Project />")

    found = discover(tmp_path)

    assert [str(f.rel_path) for f in found] == ["Everything.sln"]
