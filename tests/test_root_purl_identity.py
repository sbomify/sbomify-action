"""The root component must not identify itself by the directory it was mounted at.

Generators name the root component after the directory they are pointed at.
In this image that is ``/workspace`` for every project, so the field consumers
treat as identity is the same string for everyone. Measured across 500 open
source projects, thirty documents shared five PURLs -- fastapi, flask,
transformers and airbyte all claiming ``pkg:pypi/workspace@latest``.

The repair is narrow on purpose. Most of these tests are about what it must
leave alone.
"""

import json
import sys
from pathlib import Path

import pytest

from sbomify_action.cli.main import _repair_directory_derived_purl

#: The module object, fetched from sys.modules rather than imported.
#: `sbomify_action.cli` re-exports the click command as `main`, so both
#: `from sbomify_action.cli import main` and `import sbomify_action.cli.main
#: as m` hand back the function -- the attribute lookup finds the export,
#: not the submodule. Patching needs the module.
cli_main = sys.modules["sbomify_action.cli.main"]


class Cfg:
    """Minimal stand-in for Config.

    Follows the pattern MockPurlConfig already sets in
    test_augmentation_module.py: the function under test reads one field, and
    constructing the real Config would demand token, component_id and other
    unrelated required arguments.
    """

    def __init__(self, component_name: str | None = None):
        self.component_name = component_name
        self.component_purl = None


def write_sbom(path: Path, *, name: str, purl: str | None, version: str = "1.0.0") -> None:
    component: dict = {"type": "application", "name": name, "version": version}
    if purl:
        component["purl"] = purl
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {"component": component},
                "components": [],
            }
        )
    )


def root_purl(path: Path) -> str | None:
    return json.loads(path.read_text())["metadata"]["component"].get("purl")


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A working directory named 'workspace', as the container mounts it."""
    d = tmp_path / "workspace"
    d.mkdir()
    monkeypatch.setenv("WORKING_DIR", str(d))
    return d


class TestItRepairs:
    def test_a_purl_named_after_the_mount_point(self, tmp_path, workspace):
        sbom = tmp_path / "s.json"
        write_sbom(sbom, name="rails", purl="pkg:gem/workspace@1.0.0")

        _repair_directory_derived_purl(str(sbom), Cfg(component_name="rails"))

        assert root_purl(sbom) == "pkg:generic/rails@1.0.0"

    def test_two_projects_stop_colliding(self, tmp_path, workspace):
        """The actual defect: distinct projects sharing one identity."""
        purls = []
        for project in ("fastapi", "flask"):
            sbom = tmp_path / f"{project}.json"
            write_sbom(sbom, name=project, purl="pkg:pypi/workspace@latest", version="latest")
            _repair_directory_derived_purl(str(sbom), Cfg(component_name=project))
            purls.append(root_purl(sbom))

        assert purls == ["pkg:generic/fastapi@latest", "pkg:generic/flask@latest"]
        assert len(set(purls)) == 2, "the two projects still share an identity"

    def test_it_does_not_assert_a_registry_identity(self, tmp_path, workspace):
        """pkg:npm/workspace must not become pkg:npm/rails.

        A PURL is resolvable. npm's `rails` package is not the Ruby framework's
        asset pipeline, and pointing at somebody else's package is worse than
        pointing nowhere.
        """
        sbom = tmp_path / "s.json"
        write_sbom(sbom, name="rails", purl="pkg:npm/workspace@1.0.0")

        _repair_directory_derived_purl(str(sbom), Cfg(component_name="rails"))

        assert root_purl(sbom) == "pkg:generic/rails@1.0.0"
        assert "pkg:npm/rails" != root_purl(sbom)

    @pytest.mark.parametrize(
        ("component_name", "expected"),
        [
            ("My Product", "pkg:generic/my-product@1.0.0"),
            ("@scope/name", "pkg:generic/scope-name@1.0.0"),
            ("Owner/Repo", "pkg:generic/repo@1.0.0"),
            ("Trailing--Dashes--", "pkg:generic/trailing-dashes@1.0.0"),
        ],
    )
    def test_an_awkward_component_name_still_produces_a_usable_purl(
        self, tmp_path, workspace, component_name, expected
    ):
        """COMPONENT_NAME is free text reaching a field that is not.

        PackageURL does not reject these, which is the point -- it reshapes
        them silently. A space percent-encodes; a slash is read as a namespace
        separator and restructures the identity. The repair runs the name
        through the same sanitiser the rest of the codebase uses rather than
        inventing a third spelling.
        """
        sbom = tmp_path / "s.json"
        write_sbom(sbom, name=component_name, purl="pkg:gem/workspace@1.0.0")

        _repair_directory_derived_purl(str(sbom), Cfg(component_name=component_name))

        assert root_purl(sbom) == expected


class TestItLeavesAlone:
    def test_a_purl_that_already_names_the_project(self, tmp_path, workspace):
        sbom = tmp_path / "s.json"
        write_sbom(sbom, name="rails", purl="pkg:gem/rails@1.0.0")

        _repair_directory_derived_purl(str(sbom), Cfg(component_name="rails"))

        assert root_purl(sbom) == "pkg:gem/rails@1.0.0"

    def test_a_display_name_that_differs_from_the_package_name(self, tmp_path, monkeypatch):
        """COMPONENT_NAME is a label; the PURL name is a package. They differ
        legitimately, and rewriting on mismatch alone would be a regression."""
        d = tmp_path / "src"
        d.mkdir()
        monkeypatch.setenv("WORKING_DIR", str(d))
        sbom = tmp_path / "s.json"
        write_sbom(sbom, name="My Product", purl="pkg:npm/my-product@2.0.0")

        _repair_directory_derived_purl(str(sbom), Cfg(component_name="My Product"))

        assert root_purl(sbom) == "pkg:npm/my-product@2.0.0"

    def test_a_directory_that_genuinely_is_the_project_name(self, tmp_path, monkeypatch):
        d = tmp_path / "rails"
        d.mkdir()
        monkeypatch.setenv("WORKING_DIR", str(d))
        sbom = tmp_path / "s.json"
        write_sbom(sbom, name="rails", purl="pkg:gem/rails@1.0.0")

        _repair_directory_derived_purl(str(sbom), Cfg(component_name="rails"))

        assert root_purl(sbom) == "pkg:gem/rails@1.0.0"

    def test_a_document_with_no_root_purl(self, tmp_path, workspace):
        sbom = tmp_path / "s.json"
        write_sbom(sbom, name="rails", purl=None)

        _repair_directory_derived_purl(str(sbom), Cfg(component_name="rails"))

        assert root_purl(sbom) is None

    def test_no_component_name_to_compare_against(self, tmp_path, workspace):
        sbom = tmp_path / "s.json"
        write_sbom(sbom, name="workspace", purl="pkg:gem/workspace@1.0.0")

        _repair_directory_derived_purl(str(sbom), Cfg())

        assert root_purl(sbom) == "pkg:gem/workspace@1.0.0"

    def test_an_unreadable_document_does_not_fail_the_run(self, tmp_path, workspace):
        """Identity repair is a courtesy; it must never be why a run fails."""
        sbom = tmp_path / "s.json"
        sbom.write_text("{ not json")

        _repair_directory_derived_purl(str(sbom), Cfg(component_name="rails"))

        assert sbom.read_text() == "{ not json"


class TestTheAuditTrail:
    def test_the_change_is_attributed_to_the_action_not_the_api(self, tmp_path, workspace, monkeypatch):
        """The value is derived locally from COMPONENT_NAME, and nothing is
        fetched. record_augmentation defaults its source to "sbomify-api", so
        leaving it unset would have the trail claim the API supplied this --
        the one kind of wrong an audit trail cannot afford."""
        recorded: list[dict] = []

        class Trail:
            def record_augmentation(self, field, value, old_value=None, source="sbomify-api"):
                recorded.append({"field": field, "value": value, "old": old_value, "source": source})

        monkeypatch.setattr(cli_main, "get_audit_trail", lambda: Trail())
        sbom = tmp_path / "s.json"
        write_sbom(sbom, name="rails", purl="pkg:gem/workspace@1.0.0")

        _repair_directory_derived_purl(str(sbom), Cfg(component_name="rails"))

        assert recorded == [
            {
                "field": "component.purl",
                "value": "pkg:generic/rails@1.0.0",
                "old": "pkg:gem/workspace@1.0.0",
                "source": "sbomify-action",
            }
        ]
