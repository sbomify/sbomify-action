"""An SBOM must say whether its versions were recorded or inferred.

A lock file records the versions a project committed to. A manifest records
the versions it would accept. When only the manifest exists, the resolver
picks from whatever the registry offers at that moment -- so the document
describes the day it was generated, not the project.

Measured across 500 open source projects, 112 of 427 successful documents were
built this way and none of them said so. laravel/framework commits no
composer.lock and its document asserted 72 exact versions, each chosen during
the run, each attributed to a composer.lock that does not exist in the
repository at confidence 1.0.
"""

import json
from pathlib import Path

import pytest

from sbomify_action._generation.registry import recommended_action, resolution_was_inferred
from sbomify_action.cli.main import _disclose_inferred_resolution as _disclose


class Cfg:
    def __init__(self, lock_file: str | None = None, bom_type: str | None = None):
        self.lock_file = lock_file
        self.bom_type = bom_type
        self.component_name = None
        self.component_purl = None


def write_sbom(path: Path, *, components: list[dict] | None = None) -> None:
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {"component": {"type": "application", "name": "thing"}},
                "components": components or [],
            }
        )
    )


class TestWhenItCounts:
    def test_a_manifest_with_no_lockfile_beside_it(self, tmp_path):
        (tmp_path / "composer.json").write_text("{}")
        assert resolution_was_inferred(str(tmp_path / "composer.json"))

    def test_a_manifest_with_its_lockfile_committed(self, tmp_path):
        (tmp_path / "composer.json").write_text("{}")
        (tmp_path / "composer.lock").write_text("{}")
        assert not resolution_was_inferred(str(tmp_path / "composer.json"))

    def test_a_lockfile_named_directly(self, tmp_path):
        (tmp_path / "composer.lock").write_text("{}")
        assert not resolution_was_inferred(str(tmp_path / "composer.lock"))

    def test_requirements_txt_counts_as_inferred(self, tmp_path):
        """It may be fully pinned with == or a list of bare names, and nothing
        in the file says which. Overstating the doubt on a pinned one is a
        smaller error than understating it on an unpinned one, and only the
        second puts fiction in a provenance document."""
        (tmp_path / "requirements.txt").write_text("requests\n")
        assert resolution_was_inferred(str(tmp_path / "requirements.txt"))

    @pytest.mark.parametrize(
        "manifest", ["pyproject.toml", "package.json", "Cargo.toml", "pom.xml", "build.gradle", "go.mod"]
    )
    def test_every_manifest_family(self, tmp_path, manifest):
        (tmp_path / manifest).write_text("")
        assert resolution_was_inferred(str(tmp_path / manifest))

    def test_no_input_at_all(self):
        assert not resolution_was_inferred(None)


class TestWhatItSays:
    def test_the_document_records_that_it_was_inferred(self, tmp_path):
        (tmp_path / "composer.json").write_text("{}")
        sbom = tmp_path / "s.json"
        write_sbom(sbom)

        _disclose(str(sbom), Cfg(lock_file=str(tmp_path / "composer.json")))

        props = json.loads(sbom.read_text())["metadata"]["properties"]
        assert any(p["name"] == "sbomify:resolution" and "inferred-at-build-time" in p["value"] for p in props)

    def test_a_committed_lockfile_leaves_the_document_alone(self, tmp_path):
        (tmp_path / "composer.json").write_text("{}")
        (tmp_path / "composer.lock").write_text("{}")
        sbom = tmp_path / "s.json"
        write_sbom(sbom)
        before = sbom.read_text()

        _disclose(str(sbom), Cfg(lock_file=str(tmp_path / "composer.json")))

        assert sbom.read_text() == before

    def test_it_stops_components_citing_a_lockfile_that_was_never_committed(self, tmp_path):
        """The sharp end. cdxgen resolves composer.json by materialising a
        composer.lock, then attributes every component to that file at
        confidence 1.0 -- a source the reader cannot inspect because it never
        existed outside the container."""
        (tmp_path / "composer.json").write_text("{}")
        sbom = tmp_path / "s.json"
        write_sbom(
            sbom,
            components=[
                {
                    "name": "guzzle",
                    "version": "7.15.3",
                    "evidence": {
                        "identity": [
                            {
                                "field": "purl",
                                "concludedValue": "composer.lock",
                                "confidence": 1.0,
                                "methods": [
                                    {"technique": "manifest-analysis", "value": "composer.lock", "confidence": 1.0}
                                ],
                            }
                        ]
                    },
                }
            ],
        )

        _disclose(str(sbom), Cfg(lock_file=str(tmp_path / "composer.json")))

        identity = json.loads(sbom.read_text())["components"][0]["evidence"]["identity"][0]
        assert identity["concludedValue"] == "composer.json"
        assert identity["confidence"] <= 0.5
        assert identity["methods"][0]["value"] == "composer.json"

    def test_an_unreadable_document_does_not_fail_the_run(self, tmp_path):
        (tmp_path / "composer.json").write_text("{}")
        sbom = tmp_path / "s.json"
        sbom.write_text("{ not json")

        _disclose(str(sbom), Cfg(lock_file=str(tmp_path / "composer.json")))

        assert sbom.read_text() == "{ not json"


class TestTheRecommendedAction:
    """ "Your versions were inferred" tells a reader their document is worse
    without telling them how to make it better. Every manifest gets the
    command that fixes it, in its own ecosystem's terms."""

    @pytest.mark.parametrize(
        ("manifest", "expect_command", "expect_in_detail"),
        [
            ("composer.json", "composer update", "composer.lock"),
            ("package.json", "npm install", "lock file"),
            ("pyproject.toml", "uv lock", "uv.lock"),
            ("Cargo.toml", "cargo generate-lockfile", "Cargo.lock"),
            ("Package.swift", "swift package resolve", "Package.resolved"),
            ("requirements.txt", "pip-compile", "=="),
        ],
    )
    def test_each_manifest_gets_its_own_remedy(self, manifest, expect_command, expect_in_detail):
        action = recommended_action(f"/w/{manifest}")
        assert action is not None
        assert expect_command in action[0]
        assert expect_in_detail in action[1]

    @pytest.mark.parametrize("manifest", ["pom.xml", "build.gradle", "build.gradle.kts", "build.sbt"])
    def test_the_jvm_says_what_to_do_instead_of_naming_a_file(self, manifest):
        """Maven, Gradle and sbt have no lock file by convention. Telling
        someone to commit one would be advice they cannot follow."""
        action = recommended_action(f"/w/{manifest}")
        assert action is not None
        assert action[0] == "", "there is no command that writes a lock file for these"
        # What the four share is not a word but a direction: get the SBOM
        # from the build, where the resolved graph actually exists.
        assert "build" in action[1]

    def test_the_remedy_is_written_into_the_document(self, tmp_path):
        """The console is read by whoever generated it; the file is read by
        whoever later asks why the versions do not match production."""
        (tmp_path / "composer.json").write_text("{}")
        sbom = tmp_path / "s.json"
        write_sbom(sbom)

        _disclose(str(sbom), Cfg(lock_file=str(tmp_path / "composer.json")))

        props = json.loads(sbom.read_text())["metadata"]["properties"]
        remedy = [p for p in props if p["name"] == "sbomify:resolution:remedy"]
        assert remedy and "composer update" in remedy[0]["value"]
