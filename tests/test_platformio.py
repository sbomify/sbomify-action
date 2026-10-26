"""PlatformIO projects: platformio.ini plus what `pio pkg install` recorded.

The fixtures mirror what PlatformIO 6.2 writes: a `.piopm` beside each
registry library, and inside `.git/` for a library installed from git.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from sbomify_action._generation.generators.platformio import PlatformIOGenerator
from sbomify_action._generation.protocol import GenerationInput
from sbomify_action._generation.registry import (
    RECOMMENDED_ACTION,
    records_a_resolution,
    resolution_was_inferred,
)
from sbomify_action._hash_enrichment.enricher import create_default_registry
from sbomify_action._hash_enrichment.models import normalize_package_name
from sbomify_action._hash_enrichment.parsers.platformio import PlatformIOParser, _registry_versions
from sbomify_action._platformio import (
    InstalledLibrary,
    _satisfies,
    declared_lib_deps,
    installed_libraries,
    lib_deps_are_pinned,
    libdeps_dir,
    resolve,
)
from sbomify_action.validation import validate_sbom_file_auto

COMMIT = "5438181440c71cf30bbdc347b0b1597ae3ebf77d"

INI = """\
[env]
lib_deps =
    bblanchon/ArduinoJson@^7.0.0

[env:cyd]
platform = espressif32
lib_deps =
    ${env.lib_deps}
    https://github.com/lovyan03/LovyanGFX.git#1.2.7
    knolleary/PubSubClient@2.8 ; mqtt

[env:native]
platform = native
"""


@pytest.fixture(autouse=True)
def _isolated_core_dir(tmp_path, monkeypatch):
    """Platforms and packages come from PlatformIO's core dir; never the real one."""
    monkeypatch.setenv("PLATFORMIO_CORE_DIR", str(tmp_path / "core"))
    for variable in ("PLATFORMIO_PLATFORMS_DIR", "PLATFORMIO_PACKAGES_DIR", "PLATFORMIO_LIBDEPS_DIR"):
        monkeypatch.delenv(variable, raising=False)


def _registry_library(env_dir: Path, name: str, version: str, owner: str) -> None:
    library = env_dir / name
    library.mkdir(parents=True)
    spec = {"owner": owner, "id": 1, "name": name, "requirements": None, "uri": None}
    (library / ".piopm").write_text(json.dumps({"type": "library", "name": name, "version": version, "spec": spec}))
    # The author's manifest. Present on purpose: it must not be what is read.
    (library / "library.json").write_text(json.dumps({"name": name, "version": "0.0.0-author"}))


def _git_library(env_dir: Path, name: str, version: str, uri: str) -> None:
    git = env_dir / name / ".git"
    git.mkdir(parents=True)
    (git / "HEAD").write_text(f"{COMMIT}\n")
    spec = {"owner": None, "id": None, "name": name, "requirements": None, "uri": uri}
    (git / ".piopm").write_text(json.dumps({"type": "library", "name": name, "version": version, "spec": spec}))


def _project(tmp_path: Path, ini: str = INI) -> Path:
    ini_path = tmp_path / "platformio.ini"
    ini_path.write_text(ini)
    cyd = tmp_path / ".pio" / "libdeps" / "cyd"
    native = tmp_path / ".pio" / "libdeps" / "native"
    _registry_library(cyd, "ArduinoJson", "7.4.3", "bblanchon")
    _registry_library(cyd, "PubSubClient", "2.8.0", "knolleary")
    _git_library(cyd, "LovyanGFX", "1.2.7+sha.5438181", "git+https://github.com/lovyan03/LovyanGFX.git#1.2.7")
    # The same library again for another environment.
    _registry_library(native, "ArduinoJson", "7.4.3", "bblanchon")
    (cyd / "integrity.dat").write_text("bblanchon/ArduinoJson@^7.0.0\n")
    return ini_path


class TestInstalledLibraries:
    def test_each_library_is_read_once_across_environments(self, tmp_path):
        libraries = installed_libraries(_project(tmp_path))
        assert sorted(library.name for library in libraries) == ["ArduinoJson", "LovyanGFX", "PubSubClient"]

    def test_the_resolver_record_wins_over_the_author_manifest(self, tmp_path):
        libraries = {library.name: library for library in installed_libraries(_project(tmp_path))}
        assert libraries["ArduinoJson"].version == "7.4.3"
        assert libraries["ArduinoJson"].owner == "bblanchon"

    def test_git_libraries_carry_their_source_and_full_commit(self, tmp_path):
        libraries = {library.name: library for library in installed_libraries(_project(tmp_path))}
        lovyan = libraries["LovyanGFX"]
        assert lovyan.uri == "git+https://github.com/lovyan03/LovyanGFX.git#1.2.7"
        assert lovyan.commit == COMMIT
        assert not lovyan.from_registry

    def test_a_branch_checkout_resolves_through_the_ref(self, tmp_path):
        git = tmp_path / ".git"
        (git / "refs" / "heads").mkdir(parents=True)
        (git / "HEAD").write_text("ref: refs/heads/main\n")
        (git / "refs" / "heads" / "main").write_text(f"{COMMIT}\n")
        spec = {"owner": None, "uri": "git+https://example.com/lib.git"}
        (git / ".piopm").write_text(json.dumps({"type": "library", "name": "lib", "version": "1.0.0", "spec": spec}))
        from sbomify_action._platformio import _read_metadata

        library = _read_metadata(tmp_path)
        assert library is not None
        assert library.commit == COMMIT

    def test_directories_without_metadata_or_of_other_types_are_skipped(self, tmp_path):
        ini_path = _project(tmp_path)
        cyd = tmp_path / ".pio" / "libdeps" / "cyd"
        (cyd / "Hand-copied").mkdir()
        (cyd / "Broken").mkdir()
        (cyd / "Broken" / ".piopm").write_text("{not json")
        (cyd / "Tool").mkdir()
        (cyd / "Tool" / ".piopm").write_text(json.dumps({"type": "tool", "name": "x", "version": "1"}))
        assert len(installed_libraries(ini_path)) == 3

    def test_nothing_installed_is_an_empty_list(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(INI)
        assert installed_libraries(ini_path) == []

    def test_a_relocated_libdeps_dir_is_honoured(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[platformio]\nlibdeps_dir = deps\n\n[env:x]\nlib_deps = a/b@1.0.0\n")
        assert libdeps_dir(ini_path) == tmp_path / "deps"
        _registry_library(tmp_path / "deps" / "x", "b", "1.0.0", "a")
        assert [library.name for library in installed_libraries(ini_path)] == ["b"]

    def test_a_relocated_workspace_is_honoured(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[platformio]\nworkspace_dir = build\n")
        assert libdeps_dir(ini_path) == tmp_path / "build" / "libdeps"


class TestWhereLibrariesAre:
    def test_a_home_relative_workspace_is_expanded(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[platformio]\nworkspace_dir = ~/pio-ws\n")
        assert libdeps_dir(ini_path) == tmp_path / "home" / "pio-ws" / "libdeps"

    def test_project_dir_is_interpolated(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[platformio]\nworkspace_dir = ${PROJECT_DIR}/../build/.pio\n")
        assert libdeps_dir(ini_path) == tmp_path / ".." / "build" / ".pio" / "libdeps"

    def test_environment_variables_override_the_file(self, tmp_path, monkeypatch):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[platformio]\nlibdeps_dir = deps\n")
        monkeypatch.setenv("PLATFORMIO_LIBDEPS_DIR", str(tmp_path / "elsewhere"))
        assert libdeps_dir(ini_path) == tmp_path / "elsewhere"

    def test_workspace_variable_moves_libdeps_with_it(self, tmp_path, monkeypatch):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\n")
        monkeypatch.setenv("PLATFORMIO_WORKSPACE_DIR", str(tmp_path / "ws"))
        assert libdeps_dir(ini_path) == tmp_path / "ws" / "libdeps"

    def test_an_unresolvable_location_is_reported_not_guessed(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[platformio]\nlibdeps_dir = ${missing.dir}\n\n[env:x]\nlib_deps = a/b@1.0.0\n")
        assert libdeps_dir(ini_path) is None
        result = PlatformIOGenerator().generate(
            GenerationInput(lock_file=str(ini_path), output_file=str(tmp_path / "o.json"), output_format="cyclonedx")
        )
        assert "PLATFORMIO_LIBDEPS_DIR" in (result.error_message or "")

    def test_packed_refs_still_give_the_full_commit(self, tmp_path):
        from sbomify_action._platformio import _git_commit

        git = tmp_path / ".git"
        git.mkdir()
        (git / "HEAD").write_text("ref: refs/heads/master\n")
        (git / "packed-refs").write_text(
            f"# pack-refs with: peeled\n{'0' * 40} refs/tags/x\n{COMMIT} refs/heads/master\n"
        )
        assert _git_commit(git) == COMMIT

    def test_environments_no_longer_configured_are_not_read(self, tmp_path):
        ini_path = _project(tmp_path)
        _registry_library(tmp_path / ".pio" / "libdeps" / "removed-env", "Stale", "1.0.0", "someone")
        assert "Stale" not in {library.name for library in installed_libraries(ini_path)}

    def test_one_purl_is_one_component(self, tmp_path):
        """Same commit reached through two refs is one bom-ref, so one component."""
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(
            "[env:a]\nlib_deps = https://github.com/o/gfx.git#1.2.7\n\n"
            f"[env:b]\nlib_deps = https://github.com/o/gfx.git#{COMMIT}\n"
        )
        _git_library(
            tmp_path / ".pio" / "libdeps" / "a", "Gfx", "1.2.7+sha.5438181", "git+https://github.com/o/gfx.git#1.2.7"
        )
        _git_library(
            tmp_path / ".pio" / "libdeps" / "b",
            "Gfx",
            "1.2.7+sha.5438181",
            f"git+https://github.com/o/gfx.git#{COMMIT}",
        )
        assert len(installed_libraries(ini_path)) == 1


class TestPurls:
    def test_registry_library(self):
        library = InstalledLibrary(name="ArduinoJson", version="7.4.3", owner="bblanchon")
        assert library.purl == (
            "pkg:generic/bblanchon/ArduinoJson@7.4.3?repository_url=https://registry.platformio.org"
        )

    def test_github_library_is_pinned_to_its_commit(self):
        library = InstalledLibrary(
            name="LovyanGFX",
            version="1.2.7+sha.5438181",
            uri="git+https://github.com/lovyan03/LovyanGFX.git#1.2.7",
            commit=COMMIT,
        )
        assert library.purl == f"pkg:github/lovyan03/lovyangfx@{COMMIT}"

    def test_other_git_hosts_keep_the_vcs_url(self):
        library = InstalledLibrary(
            name="lib", version="1.0.0", uri="git+https://git.example.com/team/lib.git#v1", commit=COMMIT
        )
        assert library.purl.startswith("pkg:generic/lib@1.0.0?vcs_url=")
        assert COMMIT in library.purl


class TestArchives:
    def test_an_archive_is_a_download_not_a_git_source(self):
        library = InstalledLibrary(name="lib", version="1.0.0", uri="https://example.com/archive/v1.0.0.zip")
        assert not library.from_git
        assert library.purl.startswith("pkg:generic/lib@1.0.0?download_url=")

    def test_a_library_without_an_owner_does_not_claim_the_registry(self):
        assert InstalledLibrary(name="lib", version="1.0.0").purl == "pkg:generic/lib@1.0.0"


class TestLibDepsPinning:
    def _ini(self, tmp_path: Path, lib_deps: str) -> Path:
        path = tmp_path / "platformio.ini"
        path.write_text(f"[env:x]\nlib_deps =\n{lib_deps}\n")
        return path

    def test_each_env_resolves_through_env_inheritance_and_interpolation(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(INI)
        # [env:native] has no lib_deps of its own, so it inherits [env]'s.
        assert declared_lib_deps(ini_path) == [
            "bblanchon/ArduinoJson@^7.0.0",
            "https://github.com/lovyan03/LovyanGFX.git#1.2.7",
            "knolleary/PubSubClient@2.8",
        ]

    def test_a_range_is_not_pinned(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(INI)
        assert not lib_deps_are_pinned(ini_path)

    def test_exact_versions_tags_commits_and_local_paths_are_pinned(self, tmp_path):
        path = self._ini(
            tmp_path,
            "    bblanchon/ArduinoJson @ 7.4.3\n"
            "    knolleary/PubSubClient@=2.8.0\n"
            "    https://github.com/lovyan03/LovyanGFX.git#1.2.7\n"
            f"    https://github.com/o/r.git#{COMMIT}\n"
            "    https://example.com/lib-1.0.0.zip\n"
            "    file://../local-lib\n",
        )
        assert lib_deps_are_pinned(path)

    @pytest.mark.parametrize(
        "entry",
        [
            # semantic_version treats a partial version as a wildcard:
            # @2.8 accepts 2.8.0 and 2.8.1.
            "knolleary/PubSubClient@2.8",
            "knolleary/PubSubClient@=2.8",
            "knolleary/PubSubClient@1",
            "bblanchon/ArduinoJson@^7.0.0",
            "bblanchon/ArduinoJson@~7.4.0",
            "bblanchon/ArduinoJson@>=7.0.0",
            "bblanchon/ArduinoJson@v7.4.3",
            "bblanchon/ArduinoJson",
            "https://github.com/lovyan03/LovyanGFX.git",
            "https://github.com/lovyan03/LovyanGFX.git#develop",
            "https://github.com/lovyan03/LovyanGFX",
        ],
    )
    def test_anything_that_can_resolve_differently_is_not_pinned(self, tmp_path, entry):
        assert not lib_deps_are_pinned(self._ini(tmp_path, f"    {entry}"))

    def test_an_inline_hash_comment_is_not_part_of_the_entry(self, tmp_path):
        assert lib_deps_are_pinned(self._ini(tmp_path, "    bblanchon/ArduinoJson@7.4.3  # pinned"))

    def test_a_single_line_list_splits_on_comma_space(self, tmp_path):
        path = tmp_path / "platformio.ini"
        path.write_text("[env:x]\nlib_deps = a/b@1.0.0, c/d@^2.0.0\n")
        assert declared_lib_deps(path) == ["a/b@1.0.0", "c/d@^2.0.0"]

    def test_a_range_behind_a_common_section_is_found(self, tmp_path):
        path = tmp_path / "platformio.ini"
        path.write_text(
            "[common]\nlib_deps = bblanchon/ArduinoJson@^7.0.0\n\n[env:esp32]\nlib_deps = ${common.lib_deps}\n"
        )
        assert declared_lib_deps(path) == ["bblanchon/ArduinoJson@^7.0.0"]
        assert not lib_deps_are_pinned(path)

    def test_extends_is_followed(self, tmp_path):
        path = tmp_path / "platformio.ini"
        path.write_text("[base]\nlib_deps = a/b@^1.0.0\n\n[env:x]\nextends = base\nplatform = native\n")
        assert declared_lib_deps(path) == ["a/b@^1.0.0"]

    def test_extra_configs_are_read(self, tmp_path):
        (tmp_path / "libs.ini").write_text("[env:x]\nlib_deps = a/b@^1.0.0\n")
        path = tmp_path / "platformio.ini"
        path.write_text("[platformio]\nextra_configs = libs.ini\n\n[env:x]\nplatform = native\n")
        assert declared_lib_deps(path) == ["a/b@^1.0.0"]

    def test_this_env_resolves_to_the_environment_name(self, tmp_path):
        path = tmp_path / "platformio.ini"
        path.write_text("[env:x]\nlib_deps = owner/lib-${this.__env__}@1.0.0\n")
        assert declared_lib_deps(path) == ["owner/lib-x@1.0.0"]

    def test_an_unresolvable_reference_is_not_pinned(self, tmp_path):
        path = tmp_path / "platformio.ini"
        path.write_text("[env:x]\nlib_deps = ${missing.lib_deps}\n")
        assert declared_lib_deps(path) == ["${missing.lib_deps}"]
        assert not lib_deps_are_pinned(path)

    def test_no_lib_deps_is_not_a_recorded_resolution(self, tmp_path):
        path = tmp_path / "platformio.ini"
        path.write_text("[env:x]\nplatform = native\n")
        assert not lib_deps_are_pinned(path)

    def test_the_pipeline_discloses_unpinned_lib_deps(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(INI)
        assert resolution_was_inferred(str(ini_path))
        assert not records_a_resolution(str(ini_path))
        assert "platformio.ini" in RECOMMENDED_ACTION

    def test_the_pipeline_trusts_pinned_lib_deps(self, tmp_path):
        path = self._ini(tmp_path, "    bblanchon/ArduinoJson@7.4.3")
        assert not resolution_was_inferred(str(path))
        assert records_a_resolution(str(path))


class TestGenerator:
    def test_it_claims_platformio_ini_and_nothing_else(self, tmp_path):
        generator = PlatformIOGenerator()
        assert generator.supports(GenerationInput(lock_file=str(tmp_path / "platformio.ini"), output_file="o.json"))
        assert not generator.supports(GenerationInput(lock_file=str(tmp_path / "library.json"), output_file="o.json"))

    def test_it_rejects_an_unsupported_spec_version(self, tmp_path):
        generator = PlatformIOGenerator()
        assert not generator.supports(
            GenerationInput(lock_file=str(tmp_path / "platformio.ini"), output_file="o.json", spec_version="9.9")
        )

    def test_it_writes_one_component_per_installed_library(self, tmp_path):
        output = tmp_path / "out" / "sbom.json"
        result = PlatformIOGenerator().generate(
            GenerationInput(lock_file=str(_project(tmp_path)), output_file=str(output), output_format="cyclonedx")
        )
        assert result.success
        document = json.loads(output.read_text())
        assert document["metadata"]["component"]["type"] == "firmware"
        components = {component["name"]: component for component in document["components"]}
        assert set(components) == {"ArduinoJson", "LovyanGFX", "PubSubClient"}
        assert components["ArduinoJson"]["group"] == "bblanchon"
        assert components["LovyanGFX"]["externalReferences"][0]["type"] == "vcs"
        assert components["LovyanGFX"]["purl"].endswith(COMMIT)

    def test_spdx_is_written_directly(self, tmp_path):
        """No syft round trip: sbomify is the creator, there is no empty root, names stay names."""
        output = tmp_path / "sbom.spdx.json"
        result = PlatformIOGenerator().generate(
            GenerationInput(lock_file=str(_project(tmp_path)), output_file=str(output), output_format="spdx")
        )
        assert result.success
        assert result.spec_version == "2.3"
        document = json.loads(output.read_text())
        assert validate_sbom_file_auto(str(output)).valid
        assert document["creationInfo"]["creators"][0].startswith("Tool: sbomify-action-")
        names = [package["name"] for package in document["packages"]]
        assert all(names)
        assert set(names) == {tmp_path.name, "ArduinoJson", "LovyanGFX", "PubSubClient"}
        relationships = {(r["relationshipType"], r["relatedSpdxElement"]) for r in document["relationships"]}
        ids = {package["name"]: package["SPDXID"] for package in document["packages"]}
        assert ("DESCRIBES", ids[tmp_path.name]) in relationships
        assert ("DEPENDS_ON", ids["ArduinoJson"]) in relationships
        purls = {package["name"]: package["externalRefs"][0] for package in document["packages"][1:]}
        assert purls["ArduinoJson"]["referenceCategory"] == "PACKAGE_MANAGER"
        assert purls["ArduinoJson"]["referenceType"] == "purl"

    def test_spdx_2_2_has_no_package_purpose(self, tmp_path):
        output = tmp_path / "sbom.spdx.json"
        PlatformIOGenerator().generate(
            GenerationInput(
                lock_file=str(_project(tmp_path)), output_file=str(output), output_format="spdx", spec_version="2.2"
            )
        )
        document = json.loads(output.read_text())
        assert document["spdxVersion"] == "SPDX-2.2"
        assert all("primaryPackagePurpose" not in package for package in document["packages"])
        assert validate_sbom_file_auto(str(output)).valid

    def test_the_document_names_its_tool(self, tmp_path):
        output = tmp_path / "sbom.json"
        PlatformIOGenerator().generate(
            GenerationInput(lock_file=str(_project(tmp_path)), output_file=str(output), output_format="cyclonedx")
        )
        document = json.loads(output.read_text())
        (tool,) = document["metadata"]["tools"]["components"]
        assert (tool["group"], tool["name"]) == ("sbomify", "sbomify action")
        assert validate_sbom_file_auto(str(output)).valid

    def test_uninstalled_libraries_say_what_to_run(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(INI)
        result = PlatformIOGenerator().generate(
            GenerationInput(lock_file=str(ini_path), output_file=str(tmp_path / "o.json"), output_format="cyclonedx")
        )
        assert not result.success
        assert "pio pkg install" in (result.error_message or "")

    def test_a_project_without_lib_deps_fails_plainly(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nplatform = native\n")
        result = PlatformIOGenerator().generate(
            GenerationInput(lock_file=str(ini_path), output_file=str(tmp_path / "o.json"), output_format="cyclonedx")
        )
        assert not result.success
        assert "declares no lib_deps" in (result.error_message or "")

    def test_direct_dependencies_and_manifest_edges_form_the_graph(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps = adafruit/Adafruit GFX Library@1.11.9\n")
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "Adafruit GFX Library", "1.11.9", "adafruit")
        _registry_library(env, "Adafruit BusIO", "1.16.1", "adafruit")
        # The GFX library's manifest names BusIO, which LDF installed beside it.
        (env / "Adafruit GFX Library" / "library.json").write_text(
            json.dumps({"dependencies": [{"owner": "adafruit", "name": "Adafruit BusIO", "version": "^1.0"}]})
        )
        # library.properties form, pointing at nothing installed.
        (env / "Adafruit BusIO" / "library.json").unlink()
        (env / "Adafruit BusIO" / "library.properties").write_text("name=Adafruit BusIO\ndepends=Wire (>=1.0)\n")
        output = tmp_path / "sbom.json"
        PlatformIOGenerator().generate(
            GenerationInput(lock_file=str(ini_path), output_file=str(output), output_format="cyclonedx")
        )
        document = json.loads(output.read_text())
        graph = {entry["ref"]: entry["dependsOn"] for entry in document["dependencies"]}
        refs = {component["name"]: component["bom-ref"] for component in document["components"]}
        root = document["metadata"]["component"]["bom-ref"]
        # Only what lib_deps names is direct; BusIO hangs off GFX.
        assert graph[root] == [refs["Adafruit GFX Library"]]
        assert graph[refs["Adafruit GFX Library"]] == [refs["Adafruit BusIO"]]
        assert graph[refs["Adafruit BusIO"]] == []

    def test_it_is_registered(self):
        from sbomify_action._generation.generator import create_default_registry as create_generators

        names = [generator["name"] for generator in create_generators().list_generators()]
        assert "platformio" in names


def _response(status: int, body: dict) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.json.return_value = body
    return response


class TestRegistryHashes:
    SHA = "2ffda9c356d109224218da192fdeeab6f024ee8b25bed61a26dc56e38610288a"

    def test_the_registry_may_hold_a_shorter_version(self):
        assert _registry_versions("2.8.0") == ["2.8.0", "2.8"]
        assert _registry_versions("7.4.3") == ["7.4.3"]
        assert _registry_versions("1.0.0") == ["1.0.0", "1.0"]

    def test_registry_libraries_get_the_published_archive_hash(self, tmp_path):
        ini_path = _project(tmp_path)

        def fake_get(url, params, headers, timeout):
            name, version = url.rsplit("/", 1)[-1], params["version"]
            if (name, version) == ("PubSubClient", "2.8"):
                return _response(200, {"version": {"name": "2.8", "files": [{"checksum": {"sha256": self.SHA}}]}})
            if name == "ArduinoJson":
                return _response(200, {"version": {"name": version, "files": [{"checksum": {"sha256": "ab" * 32}}]}})
            return _response(404, {})

        with patch("sbomify_action._hash_enrichment.parsers.platformio.requests.get", side_effect=fake_get) as get:
            hashes = {h.name: h for h in PlatformIOParser().parse(ini_path)}

        assert hashes["PubSubClient"].value == self.SHA
        assert hashes["PubSubClient"].version == "2.8.0"  # matched against what was installed
        assert hashes["ArduinoJson"].value == "ab" * 32
        # Git libraries are pinned by commit in their purl; the registry is not asked.
        assert "LovyanGFX" not in hashes
        assert all("LovyanGFX" not in call.args[0] for call in get.call_args_list)

    def test_an_unreachable_registry_yields_no_hashes(self, tmp_path):
        ini_path = _project(tmp_path)
        with patch(
            "sbomify_action._hash_enrichment.parsers.platformio.requests.get",
            side_effect=requests.ConnectionError("offline"),
        ):
            assert PlatformIOParser().parse(ini_path) == []

    def test_a_version_mismatch_is_not_trusted(self, tmp_path):
        ini_path = _project(tmp_path)
        body = {"version": {"name": "9.9.9", "files": [{"checksum": {"sha256": "cd" * 32}}]}}
        with patch(
            "sbomify_action._hash_enrichment.parsers.platformio.requests.get", return_value=_response(200, body)
        ):
            assert PlatformIOParser().parse(ini_path) == []

    def test_same_name_and_version_from_two_owners_gets_no_hash(self, tmp_path):
        """Matching is by name and version; a hash on the wrong one is worse than none."""
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:a]\nlib_deps = owner1/Foo@1.0.0\n\n[env:b]\nlib_deps = owner2/Foo@1.0.0\n")
        _registry_library(tmp_path / ".pio" / "libdeps" / "a", "Foo", "1.0.0", "owner1")
        _registry_library(tmp_path / ".pio" / "libdeps" / "b", "Foo", "1.0.0", "owner2")
        with patch("sbomify_action._hash_enrichment.parsers.platformio.requests.get") as get:
            assert PlatformIOParser().parse(ini_path) == []
        get.assert_not_called()

    def test_an_unreachable_registry_is_asked_once(self, tmp_path):
        ini_path = _project(tmp_path)
        with patch(
            "sbomify_action._hash_enrichment.parsers.platformio.requests.get",
            side_effect=requests.Timeout("offline"),
        ) as get:
            assert PlatformIOParser().parse(ini_path) == []
        assert get.call_count == 1

    def test_the_archive_for_every_system_is_preferred(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps = o/Lib@1.0.0\n")
        _registry_library(tmp_path / ".pio" / "libdeps" / "x", "Lib", "1.0.0", "o")
        files = [
            {"system": "linux_x86_64", "checksum": {"sha256": "11" * 32}},
            {"system": "*", "checksum": {"sha256": "22" * 32}},
        ]
        body = {"version": {"name": "1.0.0", "files": files}}
        with patch(
            "sbomify_action._hash_enrichment.parsers.platformio.requests.get", return_value=_response(200, body)
        ):
            assert [h.value for h in PlatformIOParser().parse(ini_path)] == ["22" * 32]

    def test_an_unexpected_response_shape_is_ignored(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps = o/Lib@1.0.0\n")
        _registry_library(tmp_path / ".pio" / "libdeps" / "x", "Lib", "1.0.0", "o")
        with patch("sbomify_action._hash_enrichment.parsers.platformio.requests.get", return_value=_response(200, [])):
            assert PlatformIOParser().parse(ini_path) == []

    def test_the_parser_is_registered_for_platformio_ini(self):
        parser = create_default_registry().get_parser_for("platformio.ini")
        assert parser is not None
        assert parser.name == "platformio"

    def test_spdx_names_carry_the_owner(self):
        assert normalize_package_name("bblanchon/ArduinoJson", "platformio") == "arduinojson"
        assert normalize_package_name("ArduinoJson", "platformio") == "arduinojson"


def test_spdx_conversion_hands_syft_absolute_paths(tmp_path, monkeypatch):
    """syft runs in the project directory, so relative paths pointed nowhere."""
    from sbomify_action._generation import utils

    calls = []
    monkeypatch.setattr(utils, "ensure_runtime", lambda *a, **k: None)
    monkeypatch.setattr(utils, "run_command", lambda cmd, *a, **k: calls.append(cmd))
    monkeypatch.chdir(tmp_path)
    utils.convert_to_spdx(Path("staged.cdx.json"), Path("out.json"), tmp_path / "project")
    command = calls[0]
    assert command[2] == str(tmp_path / "staged.cdx.json")
    assert command[-1] == f"spdx-json={tmp_path / 'out.json'}"


def _generate(tmp_path: Path, ini_path: Path, output_format: str = "cyclonedx") -> dict:
    output = tmp_path / f"sbom.{output_format}.json"
    result = PlatformIOGenerator().generate(
        GenerationInput(lock_file=str(ini_path), output_file=str(output), output_format=output_format)
    )
    assert result.success, result.error_message
    assert validate_sbom_file_auto(str(output)).valid
    return json.loads(output.read_text())


def _archive_library(env_dir: Path, name: str, version: str, uri: str, spec_name: str | None = None) -> None:
    library = env_dir / name
    library.mkdir(parents=True)
    spec = {"owner": None, "id": None, "name": spec_name or name, "requirements": None, "uri": uri}
    (library / ".piopm").write_text(json.dumps({"type": "library", "name": name, "version": version, "spec": spec}))


class TestWhatTheBuildUses:
    """The graph is what `pio pkg list` resolves, not every directory on disk."""

    def test_a_library_nothing_reaches_is_not_in_the_firmware(self, tmp_path):
        """A test framework, or a copy left behind when a requirement changed source."""
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps = bblanchon/ArduinoJson@7.4.3\n")
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "ArduinoJson", "7.4.3", "bblanchon")
        _registry_library(env, "Unity", "2.6.1", "throwtheswitch")
        assert [library.name for library in installed_libraries(ini_path)] == ["ArduinoJson"]

    def test_a_named_git_entry_is_direct_and_is_the_git_copy(self, tmp_path):
        """`Name = git+URL#ref` is matched by source, not to a registry copy of the same name."""
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(
            f"[env:x]\nlib_deps =\n    NeoPixelBus = git+https://github.com/Makuna/NeoPixelBus#{COMMIT}\n"
        )
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "NeoPixelBus", "2.8.4", "makuna")
        git = env / f"NeoPixelBus@src-{'a' * 32}" / ".git"
        git.mkdir(parents=True)
        (git / "HEAD").write_text(f"{COMMIT}\n")
        spec = {"owner": None, "name": "NeoPixelBus", "uri": f"git+https://github.com/Makuna/NeoPixelBus#{COMMIT}"}
        (git / ".piopm").write_text(
            json.dumps({"type": "library", "name": "NeoPixelBus", "version": "2.9.0+sha.76afe83", "spec": spec})
        )
        resolution = resolve(ini_path)
        purl = f"pkg:github/makuna/neopixelbus@{COMMIT}"
        assert [library.purl for library in resolution.libraries] == [purl]
        assert purl in resolution.direct

    def test_a_dependency_resolves_to_the_owner_it_names(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps = lowpowerlab/RFM69@1.4.0\n")
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "RFM69", "1.4.0", "lowpowerlab")
        _registry_library(env, "SPIFlash", "101.1.3", "lowpowerlab")
        _archive_library(
            env, "SPIFlash@src-x", "0.0.0+20261021153803", "https://github.com/o/SPIFlash/archive/abc1234.zip"
        )
        (env / "RFM69" / "library.json").write_text(
            json.dumps({"dependencies": [{"owner": "lowpowerlab", "name": "SPIFlash"}]})
        )
        # The archive's own name is what PlatformIO recorded for it.
        piopm = json.loads((env / "SPIFlash@src-x" / ".piopm").read_text())
        (env / "SPIFlash@src-x" / ".piopm").write_text(json.dumps({**piopm, "name": "SPIFlash"}))
        resolution = resolve(ini_path)
        rfm = next(library.purl for library in resolution.libraries if library.name == "RFM69")
        (target,) = resolution.edges[rfm]
        assert "SPIFlash@101.1.3" in target

    def test_the_highest_version_meeting_the_requirement_wins(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps = a/Top@1.0.0\n")
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "Top", "1.0.0", "a")
        _registry_library(env, "Dep", "1.2.0", "a")
        (env / "Dep").rename(env / "Dep@1.2.0")
        _registry_library(env, "Dep", "2.0.0", "a")
        (env / "Top" / "library.json").write_text(json.dumps({"dependencies": {"Dep": "^1.0.0"}}))
        assert {library.version for library in installed_libraries(ini_path)} == {"1.0.0", "1.2.0"}

    def test_a_dependency_for_another_platform_does_not_apply(self, tmp_path):
        """library.json may restrict a dependency to some platforms; the env's own decides."""
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nplatform = espressif32\nlib_deps = a/Server@1.0.0\n")
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "Server", "1.0.0", "a")
        _registry_library(env, "AsyncTCP", "3.4.10", "esp32async")
        _registry_library(env, "ESPAsyncTCP", "1.2.2", "me-no-dev")
        (env / "Server" / "library.json").write_text(
            json.dumps(
                {
                    "dependencies": [
                        {"name": "AsyncTCP", "platforms": "espressif32"},
                        {"name": "ESPAsyncTCP", "platforms": ["espressif8266"]},
                    ]
                }
            )
        )
        platform = tmp_path / "core" / "platforms" / "espressif32"
        platform.mkdir(parents=True)
        (platform / ".piopm").write_text(json.dumps({"type": "platform", "name": "espressif32", "version": "6.9.0"}))
        (platform / "platform.json").write_text(json.dumps({"name": "espressif32", "version": "6.9.0"}))
        assert sorted(library.name for library in installed_libraries(ini_path)) == ["AsyncTCP", "Server"]

    def test_an_entry_that_matches_nothing_keeps_what_is_installed(self, tmp_path, caplog):
        """Unknown is not the same as unused: keep the env's other libraries, and say so."""
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps =\n    a/Known@1.0.0\n    ${missing.lib_deps}\n")
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "Known", "1.0.0", "a")
        _registry_library(env, "Other", "1.0.0", "b")
        assert sorted(library.name for library in installed_libraries(ini_path)) == ["Known", "Other"]
        assert "could not be matched" in caplog.text

    def test_environments_differ_but_one_purl_is_one_component(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:a]\nlib_deps = o/X@1.0.0\n\n[env:b]\nlib_deps = o/X@1.0.0\n")
        _registry_library(tmp_path / ".pio" / "libdeps" / "a", "X", "1.0.0", "o")
        _registry_library(tmp_path / ".pio" / "libdeps" / "b", "X", "1.0.0", "o")
        resolution = resolve(ini_path)
        assert len(resolution.libraries) == 1
        assert resolution.environments == ["a", "b"]

    def test_a_library_in_the_project_lib_dir_is_not_missing(self, tmp_path, caplog):
        """PlatformIO resolves a name in lib/ to the project's own copy; nothing else is pulled in."""
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps =\n    a/Known@1.0.0\n    ESP8266PWM\n")
        (tmp_path / "lib" / "ESP8266PWM").mkdir(parents=True)
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "Known", "1.0.0", "a")
        _registry_library(env, "Orphan", "1.0.0", "b")
        assert [library.name for library in installed_libraries(ini_path)] == ["Known"]
        assert "could not be matched" not in caplog.text


class TestVersionRequirements:
    @pytest.mark.parametrize(
        ("version", "requirement", "expected"),
        [
            ("1.2.3", None, True),
            ("1.2.3", "*", True),
            ("2.8.1", "2.8", True),
            ("2.9.0", "2.8", False),
            ("1.9.0", "^1.2.0", True),
            ("2.0.0", "^1.2.0", False),
            ("0.2.9", "^0.2.3", True),
            ("0.3.0", "^0.2.3", False),
            ("1.2.9", "~1.2.3", True),
            ("1.3.0", "~1.2.3", False),
            ("1.2.5", "~1.2", True),
            ("3.20017.241212", "~3.20017.0", True),
            ("1.5.0", ">=1.5.0-beta", True),
            ("1.4.0", ">=1.0.0, <1.5.0", True),
            ("1.5.0", ">=1.0.0, <1.5.0", False),
            ("1.0.0", "something odd", True),
        ],
    )
    def test_requirements_as_platformio_writes_them(self, version, requirement, expected):
        assert _satisfies(version, requirement) is expected


class TestStableIdentity:
    def test_an_install_timestamp_is_not_a_version(self):
        library = InstalledLibrary(
            name="Arduino-INA226",
            version="0.0.0+20261021153807",
            uri="https://github.com/jarzebski/Arduino-INA226/archive/968a684.zip",
        )
        assert library.stable_version == "968a684"
        assert library.purl == "pkg:github/jarzebski/arduino-ina226@968a684"

    def test_an_install_timestamp_with_nothing_better_is_left_out(self):
        library = InstalledLibrary(name="lib", version="0.0.0+20261021153807", uri="https://example.com/lib.zip")
        assert library.stable_version is None
        assert library.purl == "pkg:generic/lib?download_url=https://example.com/lib.zip"

    @pytest.mark.parametrize(
        ("uri", "purl"),
        [
            (
                "https://github.com/adafruit/Adafruit_BusIO/archive/refs/tags/1.17.4.zip",
                "pkg:github/adafruit/adafruit_busio@1.17.4",
            ),
            ("https://github.com/h2zero/NimBLE-Arduino/archive/2.5.0.zip", "pkg:github/h2zero/nimble-arduino@2.5.0"),
            (
                "https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32-core-3.3.12-libs.tar.xz",
                "pkg:github/espressif/arduino-esp32@3.3.12?download_url=https://github.com/espressif/arduino-esp32"
                "/releases/download/3.3.12/esp32-core-3.3.12-libs.tar.xz",
            ),
            ("https://codeload.github.com/o/r/tar.gz/refs/tags/v1.0.0", "pkg:github/o/r@v1.0.0"),
        ],
    )
    def test_a_github_download_is_a_github_package(self, uri, purl):
        assert InstalledLibrary(name="x", version="9.9.9", uri=uri).purl == purl

    def test_a_timestamp_version_is_not_written(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps = https://example.com/lib.zip\n")
        _archive_library(
            tmp_path / ".pio" / "libdeps" / "x", "lib", "0.0.0+20261021153807", "https://example.com/lib.zip"
        )
        (component,) = _generate(tmp_path, ini_path)["components"]
        assert "version" not in component


class TestAuthorManifest:
    def test_description_licence_authors_and_links_come_from_library_json(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps = makuna/NeoPixelBus@2.8.4\n")
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "NeoPixelBus", "2.8.4", "makuna")
        (env / "NeoPixelBus" / "library.json").write_text(
            json.dumps(
                {
                    "name": "NeoPixelBus",
                    "version": "0.0.0-author",
                    "description": "A library to control NeoPixels",
                    "license": "LGPL-3.0",
                    "authors": [
                        {"name": "Contributor"},
                        {"name": "Michael C. Miller", "email": "makuna@live.com", "maintainer": True},
                    ],
                    "repository": {"type": "git", "url": "https://github.com/Makuna/NeoPixelBus"},
                    "homepage": "https://github.com/Makuna/NeoPixelBus/wiki",
                }
            )
        )
        (component,) = _generate(tmp_path, ini_path)["components"]
        assert component["version"] == "2.8.4"  # never the author's
        assert component["description"] == "A library to control NeoPixels"
        # SPDX deprecated the bare GNU ids for the explicit -only.
        assert component["licenses"] == [{"license": {"id": "LGPL-3.0-only"}}]
        assert component["authors"][0] == {"name": "Michael C. Miller", "email": "makuna@live.com"}
        assert component["supplier"] == {"name": "makuna"}
        assert {"type": "vcs", "url": "https://github.com/Makuna/NeoPixelBus"} in component["externalReferences"]
        assert {"type": "website", "url": "https://github.com/Makuna/NeoPixelBus/wiki"} in component[
            "externalReferences"
        ]

    def test_library_properties_is_read_when_there_is_no_library_json(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps = knolleary/PubSubClient@2.8.0\n")
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "PubSubClient", "2.8.0", "knolleary")
        (env / "PubSubClient" / "library.json").unlink()
        (env / "PubSubClient" / "library.properties").write_text(
            "name=PubSubClient\nversion=2.8\nauthor=Nick O'Leary <nick.oleary@gmail.com>\n"
            "maintainer=Nick O'Leary <nick.oleary@gmail.com>\nsentence=A client library for MQTT messaging.\n"
            "url=http://pubsubclient.knolleary.net\nlicense=MIT\n"
        )
        (component,) = _generate(tmp_path, ini_path)["components"]
        assert component["description"] == "A client library for MQTT messaging."
        assert component["licenses"] == [{"license": {"id": "MIT"}}]
        assert component["authors"] == [{"name": "Nick O'Leary", "email": "nick.oleary@gmail.com"}]

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            (
                "MIT License\n\nPermission is hereby granted, free of charge, to any person ... The above copyright "
                "notice and this permission notice shall be included in all copies",
                {"license": {"id": "MIT"}},
            ),
            ("Apache License\nVersion 2.0, January 2004", {"license": {"id": "Apache-2.0"}}),
            (
                "Redistribution and use in source and binary forms ... Neither the name of the copyright holder",
                {"license": {"id": "BSD-3-Clause"}},
            ),
            ("Redistribution and use in source and binary forms, with or without", {"license": {"id": "BSD-2-Clause"}}),
            # The text cannot say -only or -or-later, so it is named, not identified.
            (
                "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1, February 1999",
                {"license": {"name": "GNU Lesser General Public License v2.1"}},
            ),
        ],
    )
    def test_a_licence_file_is_read_when_the_manifest_has_none(self, tmp_path, text, expected):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps = a/Lib@1.0.0\n")
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "Lib", "1.0.0", "a")
        (env / "Lib" / "LICENSE.txt").write_text(text)
        (component,) = _generate(tmp_path, ini_path)["components"]
        assert component["licenses"] == [expected]

    def test_an_unrecognised_licence_file_claims_nothing(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps = a/Lib@1.0.0\n")
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "Lib", "1.0.0", "a")
        (env / "Lib" / "LICENSE").write_text("All rights reserved.")
        (component,) = _generate(tmp_path, ini_path)["components"]
        assert "licenses" not in component

    def test_a_licence_off_the_spdx_list_is_kept_as_a_name(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nlib_deps = a/Lib@1.0.0\n")
        env = tmp_path / ".pio" / "libdeps" / "x"
        _registry_library(env, "Lib", "1.0.0", "a")
        (env / "Lib" / "library.json").write_text(json.dumps({"license": "Custom Licence 1.0"}))
        (component,) = _generate(tmp_path, ini_path)["components"]
        assert component["licenses"] == [{"license": {"name": "Custom Licence 1.0"}}]
        spdx = _generate(tmp_path, ini_path, "spdx")
        package = next(p for p in spdx["packages"] if p["name"] == "Lib")
        assert package["licenseDeclared"] == "LicenseRef-Custom-Licence-1.0"
        assert spdx["hasExtractedLicensingInfos"][0]["extractedText"] == "Custom Licence 1.0"


def _platform(core: Path, directory: str, version: str, frameworks: dict, packages: dict, uri: str | None = None):
    platform = core / "platforms" / directory
    platform.mkdir(parents=True)
    spec = {"owner": None if uri else "platformio", "name": "espressif32", "uri": uri}
    (platform / ".piopm").write_text(
        json.dumps({"type": "platform", "name": "espressif32", "version": version, "spec": spec})
    )
    (platform / "platform.json").write_text(
        json.dumps(
            {
                "name": "espressif32",
                "version": version,
                "license": "Apache-2.0",
                "frameworks": frameworks,
                "packages": packages,
            }
        )
    )


def _package(core: Path, directory: str, name: str, version: str, uri: str | None = None, **manifest) -> Path:
    package = core / "packages" / directory
    package.mkdir(parents=True)
    spec = {"owner": None if uri else "platformio", "name": name, "uri": uri}
    (package / ".piopm").write_text(json.dumps({"type": "tool", "name": name, "version": version, "spec": spec}))
    (package / "package.json").write_text(json.dumps({"name": name, "version": version, **manifest}))
    return package


class TestPlatformAndFramework:
    """The framework is compiled into the firmware, and it is what CVEs are filed against."""

    ARDUINO = {"arduino": {"package": "framework-arduinoespressif32"}, "espidf": {"package": "framework-espidf"}}
    PACKAGES = {
        "framework-arduinoespressif32": {"type": "framework", "optional": True, "version": "~3.20017.0"},
        "framework-espidf": {"type": "framework", "optional": True, "version": "~3.50301.0"},
        "toolchain-xtensa-esp32": {"type": "toolchain", "version": "8.4.0+2021r2-patch5"},
    }

    def _arduino_project(self, tmp_path: Path) -> Path:
        core = tmp_path / "core"
        _platform(core, "espressif32@6.9.0", "6.9.0", self.ARDUINO, self.PACKAGES)
        framework = _package(
            core,
            "framework-arduinoespressif32",
            "framework-arduinoespressif32",
            "3.20017.241212",
            description="Arduino Wiring-based Framework for the Espressif ESP32",
            license="LGPL-2.1-or-later",
            repository={"type": "git", "url": "https://github.com/espressif/arduino-esp32"},
        )
        (framework / "tools" / "sdk").mkdir(parents=True)
        (framework / "tools" / "sdk" / "versions.txt").write_text("esp-idf: v4.4.7 38eeba213a\narduino: v2.0.17\n")
        # Another project's newer framework in the same core dir is not this env's.
        _package(core, "framework-arduinoespressif32@3.3.12", "framework-arduinoespressif32", "3.3.12")
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(
            "[env:esp32dev]\nplatform = espressif32@6.9.0\nframework = arduino\n"
            "lib_deps = bblanchon/ArduinoJson@7.4.3\n"
        )
        _registry_library(tmp_path / ".pio" / "libdeps" / "esp32dev", "ArduinoJson", "7.4.3", "bblanchon")
        return ini_path

    def test_the_platform_framework_and_bundled_esp_idf_are_components(self, tmp_path):
        document = _generate(tmp_path, self._arduino_project(tmp_path))
        components = {component["name"]: component for component in document["components"]}
        assert set(components) == {"ArduinoJson", "espressif32", "framework-arduinoespressif32", "esp-idf"}
        assert components["espressif32"]["type"] == "platform"
        framework = components["framework-arduinoespressif32"]
        assert framework["type"] == "framework"
        assert framework["version"] == "3.20017.241212"
        # PlatformIO's 3.20017 is Arduino-ESP32 2.0.17: the CPE uses the upstream's version.
        assert framework["cpe"] == "cpe:2.3:a:espressif:arduino-esp32:2.0.17:*:*:*:*:*:*:*"
        assert framework["licenses"] == [{"license": {"id": "LGPL-2.1-or-later"}}]
        idf = components["esp-idf"]
        assert idf["cpe"] == "cpe:2.3:a:espressif:esp-idf:4.4.7:*:*:*:*:*:*:*"
        assert idf["purl"] == "pkg:github/espressif/esp-idf@v4.4.7"

    def test_the_graph_runs_root_to_framework_to_esp_idf(self, tmp_path):
        document = _generate(tmp_path, self._arduino_project(tmp_path))
        refs = {component["name"]: component["bom-ref"] for component in document["components"]}
        graph = {entry["ref"]: entry["dependsOn"] for entry in document["dependencies"]}
        root = graph[document["metadata"]["component"]["bom-ref"]]
        assert {refs["ArduinoJson"], refs["espressif32"], refs["framework-arduinoespressif32"]} == set(root)
        assert graph[refs["framework-arduinoespressif32"]] == [refs["esp-idf"]]

    def test_spdx_carries_the_cpe_as_a_security_reference(self, tmp_path):
        document = _generate(tmp_path, self._arduino_project(tmp_path), "spdx")
        idf = next(package for package in document["packages"] if package["name"] == "esp-idf")
        assert {
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": "cpe:2.3:a:espressif:esp-idf:4.4.7:*:*:*:*:*:*:*",
        } in idf["externalRefs"]
        assert idf["primaryPackagePurpose"] == "FRAMEWORK"

    def test_a_url_pinned_framework_is_only_what_came_from_that_url(self, tmp_path):
        """Forks name their packages by release URL; another download of the same name is not it."""
        core = tmp_path / "core"
        platform_url = "https://github.com/pioarduino/platform-espressif32/releases/download/55.03.312/platform.zip"
        libs_url = "https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32-core-3.3.12-libs.tar.xz"
        core_url = "https://github.com/espressif/arduino-esp32/releases/download/3.3.12/esp32-core-3.3.12.tar.xz"
        _platform(
            core,
            "espressif32",
            "55.3.312",
            {"arduino": {"script": "builder/frameworks/arduino.py"}},
            {
                "framework-arduinoespressif32": {"type": "framework", "version": core_url},
                "framework-arduinoespressif32-libs": {"type": "framework", "version": libs_url},
            },
            uri=platform_url,
        )
        _package(core, "framework-arduinoespressif32", "framework-arduinoespressif32", "3.3.12", uri=core_url)
        libs = _package(
            core,
            "framework-arduinoespressif32-libs",
            "framework-arduinoespressif32-libs",
            "5.5.5+sha.b774170",
            libs_url,
        )
        (libs / "esp32").mkdir()
        (libs / "esp32" / "versions.txt").write_text("esp-idf: v5.5.5 b774170ff46\n")
        _package(
            core,
            "framework-arduinoespressif32@src-1",
            "framework-arduinoespressif32",
            "3.3.13",
            uri="https://x/y.tar.xz",
        )
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(f"[env:s3]\nplatform = {platform_url}\nframework = arduino\nlib_deps = a/Lib@1.0.0\n")
        _registry_library(tmp_path / ".pio" / "libdeps" / "s3", "Lib", "1.0.0", "a")
        components = {c["name"]: c for c in _generate(tmp_path, ini_path)["components"]}
        assert components["espressif32"]["purl"].startswith("pkg:github/pioarduino/platform-espressif32@55.03.312?")
        assert components["framework-arduinoespressif32"]["version"] == "3.3.12"
        assert components["framework-arduinoespressif32"]["cpe"].startswith("cpe:2.3:a:espressif:arduino-esp32:3.3.12:")
        # Two assets of one release: the same repository and tag, told apart by which file.
        libs_purl = components["framework-arduinoespressif32-libs"]["purl"]
        assert libs_purl.startswith("pkg:github/espressif/arduino-esp32@3.3.12?download_url=")
        assert libs_purl != components["framework-arduinoespressif32"]["purl"]
        assert components["esp-idf"]["cpe"].startswith("cpe:2.3:a:espressif:esp-idf:5.5.5:")

    def test_platform_packages_overrides_where_a_framework_came_from(self, tmp_path):
        """An env may swap a package's source; what it built with is the override."""
        core = tmp_path / "core"
        theirs = "https://github.com/espressif/arduino-esp32/releases/download/3.3.9/esp32-core-3.3.9-libs.tar.xz"
        ours = "https://github.com/theengs/esp32-arduino-lib-builder/releases/download/0.1.8/esp32-arduino-libs.tar.gz"
        _platform(
            core,
            "espressif32",
            "55.3.39",
            {"arduino": {"script": "builder/frameworks/arduino.py"}},
            {"framework-arduinoespressif32-libs": {"type": "framework", "version": theirs}},
        )
        libs = _package(core, "framework-arduinoespressif32-libs", "framework-arduinoespressif32-libs", "5.5.1", ours)
        (libs / "versions.txt").write_text("esp-idf: v5.5.1 abc\n")
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(
            "[com]\npackages = framework-arduinoespressif32-libs @ " + ours + "\n\n"
            "[env:x]\nplatform = espressif32\nframework = arduino\nplatform_packages = ${com.packages}\n"
            "lib_deps = a/Lib@1.0.0\n"
        )
        _registry_library(tmp_path / ".pio" / "libdeps" / "x", "Lib", "1.0.0", "a")
        names = {c["name"] for c in _generate(tmp_path, ini_path)["components"]}
        assert {"framework-arduinoespressif32-libs", "esp-idf"} <= names

    def test_esp_idf_is_found_under_tools_in_arduino_esp32_3(self, tmp_path):
        core = tmp_path / "core"
        _platform(core, "espressif32", "6.9.0", self.ARDUINO, self.PACKAGES)
        framework = _package(core, "framework-arduinoespressif32", "framework-arduinoespressif32", "3.20017.0+sha.1")
        (framework / "tools" / "esp32-arduino-libs").mkdir(parents=True)
        (framework / "tools" / "esp32-arduino-libs" / "versions.txt").write_text("esp-idf: v5.4.2 1\n")
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nplatform = espressif32\nframework = arduino\nlib_deps = a/Lib@1.0.0\n")
        _registry_library(tmp_path / ".pio" / "libdeps" / "x", "Lib", "1.0.0", "a")
        components = {c["name"]: c for c in _generate(tmp_path, ini_path)["components"]}
        assert components["esp-idf"]["version"] == "5.4.2"
        # 3.20017 with build metadata, and 4.20017 from platform 7, are still Arduino-ESP32 2.0.17.
        assert ":arduino-esp32:2.0.17:" in components["framework-arduinoespressif32"]["cpe"]

    def test_esp_idf_built_from_a_release_branch_is_named_by_commit(self, tmp_path):
        core = tmp_path / "core"
        _platform(core, "espressif32", "6.9.0", self.ARDUINO, self.PACKAGES)
        framework = _package(core, "framework-arduinoespressif32", "framework-arduinoespressif32", "3.20017.0")
        (framework / "tools" / "esp32-arduino-libs").mkdir(parents=True)
        (framework / "tools" / "esp32-arduino-libs" / "versions.txt").write_text("esp-idf: release/v5.5 f2a3fa2b\n")
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nplatform = espressif32\nframework = arduino\nlib_deps = a/Lib@1.0.0\n")
        _registry_library(tmp_path / ".pio" / "libdeps" / "x", "Lib", "1.0.0", "a")
        idf = next(c for c in _generate(tmp_path, ini_path)["components"] if c["name"] == "esp-idf")
        assert idf["version"] == "release/v5.5+f2a3fa2b"
        assert idf["purl"] == "pkg:github/espressif/esp-idf@f2a3fa2b"
        assert idf["cpe"] == "cpe:2.3:a:espressif:esp-idf:5.5:*:*:*:*:*:*:*"

    def test_platform_seven_renumbering_is_decoded(self):
        from sbomify_action._platformio import _upstream_version

        assert _upstream_version("framework-arduinoespressif32", "4.20017.260907+sha.dcc1105b") == "2.0.17"
        assert _upstream_version("framework-arduinoespressif32", "3.3.12") == "3.3.12"
        assert _upstream_version("framework-espidf", "3.50505") == "5.5.5"

    def test_an_esp_idf_project_names_esp_idf_itself(self, tmp_path):
        core = tmp_path / "core"
        _platform(core, "espressif32", "6.9.0", self.ARDUINO, self.PACKAGES)
        _package(core, "framework-espidf", "framework-espidf", "3.50301.0", license="Apache-2.0")
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:idf]\nplatform = espressif32\nframework = espidf\nlib_deps = a/Lib@1.0.0\n")
        _registry_library(tmp_path / ".pio" / "libdeps" / "idf", "Lib", "1.0.0", "a")
        components = {c["name"]: c for c in _generate(tmp_path, ini_path)["components"]}
        assert components["framework-espidf"]["cpe"] == "cpe:2.3:a:espressif:esp-idf:5.3.1:*:*:*:*:*:*:*"
        assert "esp-idf" not in components

    def test_an_environment_without_libraries_is_its_platform_and_framework(self, tmp_path):
        """Marlin's default env has no lib_deps; `pio pkg install` leaves no libdeps directory at all."""
        core = tmp_path / "core"
        _platform(
            core,
            "atmelavr",
            "4.0.1",
            {"arduino": {"package": "framework-arduino-avr"}},
            {
                "framework-arduino-avr": {"type": "framework", "version": "~5.1.0"},
            },
        )
        piopm = json.loads((core / "platforms" / "atmelavr" / ".piopm").read_text())
        (core / "platforms" / "atmelavr" / ".piopm").write_text(json.dumps({**piopm, "name": "atmelavr"}))
        _package(core, "framework-arduino-avr", "framework-arduino-avr", "5.1.0")
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(
            "[platformio]\ndefault_envs = mega2560\n\n[common]\nlib_deps =\n\n"
            "[env:mega2560]\nplatform = atmelavr\nframework = arduino\nlib_deps = ${common.lib_deps}\n\n"
            "[env:native]\nplatform = native\nlib_deps = throwtheswitch/Unity@^2.6.0\n"
        )
        document = _generate(tmp_path, ini_path)
        assert sorted(c["name"] for c in document["components"]) == ["atmelavr", "framework-arduino-avr"]

    def test_a_platform_that_is_not_installed_is_reported(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[platformio]\ndefault_envs = x\n\n[env:x]\nplatform = atmelavr\n")
        result = PlatformIOGenerator().generate(
            GenerationInput(lock_file=str(ini_path), output_file=str(tmp_path / "o.json"), output_format="cyclonedx")
        )
        assert not result.success
        assert "platform is not installed" in (result.error_message or "")
