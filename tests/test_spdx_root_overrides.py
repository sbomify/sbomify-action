"""COMPONENT_NAME, COMPONENT_VERSION and COMPONENT_PURL belong on the package
an SPDX document describes, never on ``packages[0]``.

syft lists a lock file's dependencies first and the package the document
describes last. Writing the overrides to the first package renamed ``arrow``
to "sbomify Action" in this repository's own SPDX SBOM and handed it the
action's PURL, while the package the document actually describes kept its old
identity.
"""

import json
import sys
from pathlib import Path

import pytest

from sbomify_action._generation.result import GenerationResult
from sbomify_action.cli.main import build_config, run_pipeline

#: The module, not the click command `sbomify_action.cli` re-exports as `main`.
cli_main = sys.modules["sbomify_action.cli.main"]

NAME = "sbomify Action"
VERSION = "1.2.3"
PURL = "pkg:docker/sbomify/sbomify-action@1.2.3?repository_url=ghcr.io"

ROOT = "SPDXRef-DocumentRoot-File-uv.lock"
ARROW = "SPDXRef-Package-python-arrow-9a674c0d42e22c36"
ATTRS = "SPDXRef-Package-python-attrs-e52aeb32f0af533a"

UV_LOCK = """\
version = 1
requires-python = ">=3.11"

[[package]]
name = "arrow"
version = "1.4.0"
source = { registry = "https://pypi.org/simple" }
"""


def package(spdx_id: str, name: str, version: str, purl: str | None = None) -> dict:
    entry: dict = {
        "SPDXID": spdx_id,
        "name": name,
        "versionInfo": version,
        "supplier": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    if purl:
        entry["externalRefs"] = [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}
        ]
    return entry


def syft_uv_lock(spdx_version: str = "2.3") -> dict:
    """What syft 1.42 writes for uv.lock, cut down to two dependencies."""
    return {
        "spdxVersion": f"SPDX-{spdx_version}",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "uv.lock",
        "documentNamespace": "https://anchore.com/syft/file/uv.lock-bc7586df-c4cf-41d2-b755-a1b63691ff75",
        "creationInfo": {
            "creators": ["Organization: Anchore, Inc", "Tool: syft-1.42.4"],
            "created": "2026-10-26T10:36:23Z",
        },
        "packages": [
            package(ARROW, "arrow", "1.4.0", "pkg:pypi/arrow@1.4.0"),
            package(ATTRS, "attrs", "26.1.0", "pkg:pypi/attrs@26.1.0"),
            package(ROOT, "uv.lock", "sha256:d1a03d2bd4a3ade2714cc8d2394677c0a02c9e428f0409168ab20449d3d2c3be"),
        ],
        "relationships": [
            {"spdxElementId": ROOT, "relatedSpdxElement": ARROW, "relationshipType": "CONTAINS"},
            {"spdxElementId": ROOT, "relatedSpdxElement": ATTRS, "relationshipType": "CONTAINS"},
            {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": ROOT, "relationshipType": "DESCRIBES"},
        ],
    }


def purls(entry: dict) -> list[str]:
    return [ref["referenceLocator"] for ref in entry.get("externalRefs", []) if ref["referenceType"] == "purl"]


def by_id(document: dict) -> dict[str, dict]:
    return {entry["SPDXID"]: entry for entry in document["packages"]}


def run_on_uv_lock(tmp_path: Path, monkeypatch, generated: dict, *, augment: bool) -> dict:
    """Run the pipeline the way .github/workflows/sboms.yml does, minus the upload.

    Generation is replaced by the document syft wrote for this repository's
    uv.lock, so the test needs no syft binary and pins the shape that broke.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "uv.lock").write_text(UV_LOCK)

    def syft(file_path, output_file, output_format, spec_version):
        Path(output_file).write_text(json.dumps(generated))
        return GenerationResult.success_result(
            output_file=output_file,
            sbom_format="spdx",
            spec_version=generated["spdxVersion"].removeprefix("SPDX-"),
            generator_name="syft-fs",
        )

    monkeypatch.setattr(cli_main, "process_lock_file", syft)
    config = build_config(
        lock_file="uv.lock",
        sbom_format="spdx",
        upload=False,
        augment=augment,
        enrich=False,
        component_name=NAME,
        component_version=VERSION,
        component_purl=PURL,
        output_file="out.spdx.json",
    )
    run_pipeline(config)
    return json.loads((tmp_path / "out.spdx.json").read_text())


@pytest.mark.parametrize("spdx_version", ["2.3", "2.2"])
@pytest.mark.parametrize("augment", [False, True], ids=["augment-off", "augment-on"])
def test_overrides_land_on_the_described_package(tmp_path, monkeypatch, spdx_version, augment):
    result = run_on_uv_lock(tmp_path, monkeypatch, syft_uv_lock(spdx_version), augment=augment)
    packages = by_id(result)

    arrow = packages[ARROW]
    assert (arrow["name"], arrow["versionInfo"], purls(arrow)) == ("arrow", "1.4.0", ["pkg:pypi/arrow@1.4.0"])

    root = packages[ROOT]
    assert root["versionInfo"] == VERSION
    assert purls(root) == [PURL]
    assert result["name"] == NAME
    if augment:
        # Without augmentation COMPONENT_NAME names the document, not the package.
        assert root["name"] == NAME


def run_on_additional_packages(tmp_path: Path, monkeypatch, spec_version: str | None = None) -> dict:
    """An SBOM built only from ADDITIONAL_PACKAGES, which describes nothing."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ADDITIONAL_PACKAGES", "pkg:pypi/requests@2.32.0")
    config = build_config(
        lock_file="none",
        sbom_format="spdx",
        spec_version=spec_version,
        upload=False,
        augment=True,
        component_name=NAME,
        component_version=VERSION,
        component_purl=PURL,
        output_file="out.spdx.json",
    )
    run_pipeline(config)
    return json.loads((tmp_path / "out.spdx.json").read_text())


def test_additional_packages_alone_are_not_renamed(tmp_path, monkeypatch):
    """The first injected package is a dependency like any other."""
    result = run_on_additional_packages(tmp_path, monkeypatch)

    [requests] = result["packages"]
    assert (requests["name"], requests["versionInfo"], purls(requests)) == (
        "requests",
        "2.32.0",
        ["pkg:pypi/requests@2.32.0"],
    )
    assert result["name"] == NAME


def test_additional_packages_alone_are_not_renamed_in_spdx3(tmp_path, monkeypatch):
    result = run_on_additional_packages(tmp_path, monkeypatch, spec_version="3.0.1")

    [requests] = [e for e in result["@graph"] if e.get("type") == "software_Package"]
    assert (requests["name"], requests["software_packageVersion"], requests["software_packageUrl"]) == (
        "requests",
        "2.32.0",
        "pkg:pypi/requests@2.32.0",
    )
    [document] = [e for e in result["@graph"] if e.get("type") == "SpdxDocument"]
    assert document["name"] == NAME


# ---------------------------------------------------------------------------
# The overrides alone, on documents that describe something other than one
# package, or nothing at all.


class Cfg:
    """The three fields the override functions read."""

    def __init__(self) -> None:
        self.component_name = NAME
        self.component_version = VERSION
        self.component_purl = PURL


def apply_overrides(tmp_path: Path, document: dict) -> dict:
    path = tmp_path / "sbom.spdx.json"
    path.write_text(json.dumps(document))
    config = Cfg()
    cli_main._apply_sbom_version_override(str(path), config)
    cli_main._apply_sbom_purl_override(str(path), config)
    return json.loads(path.read_text())


def test_documentdescribes_alone_names_the_root(tmp_path):
    document = syft_uv_lock()
    document["relationships"] = document["relationships"][:-1]
    document["documentDescribes"] = [ROOT]

    root = by_id(apply_overrides(tmp_path, document))[ROOT]
    assert (root["versionInfo"], purls(root)) == (VERSION, [PURL])


def test_with_several_described_packages_the_first_is_the_root(tmp_path):
    """Dependency expansion adds a DESCRIBES for every package it discovers,
    after the generator's own. The generator's root keeps the overrides."""
    document = syft_uv_lock()
    document["relationships"].append(
        {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": ATTRS, "relationshipType": "DESCRIBES"}
    )

    packages = by_id(apply_overrides(tmp_path, document))
    assert (packages[ROOT]["versionInfo"], purls(packages[ROOT])) == (VERSION, [PURL])
    assert (packages[ATTRS]["versionInfo"], purls(packages[ATTRS])) == ("26.1.0", ["pkg:pypi/attrs@26.1.0"])


@pytest.mark.parametrize(
    "describes",
    [
        pytest.param(None, id="nothing-described"),
        pytest.param("SPDXRef-File-uv.lock-3717ae13dd3eb744", id="a-file-described"),
        pytest.param("SPDXRef-Package-not-in-this-document", id="a-dangling-reference"),
    ],
)
def test_without_a_described_package_no_package_is_touched(tmp_path, caplog, describes):
    document = syft_uv_lock()
    document["relationships"] = document["relationships"][:-1]
    if describes:
        document["relationships"].append(
            {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": describes, "relationshipType": "DESCRIBES"}
        )

    assert apply_overrides(tmp_path, document)["packages"] == document["packages"]
    assert "describes no package" in caplog.text


# ---------------------------------------------------------------------------
# Augmentation, which writes the backend's metadata as well as the overrides.

BACKEND = {"supplier": {"name": "sbomify"}, "licenses": ["Apache-2.0"]}


def parse(document: dict):
    from spdx_tools.spdx.parser.jsonlikedict.json_like_dict_parser import JsonLikeDictParser

    return JsonLikeDictParser().parse(document)


def snapshot(document) -> list[tuple]:
    return [(p.spdx_id, p.name, p.version, p.supplier, p.license_declared) for p in document.packages]


@pytest.mark.parametrize("several", [False, True], ids=["one-described", "several-described"])
def test_augmentation_writes_to_the_described_package(several):
    from sbomify_action.augmentation import augment_spdx_sbom

    document = syft_uv_lock()
    if several:
        document["relationships"].append(
            {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": ATTRS, "relationshipType": "DESCRIBES"}
        )
    before = {row[0]: row for row in snapshot(parse(document))}

    # Override, because syft fills supplier and licence with NOASSERTION.
    augmented = augment_spdx_sbom(
        parse(document), BACKEND, override_sbom_metadata=True, component_name=NAME, component_version=VERSION
    )

    after = {row[0]: row for row in snapshot(augmented)}
    assert after[ARROW] == before[ARROW]
    assert after[ATTRS] == before[ATTRS]
    _, name, version, supplier, licence = after[ROOT]
    assert (name, version, supplier.name, str(licence)) == (NAME, VERSION, "sbomify", "Apache-2.0")


def test_augmentation_of_a_document_describing_nothing_changes_no_package(caplog):
    from sbomify_action.augmentation import augment_spdx_sbom

    document = syft_uv_lock()
    document["relationships"] = document["relationships"][:-1]
    before = snapshot(parse(document))

    augmented = augment_spdx_sbom(
        parse(document), BACKEND, override_sbom_metadata=True, component_name=NAME, component_version=VERSION
    )

    assert snapshot(augmented) == before
    assert augmented.creation_info.name == NAME
    assert "describes no package" in caplog.text


# ---------------------------------------------------------------------------
# SPDX 3, where the root is the document's rootElement.


def spdx3_with_a_dependency_first(described: bool) -> dict:
    document = json.loads((Path(__file__).parent / "test-data" / "spdx3_minimal.json").read_text())
    graph = document["@graph"]
    dependency = {**graph[2], "spdxId": "urn:spdx.dev:pkg-dep", "name": "arrow"}
    dependency.update(software_packageVersion="1.4.0", software_packageUrl="pkg:pypi/arrow@1.4.0")
    graph.insert(2, dependency)
    graph[0]["element"].append("urn:spdx.dev:pkg-dep")
    if not described:
        graph[0]["rootElement"] = []
    return document


def spdx3_packages(document: dict) -> dict[str, tuple]:
    return {
        e["spdxId"]: (e["name"], e.get("software_packageVersion"), e.get("software_packageUrl"))
        for e in document["@graph"]
        if e.get("type") == "software_Package"
    }


@pytest.mark.parametrize("described", [True, False], ids=["root-described", "nothing-described"])
def test_spdx3_overrides_land_on_the_root_element(tmp_path, described):
    document = spdx3_with_a_dependency_first(described)
    path = tmp_path / "sbom.spdx3.json"
    path.write_text(json.dumps(document))

    config = Cfg()
    cli_main._apply_sbom_version_override(str(path), config)
    cli_main._apply_sbom_name_override(str(path), config)
    cli_main._apply_sbom_purl_override(str(path), config)

    result = json.loads(path.read_text())
    packages = spdx3_packages(result)
    assert packages["urn:spdx.dev:pkg-dep"] == ("arrow", "1.4.0", "pkg:pypi/arrow@1.4.0")
    expected = (NAME, VERSION, PURL) if described else spdx3_packages(document)["urn:spdx.dev:pkg-test"]
    assert packages["urn:spdx.dev:pkg-test"] == expected
    [spdx_document] = [e for e in result["@graph"] if e.get("type") == "SpdxDocument"]
    assert spdx_document["name"] == NAME


# ---------------------------------------------------------------------------
# Enrichment copies the root's supplier and version onto related packages.

SUPPLIER = "Organization: sbomify"


def test_lockfile_packages_inherit_from_the_described_package():
    """trivy puts the lock file first, its dependencies next and the package
    the document describes last. The lock file's supplier and version are the
    component's, not those of whichever dependency comes first."""
    from sbomify_action.enrichment import _enrich_lockfile_packages

    root = "SPDXRef-Filesystem-956eda8d387b7ce0"
    lockfile = "SPDXRef-Application-3bc52fafdd5c33c7"
    document = syft_uv_lock()
    document["packages"] = [
        {**package(lockfile, "uv.lock", ""), "versionInfo": None, "supplier": None},
        {**package(ARROW, "arrow", "1.4.0", "pkg:pypi/arrow@1.4.0"), "supplier": "Organization: arrow"},
        {**package(root, "/github/workspace", VERSION, PURL), "supplier": SUPPLIER},
    ]
    document["relationships"] = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": root, "relationshipType": "DESCRIBES"}
    ]
    parsed = parse(document)

    _enrich_lockfile_packages(parsed)

    uv_lock = next(p for p in parsed.packages if p.spdx_id == lockfile)
    assert (uv_lock.version, str(uv_lock.supplier)) == (VERSION, SUPPLIER)


def test_self_references_inherit_from_the_described_package():
    from sbomify_action.enrichment import _enrich_self_referencing_packages

    document = syft_uv_lock()
    itself = "SPDXRef-Package-python-sbomify-action-7495774778750db7"
    document["packages"][-1].update(name="sbomify-action", supplier=SUPPLIER)
    document["packages"].insert(1, package(itself, "sbomify-action", "26.10.2", "pkg:pypi/sbomify-action@26.10.2"))
    parsed = parse(document)

    assert _enrich_self_referencing_packages(parsed) == 1

    suppliers = {p.spdx_id: str(p.supplier) for p in parsed.packages}
    assert (suppliers[itself], suppliers[ARROW]) == (SUPPLIER, "NOASSERTION")
