"""What the action writes must pass the schema the action ships, and say what
the producer said.

Every SPDX 3 file the writer produced failed `spdx-3.0.1.schema.json`, the
copy bundled in this repo, because spdx-tools 0.8.5 models a pre-3.0.1 draft:
its CreationInfo still carries `profile` and `data_license`, both of which
3.0.1 moved or removed. `CreationInfo_props` allows exactly
comment/created/createdBy/createdUsing/specVersion under
`unevaluatedProperties: false`, so one extra key invalidates every element in
the document. That is what makes AUGMENT=true or ENRICH=true on any SPDX 3
input an unconditional exit 1: both re-validate their own output.

The quieter half of the same draft model is worse, because nothing fails. The
library's enums cannot hold 37 of 3.0.1's 59 relationship types or two of its
purposes, and it substitutes a legal value rather than refusing, so the
rewritten document validates while stating something its author never wrote.
Those cases need an assertion on the value, not on the error count.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest

from sbomify_action.spdx3 import (
    _ACTION_AGENT_ID,
    Organization,
    Package,
    make_spdx3_creation_info,
    parse_spdx3_data,
    parse_spdx3_file,
    spdx3_license_from_string,
    spdx3_licenses_from_list,
    write_spdx3_file,
)

FIXTURE = Path(__file__).parent / "test-data" / "spdx3_conformant.json"
SCHEMA = Path(__file__).parent.parent / "sbomify_action" / "schemas" / "spdx" / "spdx-3.0.1.schema.json"


@pytest.fixture(scope="module")
def validator() -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text()))


def _errors(validator, document: dict) -> list[str]:
    return [
        "/" + "/".join(str(p) for p in e.absolute_path) + ": " + e.message[:200]
        for e in validator.iter_errors(document)
    ]


@pytest.fixture
def round_tripped(tmp_path: Path) -> dict:
    out = tmp_path / "out.json"
    write_spdx3_file(parse_spdx3_file(str(FIXTURE)), str(out))
    return json.loads(out.read_text())


def _write(source: dict, tmp_path: Path) -> dict:
    """The document as the writer produces it, from a raw source dict."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "out.json"
    write_spdx3_file(parse_spdx3_data(source), str(out))
    return json.loads(out.read_text())


def _elements(document: dict, type_name: str) -> list[dict]:
    return [e for e in document.get("@graph", []) if e.get("type") == type_name]


def _creation_infos(node) -> list[dict]:
    """Every CreationInfo in the document, inline or standalone."""
    found = []
    if isinstance(node, dict):
        if node.get("type") == "CreationInfo" or "specVersion" in node:
            found.append(node)
        for value in node.values():
            found.extend(_creation_infos(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_creation_infos(item))
    return found


class TestTheControlIsActuallyValid:
    """Without this the round-trip assertion below proves nothing.

    The repo's other fixture, spdx3_minimal.json, is not a control: it uses
    `@id` rather than `spdxId`, carries no `@context`, and fails the schema
    eight times on its own.
    """

    def test_the_fixture_validates_before_anything_touches_it(self, validator):
        assert _errors(validator, json.loads(FIXTURE.read_text())) == []


class TestTheRoundTripStaysValid:
    def test_a_valid_document_comes_back_valid(self, validator, round_tripped):
        assert _errors(validator, round_tripped) == []

    def test_no_creation_info_carries_datalicense(self, round_tripped):
        """3.0.1 moved it to SpdxDocument."""
        assert [ci for ci in _creation_infos(round_tripped) if "dataLicense" in ci] == []

    def test_no_creation_info_carries_profile(self, round_tripped):
        """3.0.1 replaced it with Element.profileConformance."""
        assert [ci for ci in _creation_infos(round_tripped) if "profile" in ci] == []

    def test_a_document_that_declared_no_datalicense_is_not_given_one(self, round_tripped):
        """The draft model defaults data_license to the bare id "CC0-1.0",
        which is both a claim its author never made and invalid where the
        schema wants a licence IRI."""
        assert "dataLicense" not in _elements(round_tripped, "SpdxDocument")[0]

    def test_external_refs_keep_the_3_0_1_spelling(self, round_tripped):
        """spdx-tools writes externalReference / externalReferenceType /
        ExternalReference; 3.0.1 renamed all three and rejects the old names."""
        package = _elements(round_tripped, "software_Package")[0]

        assert "externalReference" not in package
        assert package["externalRef"][0]["externalRefType"] == "vcs"
        assert package["externalRef"][0]["type"] == "ExternalRef"

    def test_the_document_keeps_its_profile_conformance(self, round_tripped):
        """Listing a profile claims every contained element meets it, so
        dropping it silently weakens the document."""
        assert _elements(round_tripped, "SpdxDocument")[0]["profileConformance"] == ["core", "software"]

    def test_the_packages_survive(self, round_tripped):
        names = {p.get("name") for p in _elements(round_tripped, "software_Package")}

        assert names == {"my-app"}


class TestDocumentsThatDeclareNothing:
    def test_a_document_without_profile_conformance_does_not_gain_one(self, tmp_path, validator):
        source = json.loads(FIXTURE.read_text())
        for element in source["@graph"]:
            element.pop("profileConformance", None)
        out = tmp_path / "out.json"

        write_spdx3_file(parse_spdx3_data(source), str(out))
        result = json.loads(out.read_text())

        assert "profileConformance" not in _elements(result, "SpdxDocument")[0]
        assert _errors(validator, result) == []

    def test_a_legacy_creation_info_profile_is_not_re_emitted(self, tmp_path, validator):
        """The repo's own older fixtures put `profile` on the CreationInfo.
        Reading it is fine; writing it back out is not."""
        source = json.loads(FIXTURE.read_text())
        for element in source["@graph"]:
            if element.get("type") == "CreationInfo":
                element["profile"] = ["core", "software"]
                element["dataLicense"] = "CC0-1.0"
        out = tmp_path / "out.json"

        write_spdx3_file(parse_spdx3_data(source), str(out))
        result = json.loads(out.read_text())

        assert [ci for ci in _creation_infos(result) if "profile" in ci or "dataLicense" in ci] == []
        assert _errors(validator, result) == []


class TestADeclaredDataLicense:
    """3.0.1 puts it on the SpdxDocument, as a licence IRI."""

    LICENSE = "https://spdx.org/licenses/CC0-1.0"

    def test_it_survives_on_the_document(self, tmp_path, validator):
        source = json.loads(FIXTURE.read_text())
        for element in source["@graph"]:
            if element.get("type") == "SpdxDocument":
                element["dataLicense"] = self.LICENSE

        result = _write(source, tmp_path)

        assert _elements(result, "SpdxDocument")[0]["dataLicense"] == self.LICENSE
        assert _errors(validator, result) == []

    def test_the_draft_location_is_read_and_rewritten_to_the_document(self, tmp_path, validator):
        """Older documents put it on the CreationInfo. Read it there, write it
        where 3.0.1 expects it."""
        source = json.loads(FIXTURE.read_text())
        for element in source["@graph"]:
            if element.get("type") == "SpdxDocument":
                element["creationInfo"] = {
                    "type": "CreationInfo",
                    "specVersion": "3.0.1",
                    "created": "2026-08-01T00:00:00Z",
                    "createdBy": ["urn:acme:agent"],
                    "dataLicense": self.LICENSE,
                }

        result = _write(source, tmp_path)
        document = _elements(result, "SpdxDocument")[0]

        assert document["dataLicense"] == self.LICENSE
        assert "dataLicense" not in document["creationInfo"]
        assert _errors(validator, result) == []


class TestTheSpecVersionSurvives:
    """SPDX 3.0 shipped 2024-04 and 3.0.1 in 2024-12. Both are in the wild:
    syft, Microsoft sbom-tool, JFrog Xray and Zephyr all emit 3.0.

    The writer hardcoded a 3.0.1 @context and none of its eight call sites
    overrode it, so a 3.0 input came back labelled 3.0.1 in the @context while
    its creationInfo still read 3.0.0. CycloneDX already reads the output spec
    version off the input document.
    """

    def _as_300(self) -> dict:
        source = json.loads(FIXTURE.read_text())
        source["@context"] = "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"
        for element in source["@graph"]:
            if element.get("type") == "CreationInfo":
                element["specVersion"] = "3.0.0"
        return source

    def test_a_300_input_stays_300(self, tmp_path):
        result = _write(self._as_300(), tmp_path)

        assert result["@context"] == "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"

    def test_the_context_and_the_spec_version_agree(self, tmp_path):
        """Relabelling one and not the other is worse than either alone."""
        result = _write(self._as_300(), tmp_path)

        assert _creation_infos(result)[0]["specVersion"] == "3.0.0"

    def test_a_301_input_stays_301(self, tmp_path):
        result = _write(json.loads(FIXTURE.read_text()), tmp_path)

        assert result["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

    def test_a_document_built_from_nothing_is_301(self, tmp_path):
        """Nothing to preserve, so write the current release."""
        from sbomify_action.spdx3 import Spdx3Payload

        out = tmp_path / "out.json"
        write_spdx3_file(Spdx3Payload(), str(out))

        assert json.loads(out.read_text())["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

    def test_an_explicit_argument_still_wins(self, tmp_path):
        out = tmp_path / "out.json"
        pinned = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

        write_spdx3_file(parse_spdx3_data(self._as_300()), str(out), context_url=pinned)

        assert json.loads(out.read_text())["@context"] == pinned


class TestPurposesTheLibraryHasNotHeardOf:
    """spdx-tools 0.8.5 carries the pre-3.0.1 SoftwarePurpose enum.

    It has neither `specification` nor `filesystemImage`, both of which 3.0.1
    defines and Yocto emits. Measured on the published 6.0.3 core-image-minimal
    SBOM, which validates clean: a round-trip dropped primaryPurpose from 38
    packages, `filesystemImage` among them. That one is the image itself.

    A value the producer wrote and the schema accepts does not get dropped
    because a library is a version behind.
    """

    def _package(self, source: dict) -> dict:
        return [e for e in source["@graph"] if e.get("type") == "software_Package"][0]

    def _round_trip(self, purpose: str, tmp_path: Path, key: str = "software_primaryPurpose") -> dict:
        source = json.loads(FIXTURE.read_text())
        self._package(source)[key] = purpose
        out = tmp_path / "out.json"
        write_spdx3_file(parse_spdx3_data(source), str(out))
        return json.loads(out.read_text())

    @pytest.mark.parametrize("purpose", ["specification", "filesystemImage"])
    def test_a_3_0_1_purpose_survives(self, purpose, tmp_path, validator):
        result = self._round_trip(purpose, tmp_path)

        assert _elements(result, "software_Package")[0]["software_primaryPurpose"] == purpose
        assert _errors(validator, result) == []

    @pytest.mark.parametrize("purpose", ["library", "source", "install", "archive", "patch"])
    def test_a_purpose_the_library_knows_still_survives(self, purpose, tmp_path):
        result = self._round_trip(purpose, tmp_path)

        assert _elements(result, "software_Package")[0]["software_primaryPurpose"] == purpose

    def test_additional_purposes_survive_too(self, tmp_path, validator):
        """Same enum, same gap, and it takes a list."""
        result = self._round_trip("specification", tmp_path, key="software_additionalPurpose")
        package = _elements(result, "software_Package")[0]

        assert package["software_additionalPurpose"] == ["specification"]
        assert _errors(validator, result) == []

    def test_a_package_without_a_purpose_is_not_given_one(self, tmp_path):
        source = json.loads(FIXTURE.read_text())
        out = tmp_path / "out.json"

        write_spdx3_file(parse_spdx3_data(source), str(out))
        package = _elements(json.loads(out.read_text()), "software_Package")[0]

        assert "software_primaryPurpose" not in package


class TestRelationshipTypesSurvive:
    """spdx-tools 0.8.5 holds 62 relationship types; 37 of 3.0.1's 59 are not
    among them, and its parser maps anything it does not recognise to
    ``other``. ``other`` is itself legal, so the rewritten document passes the
    schema while saying something different from what the producer wrote: a
    declared licence, a static link and a prerequisite all come back as an
    unspecified relationship to the same target.
    """

    @pytest.mark.parametrize(
        "relationship_type",
        ["hasDeclaredLicense", "hasConcludedLicense", "hasStaticLink", "hasPrerequisite", "hasOptionalDependency"],
    )
    def test_a_type_the_library_predates_is_not_rewritten(self, relationship_type, tmp_path, validator):
        source = json.loads(FIXTURE.read_text())
        for element in source["@graph"]:
            if element.get("type") == "Relationship":
                element["relationshipType"] = relationship_type
                break

        written = _write(source, tmp_path)

        assert _errors(validator, written) == []
        assert _elements(written, "Relationship")[0]["relationshipType"] == relationship_type

    def test_a_type_the_library_does_hold_still_survives(self, tmp_path):
        source = json.loads(FIXTURE.read_text())
        source["@graph"][-1]["relationshipType"] = "contains"

        written = _write(source, tmp_path)

        assert "contains" in [r["relationshipType"] for r in _elements(written, "Relationship")]

    def test_the_fixture_licence_relationships_round_trip(self, round_tripped):
        assert sorted(r["relationshipType"] for r in _elements(round_tripped, "Relationship")) == [
            "hasConcludedLicense",
            "hasDeclaredLicense",
        ]


class TestANestedLicenceSetKeepsItsMeaning:
    """SPDX binds AND tighter than OR, so joining set members without
    parentheses re-reads the expression rather than writing it out. A
    disjunction inside a conjunction came back granting one of its members on
    its own, which is a different licence claim from the one the producer made.
    """

    @staticmethod
    def _listed(identifier: str) -> dict:
        return {"type": "ListedLicense", "licenseId": identifier}

    def test_a_disjunction_inside_a_conjunction_is_parenthesised(self):
        from sbomify_action.spdx3 import _license_expression_text

        expression = _license_expression_text(
            {
                "type": "ConjunctiveLicenseSet",
                "member": [
                    {
                        "type": "DisjunctiveLicenseSet",
                        "member": [self._listed("MIT"), self._listed("Apache-2.0")],
                    },
                    self._listed("GPL-2.0-only"),
                ],
            }
        )

        assert expression == "(MIT OR Apache-2.0) AND GPL-2.0-only"

    def test_a_conjunction_inside_a_disjunction_is_parenthesised(self):
        from sbomify_action.spdx3 import _license_expression_text

        expression = _license_expression_text(
            {
                "type": "DisjunctiveLicenseSet",
                "member": [
                    {
                        "type": "ConjunctiveLicenseSet",
                        "member": [self._listed("MIT"), self._listed("Apache-2.0")],
                    },
                    self._listed("GPL-2.0-only"),
                ],
            }
        )

        assert expression == "(MIT AND Apache-2.0) OR GPL-2.0-only"

    def test_the_same_operator_stays_flat(self):
        """AND is associative, so parenthesising there would only add noise."""
        from sbomify_action.spdx3 import _license_expression_text

        expression = _license_expression_text(
            {
                "type": "ConjunctiveLicenseSet",
                "member": [
                    {
                        "type": "ConjunctiveLicenseSet",
                        "member": [self._listed("MIT"), self._listed("Apache-2.0")],
                    },
                    self._listed("GPL-2.0-only"),
                ],
            }
        )

        assert expression == "MIT AND Apache-2.0 AND GPL-2.0-only"

    def test_a_member_that_is_already_an_expression_string_is_read_the_same_way(self):
        """spdx3_license_from_string parks a verbatim expression on a licence
        object, so a member can carry an operator without being a set."""
        from sbomify_action.spdx3 import _license_expression_text

        expression = _license_expression_text(
            {"type": "ConjunctiveLicenseSet", "member": ["MIT OR Apache-2.0", "GPL-2.0-only"]}
        )

        assert expression == "(MIT OR Apache-2.0) AND GPL-2.0-only"

    def test_a_member_that_is_already_parenthesised_is_not_wrapped_twice(self):
        from sbomify_action.spdx3 import _license_expression_text

        expression = _license_expression_text(
            {"type": "ConjunctiveLicenseSet", "member": ["(MIT OR Apache-2.0)", "GPL-2.0-only"]}
        )

        assert expression == "(MIT OR Apache-2.0) AND GPL-2.0-only"


class TestLicencesAreRelationshipsNotProperties:
    """3.0.1 has no declaredLicense or concludedLicense property: a licence is
    a Relationship to a licensing element. spdx-tools still models both as
    fields, so the licence the action worked out was written somewhere the
    schema rejects and no conforming reader looks, sbomify's own included.
    """

    def _write_with_licence(self, licence, tmp_path: Path) -> dict:
        """The document the action produces after stating a declared licence.

        Goes through the model field the way enrichment and augmentation do,
        rather than putting the property on the source: the parser has no slot
        for it, so a source-level property would never reach the writer and
        the test would pass without exercising anything.
        """
        source = json.loads(FIXTURE.read_text())
        source["@graph"] = [e for e in source["@graph"] if e.get("type") != "Relationship"]
        payload = parse_spdx3_data(source)
        package = next(p for p in payload.get_full_map().values() if isinstance(p, Package))
        package.declared_license = licence
        out = tmp_path / "out.json"
        write_spdx3_file(payload, str(out))
        return json.loads(out.read_text())

    def _licence_of(self, document: dict, relationship_type: str) -> str | None:
        by_id = {e.get("spdxId"): e for e in document["@graph"]}
        for relationship in _elements(document, "Relationship"):
            if relationship["relationshipType"] != relationship_type:
                continue
            return by_id.get(relationship["to"][0], {}).get("simplelicensing_licenseExpression")
        return None

    def test_the_property_never_reaches_the_output(self, tmp_path, validator):
        written = self._write_with_licence(spdx3_license_from_string("MIT"), tmp_path)

        assert _errors(validator, written) == []
        assert all("declaredLicense" not in e for e in written["@graph"])

    def test_the_licence_becomes_a_relationship_a_reader_can_follow(self, tmp_path):
        written = self._write_with_licence(spdx3_license_from_string("MIT"), tmp_path)

        assert self._licence_of(written, "hasDeclaredLicense") == "MIT"

    def test_an_expression_is_not_flattened_to_its_placeholder_id(self, tmp_path):
        """spdx3_license_from_string has no expression class to reach for, so
        for anything that is not a bare identifier it mints a CustomLicense
        with a synthesised `LicenseRef-MIT-OR-Apache-2-0` id. Publishing that
        id would report a licence nobody wrote."""
        written = self._write_with_licence(spdx3_license_from_string("MIT OR Apache-2.0"), tmp_path)

        assert self._licence_of(written, "hasDeclaredLicense") == "MIT OR Apache-2.0"

    def test_a_licence_set_composes_back_into_one_expression(self, tmp_path):
        written = self._write_with_licence(spdx3_licenses_from_list(["MIT", "Apache-2.0"]), tmp_path)

        assert self._licence_of(written, "hasDeclaredLicense") == "MIT OR Apache-2.0"

    @pytest.mark.parametrize("nothing", ["NOASSERTION", "NONE"])
    def test_asserting_nothing_writes_no_relationship(self, nothing, tmp_path):
        """A relationship pointing at nothing asserts less than no
        relationship, and reads back as a licence that is not one."""
        written = self._write_with_licence(spdx3_license_from_string(nothing), tmp_path)

        assert _elements(written, "Relationship") == []

    def test_a_licence_is_countersigned_by_the_element_it_describes(self, tmp_path, validator):
        """The minted licence and relationship carry the package's own
        creationInfo, so neither adds provenance nobody can account for."""
        written = self._write_with_licence(spdx3_license_from_string("MIT"), tmp_path)
        package = _elements(written, "software_Package")[0]
        relationship = _elements(written, "Relationship")[0]
        by_id = {e.get("spdxId"): e for e in written["@graph"]}

        minted = by_id[relationship["to"][0]]
        assert minted["creationInfo"] == package["creationInfo"] == relationship["creationInfo"]


class TestWhatTheActionMintsSaysWhoMintedIt:
    """``CreationInfo_props`` requires createdBy with minItems 1, so an
    element the action adds with no creator named fails and takes every
    element sharing its CreationInfo down with it. Augmentation and
    enrichment add a Tool, an Organization and a Person each.
    """

    def _with_minted_organization(self, tmp_path: Path) -> dict:
        """The fixture plus one Organization added the way the action adds one."""
        payload = parse_spdx3_data(json.loads(FIXTURE.read_text()))
        payload.add_element(
            Organization(spdx_id="urn:acme:minted", name="Acme Corp", creation_info=make_spdx3_creation_info())
        )
        tmp_path.mkdir(parents=True, exist_ok=True)
        out = tmp_path / "out.json"
        write_spdx3_file(payload, str(out))
        return json.loads(out.read_text())

    def test_the_document_still_validates(self, tmp_path, validator):
        assert _errors(validator, self._with_minted_organization(tmp_path)) == []

    def test_the_named_agent_is_in_the_graph(self, tmp_path):
        """A createdBy pointing at an element nobody wrote is a dangling
        reference, which is how the minted agent would otherwise read."""
        written = self._with_minted_organization(tmp_path)
        minted = next(e for e in written["@graph"] if e.get("spdxId") == "urn:acme:minted")

        named = minted["creationInfo"]["createdBy"][0]
        assert named in {e.get("spdxId") for e in written["@graph"]}

    def test_the_agent_is_not_a_tool(self, tmp_path):
        """3.0.1 is strict about it: createdBy takes an Agent, and Tool is
        not one."""
        assert _elements(self._with_minted_organization(tmp_path), "SoftwareAgent") != []

    def test_a_document_that_already_names_its_creators_gains_no_agent(self, round_tripped):
        assert _elements(round_tripped, "SoftwareAgent") == []

    def test_a_creation_info_that_arrived_without_one_is_left_alone(self, tmp_path):
        """The action does not know who created that element, and naming
        itself there would state provenance nobody wrote."""
        source = json.loads(FIXTURE.read_text())
        source["@graph"].append(
            {
                "type": "Organization",
                "spdxId": "urn:acme:theirs",
                "name": "Someone Else",
                "creationInfo": {"type": "CreationInfo", "specVersion": "3.0.1", "created": "2026-01-01T00:00:00Z"},
            }
        )

        written = _write(source, tmp_path)

        theirs = next(e for e in written["@graph"] if e.get("spdxId") == "urn:acme:theirs")
        assert "createdBy" not in theirs["creationInfo"]

    def test_the_agent_id_is_stable_across_runs(self, tmp_path):
        """A fresh uuid per run would put a spurious element in every diff."""
        first = self._with_minted_organization(tmp_path / "a")
        second = self._with_minted_organization(tmp_path / "b")

        assert _elements(first, "SoftwareAgent")[0]["spdxId"] == _elements(second, "SoftwareAgent")[0]["spdxId"]


class TestTheSupplierIsOne:
    """3.0.1 gives an artifact exactly one suppliedBy; originatedBy is the
    set. spdx-tools models both as lists, so a supplier the action worked out
    was written as a one-element array the schema refuses.
    """

    def _with_supplier(self, value) -> dict:
        source = json.loads(FIXTURE.read_text())
        for element in source["@graph"]:
            if element.get("type") == "software_Package":
                element["suppliedBy"] = value
        return source

    def test_a_supplier_is_written_as_one_value(self, tmp_path, validator):
        written = _write(self._with_supplier("urn:acme:agent"), tmp_path)

        assert _errors(validator, written) == []
        package = _elements(written, "software_Package")[0]
        assert package["suppliedBy"] == "urn:acme:agent"

    def test_originated_by_stays_a_list(self, round_tripped):
        package = _elements(round_tripped, "software_Package")[0]

        assert package["originatedBy"] == ["urn:acme:agent"]


class TestEnrichAndAugmentProduceValidDocuments:
    """Both re-validate their own output, so a schema error here is exit 1 on
    a document that arrived clean. These run the real entry points: the
    defects were in what the writer emitted for the elements they add, which
    a writer-only test does not reach.
    """

    LICENCE = "MIT OR Apache-2.0"

    @staticmethod
    def _undeclared() -> dict:
        """The fixture with its licence relationships removed."""
        source = json.loads(FIXTURE.read_text())
        source["@graph"] = [e for e in source["@graph"] if e.get("type") != "Relationship"]
        return source

    def _enriched(self, source: dict, tmp_path: Path) -> dict:
        from sbomify_action._enrichment.metadata import NormalizedMetadata
        from sbomify_action.enrichment import _enrich_spdx3_sbom

        metadata = NormalizedMetadata()
        metadata.licenses = [self.LICENCE]
        metadata.supplier = "Acme Corp"
        metadata.source = "test"

        class _Enricher:
            def fetch_metadata(self, purl, merge_results=True):
                return metadata

        source_path, out = tmp_path / "in.json", tmp_path / "out.json"
        source_path.write_text(json.dumps(source))
        _enrich_spdx3_sbom(source_path, out, _Enricher())
        return json.loads(out.read_text())

    def _augmented(self, source: dict, tmp_path: Path, **kwargs) -> dict:
        from sbomify_action.augmentation import augment_spdx3_sbom

        source_path, out = tmp_path / "in.json", tmp_path / "out.json"
        source_path.write_text(json.dumps(source))
        augment_spdx3_sbom(
            str(source_path),
            str(out),
            {"supplier": {"name": "Acme Corp"}, "authors": [{"name": "A Person"}], "licenses": [{"spdx_id": "MIT"}]},
            **kwargs,
        )
        return json.loads(out.read_text())

    def _declared(self, document: dict) -> list[str]:
        by_id = {e.get("spdxId"): e for e in document["@graph"]}
        return [
            by_id.get(r["to"][0], {}).get("simplelicensing_licenseExpression")
            for r in _elements(document, "Relationship")
            if r["relationshipType"] == "hasDeclaredLicense"
        ]

    def test_enrich_leaves_a_valid_document_valid(self, tmp_path, validator):
        assert _errors(validator, self._enriched(self._undeclared(), tmp_path)) == []

    def test_augment_leaves_a_valid_document_valid(self, tmp_path, validator):
        assert _errors(validator, self._augmented(self._undeclared(), tmp_path)) == []

    def test_enrich_states_the_licence_where_a_reader_looks(self, tmp_path):
        assert self._declared(self._enriched(self._undeclared(), tmp_path)) == [self.LICENCE]

    def test_enrich_does_not_second_guess_a_package_that_already_declared(self, tmp_path):
        """declared_license is unset on any package whose author stated a
        licence the 3.0.1 way, so reading that field alone as "no licence" is
        how a contradicting second declaration got added."""
        enriched = self._enriched(json.loads(FIXTURE.read_text()), tmp_path)

        assert self._declared(enriched) == ["MIT"]

    def test_augment_does_not_second_guess_either(self, tmp_path):
        assert self._declared(self._augmented(json.loads(FIXTURE.read_text()), tmp_path)) == ["MIT"]

    def test_overriding_replaces_the_declaration_rather_than_adding_one(self, tmp_path):
        """Two hasDeclaredLicense relationships that disagree are worse than
        either of them alone."""
        augmented = self._augmented(json.loads(FIXTURE.read_text()), tmp_path, override_sbom_metadata=True)

        assert self._declared(augmented) == ["MIT"]
        assert len(_elements(augmented, "Relationship")) == 2  # the concluded one is untouched

    def test_enrich_names_one_supplier_not_a_list_of_one(self, tmp_path):
        package = _elements(self._enriched(self._undeclared(), tmp_path), "software_Package")[0]

        assert isinstance(package["suppliedBy"], str)

    def test_the_agents_enrich_mints_say_who_created_them(self, tmp_path):
        enriched = self._enriched(self._undeclared(), tmp_path)

        minted = _elements(enriched, "Organization")
        assert minted and all(_creation_infos(e)[0].get("createdBy") for e in minted)


class TestTheOtherWritePaths:
    """The paths that write SPDX 3 without validating, so an invalid document
    from one of them reaches the upload rather than the log.
    """

    def test_an_empty_sbom_validates(self, tmp_path, validator):
        """`create_empty_sbom` built its own CreationInfo beside
        make_spdx3_creation_info and left createdBy empty, so both elements it
        writes failed."""
        from sbomify_action.additional_packages import create_empty_sbom

        out = tmp_path / "empty.json"
        create_empty_sbom(str(out), "spdx", spec_version="3.0.1")

        assert _errors(validator, json.loads(out.read_text())) == []

    def test_a_component_override_leaves_the_document_valid(self, tmp_path, validator):
        """What the CLI does for COMPONENT_NAME and COMPONENT_VERSION."""
        payload = parse_spdx3_data(json.loads(FIXTURE.read_text()))
        package = next(p for p in payload.get_full_map().values() if isinstance(p, Package))
        package.name, package.package_version = "renamed", "9.9.9"
        out = tmp_path / "out.json"
        write_spdx3_file(payload, str(out))

        written = json.loads(out.read_text())
        assert _errors(validator, written) == []
        assert _elements(written, "software_Package")[0]["software_packageVersion"] == "9.9.9"


class TestWhatTheProducerWroteSurvivesTheRoundTrip:
    """Three ways the preservation machinery lost what it was built to keep."""

    def test_a_purpose_the_library_knows_survives_beside_one_it_does_not(self, tmp_path, validator):
        """Only the strangers were kept, and restoring overwrites the whole
        list, so a package listing both came back with only the stranger."""
        source = json.loads(FIXTURE.read_text())
        for element in source["@graph"]:
            if element.get("type") == "software_Package":
                element["software_additionalPurpose"] = ["library", "specification"]

        written = _write(source, tmp_path)

        assert _errors(validator, written) == []
        assert _elements(written, "software_Package")[0]["software_additionalPurpose"] == [
            "library",
            "specification",
        ]

    @pytest.mark.parametrize(
        "context",
        [
            pytest.param(["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"], id="list"),
            pytest.param({"@vocab": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}, id="object"),
        ],
    )
    def test_a_context_that_is_not_a_bare_string_is_still_the_document_s(self, context, tmp_path):
        """JSON-LD allows all three shapes and is_spdx3 reads all three. Taking
        only the string left context_url unset, and the writer then relabelled
        the document to the current release."""
        source = json.loads(FIXTURE.read_text())
        source["@context"] = context

        written = _write(source, tmp_path)

        assert written["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

    @pytest.mark.parametrize(
        "context",
        [
            pytest.param("https://spdx.org/rdf/3.0.1/terms/Core/", id="only-a-terms-iri"),
            pytest.param(
                [
                    "https://spdx.org/rdf/3.0.1/terms/Core/",
                    "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                ],
                id="a-terms-iri-listed-first",
            ),
        ],
    )
    def test_an_spdx_url_that_is_not_the_context_is_not_written_as_one(self, context, tmp_path):
        """Any spdx.org/rdf/3 URL counted as the document's context, so a
        document naming a terms IRI came back declaring that as its @context.
        The schemas pin @context with a const, so nothing would accept it."""
        source = json.loads(FIXTURE.read_text())
        source["@context"] = context

        written = _write(source, tmp_path)

        assert written["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

    def test_an_http_context_is_written_back_as_https(self, tmp_path, validator):
        """The schemas pin @context to the https form with a const, so what an
        http one names is the version rather than the scheme. Echoing the
        scheme back meant the action wrote a document its own validation step
        then refused."""
        source = json.loads(FIXTURE.read_text())
        source["@context"] = "http://spdx.org/rdf/3.0.1/spdx-context.jsonld"

        written = _write(source, tmp_path)

        assert written["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
        assert _errors(validator, written) == []

    def test_a_line_alias_context_is_resolved_to_the_one_the_schemas_pin(self, tmp_path, validator):
        """spdx.org/rdf/3.0/ is served and byte-identical to the 3.0.1 one, so
        a producer may point at it, but the schemas pin @context with a const
        and reject the alias. Writing it through meant the action emitted
        documents its own validation step then refused.

        The version comes from the document's own CreationInfos, so resolving
        it states no more than the document already did.
        """
        source = json.loads(FIXTURE.read_text())
        source["@context"] = "https://spdx.org/rdf/3.0/spdx-context.jsonld"

        written = _write(source, tmp_path)

        assert written["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
        assert _errors(validator, written) == []

    def test_two_runs_stating_a_licence_produce_the_same_bytes(self, tmp_path):
        """The elements a draft licence field turns into were named with a
        fresh uuid4 each write, so a document rewritten with no change to its
        licences still came back with a diff to read and discard."""
        written = []
        for name in ("a", "b"):
            payload = parse_spdx3_data(json.loads(FIXTURE.read_text()))
            package = next(e for e in payload.get_full_map().values() if isinstance(e, Package))
            package.declared_license = spdx3_license_from_string("MIT")
            (tmp_path / name).mkdir(parents=True, exist_ok=True)
            out = tmp_path / name / "out.json"
            write_spdx3_file(payload, str(out))
            written.append(json.loads(out.read_text()))

        minted = [e for e in written[0]["@graph"] if e.get("type") == "simplelicensing_LicenseExpression"]
        assert minted
        assert json.dumps(written[0], sort_keys=True) == json.dumps(written[1], sort_keys=True)

    def test_two_runs_over_one_input_produce_the_same_bytes(self, tmp_path):
        """The minted agent stamped the clock, so every rewrite differed by a
        line a user had to read and discard.

        The agent is only added when something already names it, so the input
        has to carry an element the action minted for the regression to have
        anywhere to happen.
        """
        source = json.loads(FIXTURE.read_text())
        source["@graph"].append(
            {
                "type": "Organization",
                "spdxId": "urn:acme:minted",
                "name": "Acme",
                "creationInfo": {
                    "type": "CreationInfo",
                    "specVersion": "3.0.1",
                    "created": "2026-01-01T00:00:00Z",
                    "createdBy": [_ACTION_AGENT_ID],
                },
            }
        )

        first = _write(copy.deepcopy(source), tmp_path / "a")
        second = _write(copy.deepcopy(source), tmp_path / "b")

        agent = next(e for e in first["@graph"] if e.get("spdxId") == _ACTION_AGENT_ID)
        assert agent["creationInfo"]["created"] == "2026-01-01T00:00:00Z"
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


class TestOverridingALicenceLeavesNoDanglingReference:
    """A document that lists its elements is asserting what it contains.

    Overriding a declared licence removes the relationship that stated the old
    one. Removing it from the graph but not from that list leaves the document
    claiming an element nobody can resolve, and no schema catches it: JSON
    Schema cannot follow a cross-reference.
    """

    def _augmented(self, tmp_path):
        import json as _json

        from sbomify_action.augmentation import augment_spdx3_sbom

        source = _json.loads(FIXTURE.read_text())
        document = next(e for e in source["@graph"] if e.get("type") == "SpdxDocument")
        document["element"] = [
            e["spdxId"] for e in source["@graph"] if e.get("spdxId") and e["spdxId"] != document["spdxId"]
        ]
        in_path, out_path = tmp_path / "in.json", tmp_path / "out.json"
        in_path.write_text(_json.dumps(source))
        augment_spdx3_sbom(
            str(in_path),
            str(out_path),
            {"licenses": [{"spdx_id": "GPL-3.0-only"}]},
            override_sbom_metadata=True,
        )
        return _json.loads(out_path.read_text())

    def test_every_listed_element_is_in_the_graph(self, tmp_path):
        written = self._augmented(tmp_path)

        present = {e.get("spdxId") for e in written["@graph"] if e.get("spdxId")}
        listed = next(e for e in written["@graph"] if e.get("type") == "SpdxDocument").get("element", [])

        assert [x for x in listed if x not in present] == []

    def test_the_override_still_took(self, tmp_path):
        written = self._augmented(tmp_path)

        by_id = {e.get("spdxId"): e for e in written["@graph"]}
        declared = [
            by_id.get(r["to"][0], {}).get("simplelicensing_licenseExpression")
            for r in _elements(written, "Relationship")
            if r["relationshipType"] == "hasDeclaredLicense"
        ]

        assert declared == ["GPL-3.0-only"]


class TestWhatTheActionMintsAgreesWithTheDocument:
    """make_spdx3_creation_info hardcodes 3.0.1 because it has no document to
    ask. The writer preserves the @context the input declared, so a 3.0
    document came back carrying 3.0.1 on every element the action added: the
    context and specVersion disagreement this module exists to prevent,
    walking back in through the minting path.
    """

    @staticmethod
    def _as_300_with_a_minted_element(tmp_path):
        from sbomify_action.spdx3 import Organization, make_spdx3_creation_info

        source = json.loads(FIXTURE.read_text())
        source["@context"] = "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"
        for element in source["@graph"]:
            if element.get("type") == "CreationInfo":
                element["specVersion"] = "3.0.0"
        payload = parse_spdx3_data(source)
        payload.add_element(
            Organization(spdx_id="urn:acme:minted", name="Acme", creation_info=make_spdx3_creation_info())
        )
        tmp_path.mkdir(parents=True, exist_ok=True)
        out = tmp_path / "out.json"
        write_spdx3_file(payload, str(out))
        return json.loads(out.read_text())

    @staticmethod
    def _spec_versions(node, found=None):
        found = [] if found is None else found
        if isinstance(node, dict):
            if isinstance(node.get("specVersion"), str):
                found.append(node["specVersion"])
            for value in node.values():
                TestWhatTheActionMintsAgreesWithTheDocument._spec_versions(value, found)
        elif isinstance(node, list):
            for item in node:
                TestWhatTheActionMintsAgreesWithTheDocument._spec_versions(item, found)
        return found

    def test_one_version_throughout(self, tmp_path):
        written = self._as_300_with_a_minted_element(tmp_path)

        assert set(self._spec_versions(written["@graph"])) == {"3.0.0"}

    def test_the_context_still_agrees_with_it(self, tmp_path):
        written = self._as_300_with_a_minted_element(tmp_path)

        assert written["@context"] == "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"

    @staticmethod
    def _minted_under(context, tmp_path):
        from sbomify_action.spdx3 import Organization, make_spdx3_creation_info

        source = json.loads(FIXTURE.read_text())
        source["@context"] = context
        payload = parse_spdx3_data(source)
        payload.add_element(
            Organization(spdx_id="urn:acme:minted", name="Acme", creation_info=make_spdx3_creation_info())
        )
        tmp_path.mkdir(parents=True, exist_ok=True)
        out = tmp_path / "out.json"
        write_spdx3_file(payload, str(out))
        written = json.loads(out.read_text())
        minted = [ci for ci in _creation_infos(written) if _ACTION_AGENT_ID in (ci.get("createdBy") or [])]
        assert minted
        return {ci["specVersion"] for ci in minted}

    def test_a_two_part_context_takes_the_version_the_producer_states(self, tmp_path):
        """spdx.org/rdf/3.0/ is a real context, and the version read off it has
        two parts. Writing that as a specVersion fails the semver pattern the
        schema holds it to, so what the producer states settles it and the
        context only says which line."""
        assert self._minted_under("https://spdx.org/rdf/3.0/spdx-context.jsonld", tmp_path) == {"3.0.1"}

    @pytest.mark.parametrize("inline", [True, False], ids=["inline", "referenced"])
    def test_the_document_settles_the_patch_not_whichever_element_comes_first(self, inline, tmp_path):
        """A merged document carries another document's version on the element
        it took. Scanning the graph let that element pick the patch for the
        whole document, which decides both the @context written and the schema
        the result is held to."""
        from sbomify_action.spdx3 import _three_part_spec_version

        copied = {
            "type": "software_Package",
            "spdxId": "urn:copied",
            "creationInfo": {"type": "CreationInfo", "specVersion": "3.0.0"},
        }
        if inline:
            element_list = [
                copied,
                {
                    "type": "SpdxDocument",
                    "spdxId": "urn:doc",
                    "creationInfo": {"type": "CreationInfo", "specVersion": "3.0.1"},
                },
            ]
        else:
            element_list = [
                copied,
                {"type": "CreationInfo", "@id": "_:doc-ci", "specVersion": "3.0.1"},
                {"type": "SpdxDocument", "spdxId": "urn:doc", "creationInfo": "_:doc-ci"},
            ]

        assert _three_part_spec_version("3.0", element_list) == "3.0.1"

    def test_without_an_spdx_document_the_graph_still_answers(self, tmp_path):
        """The preference is a preference. A fragment with no SpdxDocument
        still has a producer worth asking."""
        from sbomify_action.spdx3 import _three_part_spec_version

        element_list = [
            {
                "type": "software_Package",
                "spdxId": "urn:p",
                "creationInfo": {"type": "CreationInfo", "specVersion": "3.0.0"},
            }
        ]

        assert _three_part_spec_version("3.0", element_list) == "3.0.0"

    def test_a_two_part_context_with_nothing_else_to_go_on_settles_on_zero(self, tmp_path):
        """A document the action builds from nothing has no producer to ask,
        and .0 is at least a version the schema will read."""
        from sbomify_action.spdx3 import Organization, Spdx3Payload, make_spdx3_creation_info

        payload = Spdx3Payload()
        payload.add_element(
            Organization(spdx_id="urn:acme:minted", name="Acme", creation_info=make_spdx3_creation_info())
        )
        tmp_path.mkdir(parents=True, exist_ok=True)
        out = tmp_path / "out.json"
        write_spdx3_file(payload, str(out), context_url="https://spdx.org/rdf/3.0/spdx-context.jsonld")

        written = json.loads(out.read_text())
        minted = [ci for ci in _creation_infos(written) if _ACTION_AGENT_ID in (ci.get("createdBy") or [])]
        assert minted and {ci["specVersion"] for ci in minted} == {"3.0.0"}

    def test_a_301_document_is_left_at_301(self, tmp_path):
        written = self._as_300_with_a_minted_element(tmp_path / "a")
        assert "3.0.1" not in self._spec_versions(written["@graph"])

        plain = _write(json.loads(FIXTURE.read_text()), tmp_path / "b")
        assert set(self._spec_versions(plain["@graph"])) == {"3.0.1"}


class TestAProfileStatedTheWayTheDraftStatesIt:
    """spdx-tools puts conformance on the CreationInfo as ``profile``, real
    producers emit it there, and the normalisation strips it from every
    CreationInfo on the way out. A document that stated its conformance only
    there silently stopped claiming it.
    """

    def _written(self, tmp_path, inline: bool) -> dict:
        source = json.loads(FIXTURE.read_text())
        document = next(e for e in source["@graph"] if e.get("type") == "SpdxDocument")
        document.pop("profileConformance", None)
        if inline:
            document["creationInfo"] = {"type": "CreationInfo", "specVersion": "3.0.1", "profile": ["core", "software"]}
        else:
            referenced = next(
                e for e in source["@graph"] if (e.get("@id") or e.get("spdxId")) == document["creationInfo"]
            )
            referenced["profile"] = ["core", "software"]
        return _write(source, tmp_path)

    @pytest.mark.parametrize("inline", [True, False], ids=["inline", "referenced"])
    def test_it_survives_as_the_property_3_0_1_has(self, inline, tmp_path):
        written = self._written(tmp_path, inline)

        assert _elements(written, "SpdxDocument")[0]["profileConformance"] == ["core", "software"]

    def test_the_document_s_own_claim_still_wins(self, tmp_path):
        """The fallback is a fallback. A document stating both keeps what it
        put on the property 3.0.1 actually reads."""
        source = json.loads(FIXTURE.read_text())
        document = next(e for e in source["@graph"] if e.get("type") == "SpdxDocument")
        document["profileConformance"] = ["core"]
        referenced = next(e for e in source["@graph"] if (e.get("@id") or e.get("spdxId")) == document["creationInfo"])
        referenced["profile"] = ["core", "software", "licensing"]

        written = _write(source, tmp_path)

        assert _elements(written, "SpdxDocument")[0]["profileConformance"] == ["core"]

    def test_a_document_that_claimed_neither_still_claims_neither(self, tmp_path):
        """Conformance is a claim about what the document satisfies, so one
        nobody wrote must not appear because the writer went looking."""
        source = json.loads(FIXTURE.read_text())
        document = next(e for e in source["@graph"] if e.get("type") == "SpdxDocument")
        document.pop("profileConformance", None)

        written = _write(source, tmp_path)

        assert "profileConformance" not in _elements(written, "SpdxDocument")[0]


class TestADataLicenseTheDocumentPointsAtRatherThanInlines:
    """JSON-LD lets a document inline its CreationInfo or reference one, and
    this repo's own fixtures reference: ``"creationInfo": "_:creationinfo"``.
    Reading only the inline form meant a legacy dataLicense on the referenced
    element was stripped by the normalisation and never put back.
    """

    def _written(self, value: str, tmp_path) -> dict:
        source = json.loads(FIXTURE.read_text())
        for element in source["@graph"]:
            if element.get("type") == "CreationInfo":
                element["dataLicense"] = value
        return _write(source, tmp_path)

    def test_it_survives(self, tmp_path):
        written = self._written("https://spdx.org/licenses/CC0-1.0", tmp_path)

        document = _elements(written, "SpdxDocument")[0]
        assert document["dataLicense"] == "https://spdx.org/licenses/CC0-1.0"

    def test_a_bare_id_is_written_the_way_3_0_1_spells_it(self, tmp_path, validator):
        """The draft location holds a bare id. dataLicense on SpdxDocument
        resolves to a licence IRI, so carrying the value forward has to carry
        its spelling forward or the document it lands in fails the schema."""
        written = self._written("CC0-1.0", tmp_path)

        assert _errors(validator, written) == []
        assert _elements(written, "SpdxDocument")[0]["dataLicense"] == "https://spdx.org/licenses/CC0-1.0"

    def test_a_document_that_declared_none_still_gains_none(self, round_tripped):
        assert "dataLicense" not in _elements(round_tripped, "SpdxDocument")[0]
