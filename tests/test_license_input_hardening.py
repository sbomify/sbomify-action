"""Malformed licence data must not end the run.

The licence paths run on documents the action already knows it cannot trust:
that is what the sanitizers are for. Each case below is one where a licence
value stopped the whole run with a traceback naming a third-party module
rather than the component or the field -- the same failure mode as
``GITHUB-ACTION-FW`` (a bare ``license.text``) and ``GITHUB-ACTION-F0``
(a licence id off the SPDX list), found by walking the rest of the licence
surface after those two.
"""

from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
from typing import Any

import pytest
from cyclonedx.model.bom import Bom

from sbomify_action._enrichment.license_normalizer import (
    validate_spdx_expression as normalizer_validate,
)
from sbomify_action._enrichment.license_utils import (
    normalize_license,
    normalize_license_list,
    validate_spdx_expression,
)
from sbomify_action._spdx_expression import (
    is_known_spdx_expression,
    parse_spdx_expression,
    spdx_licensing,
)
from sbomify_action.serialization import (
    _is_compound_expression,
    _sanitize_spdx_license_expression,
    load_cyclonedx_bom,
    sanitize_cyclonedx_licenses,
    sanitize_spdx_licenses,
)
from sbomify_action.validation import validate_sbom_data

#: Strings that tokenize as SPDX but cannot be assembled into a tree.
#: ``license_expression`` raises ``IndexError`` for the first and
#: ``AssertionError`` for the second -- neither is an ``ExpressionError``, so
#: neither was caught anywhere in this package.
UNASSEMBLABLE = ["MIT AND ()", "( AND MIT"]


def _cyclonedx(licenses: Any) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {},
        "components": [
            {
                "type": "library",
                "name": "pkg",
                "version": "1.0",
                "bom-ref": "pkg@1.0",
                "licenses": licenses,
            }
        ],
    }


class TestTheParserRaisesMoreThanExpressionError:
    """``except ExpressionError`` is not the whole failure surface."""

    @pytest.mark.parametrize("expression", UNASSEMBLABLE)
    def test_the_library_itself_still_raises(self, expression: str) -> None:
        """Why the wrapper exists, asserted rather than described.

        If a future release of ``license_expression`` turns these into an
        ``ExpressionError``, this is the test that says the wrapper's broad
        catch can be narrowed.
        """
        with pytest.raises((IndexError, AssertionError)):
            spdx_licensing().parse(expression, validate=False)

    @pytest.mark.parametrize("expression", UNASSEMBLABLE)
    def test_the_wrapper_answers_none(self, expression: str) -> None:
        assert parse_spdx_expression(expression) is None
        assert is_known_spdx_expression(expression) is False

    def test_a_real_expression_still_parses(self) -> None:
        parsed = parse_spdx_expression("Apache-2.0 WITH LLVM-exception OR MIT")
        assert parsed is not None
        assert is_known_spdx_expression("Apache-2.0 WITH LLVM-exception OR MIT") is True

    @pytest.mark.parametrize("expression", UNASSEMBLABLE)
    def test_every_validator_says_invalid_instead_of_raising(self, expression: str) -> None:
        assert validate_spdx_expression(expression) is False
        assert normalizer_validate(expression) is False
        assert _is_compound_expression(expression) is False
        # Unparseable: the whole string is kept as one reference, which is
        # what the docstring promised for an expression that cannot be read.
        sanitized, was_modified = _sanitize_spdx_license_expression(expression)
        assert was_modified is True
        assert sanitized.startswith("LicenseRef-")

    @pytest.mark.parametrize("expression", UNASSEMBLABLE)
    def test_normalize_license_keeps_the_original(self, expression: str) -> None:
        assert normalize_license(expression) == (expression, None)

    @pytest.mark.parametrize("expression", UNASSEMBLABLE)
    def test_a_component_carrying_one_is_repaired_not_fatal(self, expression: str) -> None:
        in_expression = _cyclonedx([{"expression": expression}])
        assert sanitize_cyclonedx_licenses(in_expression) == 1
        assert in_expression["components"][0]["licenses"][0]["expression"].startswith("LicenseRef-")

        # In license.id it is not a compound expression and not on the SPDX
        # list, so it lands in license.name with the value intact.
        in_id = _cyclonedx([{"license": {"id": expression}}])
        assert sanitize_cyclonedx_licenses(in_id) == 1
        assert in_id["components"][0]["licenses"][0]["license"] == {"name": expression}

        spdx = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "pkg", "licenseConcluded": expression}]}
        assert sanitize_spdx_licenses(spdx) == 1
        assert spdx["packages"][0]["licenseConcluded"].startswith("LicenseRef-")

    def test_one_licensing_instance_is_shared(self) -> None:
        """``get_spdx_licensing`` indexes the whole SPDX symbol table.

        Three modules each held their own copy of that index before they
        shared this one.
        """
        assert spdx_licensing() is spdx_licensing()

    def test_the_parser_is_reached_through_the_wrapper_only(self) -> None:
        """``get_spdx_licensing`` belongs to ``_spdx_expression`` and nowhere else.

        Each module that imported it wrote its own ``except ExpressionError``,
        and every one of them was wrong in the same way. Keeping the import to
        one module is what stops the next one repeating it.
        """
        package = Path(__file__).resolve().parents[1] / "sbomify_action"
        wrapper = package / "_spdx_expression.py"
        offenders: list[str] = []

        for path in sorted(package.rglob("*.py")):
            if path == wrapper:
                continue
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.ImportFrom) or node.module != "license_expression":
                    continue
                for alias in node.names:
                    if alias.name == "get_spdx_licensing":
                        offenders.append(f"{path.relative_to(package)}:{node.lineno}")

        assert not offenders, (
            "get_spdx_licensing imported outside _spdx_expression (the tolerant parse is skipped there):\n  "
            + "\n  ".join(offenders)
        )


class TestLicenceValuesOfTheWrongType:
    """A value of the wrong type is rendered, not skipped.

    Skipping it was the first attempt and it only moved the failure: the
    document still reaches ``Bom.from_json``, which uses the value as a dict
    key, so a dict or a list ended the run with ``TypeError: unhashable type``
    before any validator could name the field.
    """

    @pytest.mark.parametrize("value", [2, 1.5, True, ["MIT"], {"a": 1}])
    def test_a_non_string_license_id_is_rendered_and_demoted(self, value: Any) -> None:
        data = _cyclonedx([{"license": {"id": value}}])
        assert sanitize_cyclonedx_licenses(data) == 2  # rendered, then demoted
        licence = data["components"][0]["licenses"][0]["license"]
        # No JSON object is on the SPDX list, so it lands in name with the
        # value readable rather than being dropped.
        assert "id" not in licence
        assert licence["name"] == json.dumps(value)
        assert validate_sbom_data(data, "cyclonedx", "1.6").valid is True

    @pytest.mark.parametrize("value", [2, ["MIT"], {"a": 1}])
    def test_a_non_string_name_or_expression_is_rendered(self, value: Any) -> None:
        for choice in ({"license": {"name": value}}, {"expression": value}):
            data = _cyclonedx([copy.deepcopy(choice)])
            assert sanitize_cyclonedx_licenses(data) >= 1
            assert validate_sbom_data(data, "cyclonedx", "1.6").valid is True

    @pytest.mark.parametrize("value", [["MIT"], {"a": 1}])
    def test_the_document_now_deserializes(self, value: Any) -> None:
        """The half of this the first fix missed.

        A list or a dict is unhashable, and the deserializer uses the value as
        a dict key, so skipping it left the run to die one step later.
        """
        raw = _cyclonedx([{"license": {"id": value}}])
        with pytest.raises(TypeError, match="unhashable"):
            Bom.from_json(copy.deepcopy(raw))  # type: ignore[attr-defined]
        load_cyclonedx_bom(raw)  # sanitizes first, so this no longer raises

    @pytest.mark.parametrize("value", [2, 1.5, True])
    def test_a_number_reaches_the_validator_and_is_repaired(self, value: Any) -> None:
        """A scalar is hashable, so it parses and fails schema validation instead."""
        raw = _cyclonedx([{"license": {"id": value}}])
        assert validate_sbom_data(copy.deepcopy(raw), "cyclonedx", "1.6").valid is False
        sanitize_cyclonedx_licenses(raw)
        assert validate_sbom_data(raw, "cyclonedx", "1.6").valid is True

    def test_a_null_id_is_left_alone(self) -> None:
        data = _cyclonedx([{"license": {"id": None, "name": "MIT"}}])
        before = copy.deepcopy(data)
        assert sanitize_cyclonedx_licenses(data) == 0
        assert data == before

    def test_a_string_id_is_still_sanitized(self) -> None:
        data = _cyclonedx([{"license": {"id": "apache-2.0"}}])
        assert sanitize_cyclonedx_licenses(data) == 1
        assert data["components"][0]["licenses"][0]["license"]["id"] == "Apache-2.0"


class TestBlankLicenceFields:
    """Whitespace is an empty field, not an expression nobody could read.

    ``license_expression`` answers ``None`` for " " exactly as it does for a
    string it failed on, so routing both through one "unparseable" branch
    rewrote a blank field as ``LicenseRef-unknown`` -- inventing a licence the
    document never stated, and counting it as a repair.
    """

    @pytest.mark.parametrize("blank", ["", " ", "\n", "\t  "])
    def test_a_blank_expression_is_untouched(self, blank: str) -> None:
        assert _sanitize_spdx_license_expression(blank) == (blank, False)

    @pytest.mark.parametrize("blank", [" ", "\n"])
    def test_a_blank_spdx_field_is_not_counted_as_a_repair(self, blank: str) -> None:
        data = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "p", "licenseDeclared": blank}]}
        assert sanitize_spdx_licenses(data) == 0
        assert data["packages"][0]["licenseDeclared"] == blank

    def test_a_real_unparseable_expression_still_becomes_a_ref(self) -> None:
        sanitized, was_modified = _sanitize_spdx_license_expression("MIT AND ()")
        assert was_modified is True
        assert sanitized.startswith("LicenseRef-")


class TestSpdxCollectionsThatAreNotArraysOfObjects:
    """``"packages": null`` is not the same as an absent key."""

    @pytest.mark.parametrize("key", ["packages", "files", "snippets"])
    @pytest.mark.parametrize("value", [None, {}, "packages", [None], ["pkg"], [[]]])
    def test_a_malformed_collection_reports_nothing_to_fix(self, key: str, value: Any) -> None:
        assert sanitize_spdx_licenses({"spdxVersion": "SPDX-2.3", key: value}) == 0

    @pytest.mark.parametrize("value", [None, "graph", [None], ["element"]])
    def test_a_malformed_graph_reports_nothing_to_fix(self, value: Any) -> None:
        assert sanitize_spdx_licenses({"@graph": value}) == 0

    def test_a_conforming_document_is_still_repaired(self) -> None:
        data = {
            "spdxVersion": "SPDX-2.3",
            "packages": [{"name": "pkg", "licenseDeclared": "Some Custom Licence"}],
        }
        assert sanitize_spdx_licenses(data) == 1
        assert data["packages"][0]["licenseDeclared"] == "LicenseRef-Some-Custom-Licence"


class TestLicencesAsARegistryActuallyAnswers:
    """Every ``normalize_license_list`` caller passes a decoded API response."""

    @pytest.mark.parametrize("value", [None, [], {}, 0])
    def test_no_licences_is_an_empty_result(self, value: Any) -> None:
        """deps.dev answers ``"licenses": null`` for a package it knows nothing about."""
        assert normalize_license_list(value) == ([], {})

    @pytest.mark.parametrize("value", [7, 1.5, object()])
    def test_a_non_iterable_answer_is_refused_not_raised(self, value: Any, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING"):
            assert normalize_license_list(value) == ([], {})
        assert "non-iterable license value" in caplog.text

    @pytest.mark.parametrize(
        "value",
        [
            {"type": "MIT", "url": "https://example.com/LICENSE"},
            {"name": "MIT"},
            {"id": "MIT"},
            {"expression": "MIT"},
        ],
    )
    def test_one_licence_stated_as_an_object_is_read_not_walked(self, value: Any) -> None:
        """npm's deprecated ``{"type": ..., "url": ...}``.

        Iterating the mapping walked its keys, registering "type" and "url" as
        licence identifiers -- licence data invented out of field names.
        """
        assert normalize_license_list(value) == (["MIT"], {})

    def test_an_object_with_no_licence_key_is_refused(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING"):
            assert normalize_license_list({"url": "https://example.com"}) == ([], {})
        assert "no type/name/id/expression key" in caplog.text

    def test_one_string_is_one_licence_not_one_per_character(self) -> None:
        """A registry that answers with a bare string used to yield M, I, T."""
        assert normalize_license_list("MIT") == (["MIT"], {})

    @pytest.mark.parametrize("entry", [{"name": "MIT"}, 7, ["MIT"], object()])
    def test_a_non_string_entry_is_dropped_with_a_warning(self, entry: Any, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING"):
            assert normalize_license_list(["MIT", entry]) == (["MIT"], {})
        assert "non-string license" in caplog.text

    def test_the_deps_dev_null_response_is_handled_at_the_source(self) -> None:
        from sbomify_action._enrichment.sources.depsdev import DepsDevSource

        metadata = DepsDevSource()._normalize_response("pkg", "pypi", {"licenses": None, "links": []})
        assert metadata is not None
        assert metadata.licenses == []
