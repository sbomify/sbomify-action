"""Tests for license_utils split and normalize functions."""

import pytest

from sbomify_action._enrichment.license_utils import (
    _split_license_string,
    get_spdx_license_info,
    is_license_text,
    is_spdx_identifier,
    normalize_license,
    normalize_license_list,
    validate_spdx_expression,
)


class TestSplitLicenseString:
    """Tests for _split_license_string."""

    def test_single_license(self):
        assert _split_license_string("MIT") == ["MIT"]

    def test_comma_separated(self):
        assert _split_license_string("Apache-2.0, MIT") == ["Apache-2.0", "MIT"]

    def test_and_separated(self):
        result = _split_license_string("GPL-2 and LGPL-2.1")
        assert result == ["GPL-2", "LGPL-2.1"]

    def test_comma_and_mixed(self):
        result = _split_license_string("MPL-1.1, GPL-2 and LGPL-2.1")
        assert result == ["MPL-1.1", "GPL-2", "LGPL-2.1"]

    def test_uppercase_and_not_split(self):
        """Uppercase AND is a valid SPDX operator and should not be split."""
        result = _split_license_string("GPL-2.0-only AND MIT")
        assert result == ["GPL-2.0-only AND MIT"]

    def test_empty_string(self):
        assert _split_license_string("") == []

    def test_whitespace_stripped(self):
        result = _split_license_string("  MIT ,  Apache-2.0  ")
        assert result == ["MIT", "Apache-2.0"]

    def test_or_separated(self):
        result = _split_license_string("GPLv2+ or LGPLv3+")
        assert result == ["GPLv2+", "LGPLv3+"]

    def test_uppercase_or_not_split(self):
        """Uppercase OR is a valid SPDX operator and should not be split."""
        result = _split_license_string("MIT OR Apache-2.0")
        assert result == ["MIT OR Apache-2.0"]

    def test_no_false_split_on_standard(self):
        """'and' inside words like 'Standard' should not cause splits."""
        result = _split_license_string("StandardLicense")
        assert result == ["StandardLicense"]


class TestNormalizeLicenseListSplitting:
    """Tests for normalize_license_list with comma/and-separated inputs."""

    def test_splits_and_normalizes(self):
        """Comma/and-separated string should be split and each part normalized."""
        licenses, _texts = normalize_license_list(["MPL-1.1, GPL-2 and LGPL-2.1"])
        assert "MPL-1.1" in licenses
        assert "GPL-2.0-only" in licenses
        # LGPL-2.1 is a valid (deprecated) SPDX ID, recognized by the parser as-is
        assert any(lic.startswith("LGPL-2.1") for lic in licenses)
        assert len(licenses) == 3

    def test_single_license_unchanged(self):
        licenses, _texts = normalize_license_list(["MIT"])
        assert licenses == ["MIT"]

    def test_alias_normalization(self):
        """Common non-SPDX shorthand IDs should be normalized."""
        licenses, _texts = normalize_license_list(["GPL-2"])
        assert licenses == ["GPL-2.0-only"]

        licenses, _texts = normalize_license_list(["GPL-3"])
        assert licenses == ["GPL-3.0-only"]

    def test_empty_list(self):
        licenses, texts = normalize_license_list([])
        assert licenses == []
        assert texts == {}

    def test_rpm_style_aliases(self):
        """RPM-style license identifiers should be normalized."""
        licenses, _texts = normalize_license_list(["GPLv2+ or LGPLv3+"])
        assert "GPL-2.0-or-later" in licenses
        assert "LGPL-3.0-or-later" in licenses

    def test_expat_alias(self):
        """Expat (Debian convention for MIT) should normalize to MIT."""
        licenses, _texts = normalize_license_list(["Expat"])
        assert licenses == ["MIT"]

    def test_full_license_text_not_split(self):
        """Full license text with commas and 'and' should not be split."""
        long_text = (
            "Permission is hereby granted, free of charge, to any person "
            "obtaining a copy of this software and associated documentation "
            "files, to deal in the Software without restriction."
        )
        licenses, texts = normalize_license_list([long_text])
        assert len(licenses) == 1
        assert licenses[0] == "LicenseRef-Custom"
        assert long_text.strip() in texts.values()

    def test_multiple_full_license_texts_unique_keys(self):
        """Multiple full license texts should get unique LicenseRef keys."""
        text_a = "A " * 60  # >100 chars
        text_b = "B " * 60
        licenses, texts = normalize_license_list([text_a, text_b])
        assert len(licenses) == 2
        assert licenses[0] != licenses[1]
        assert len(texts) == 2


class TestNormalizeLicenseParenthesized:
    """Tests for parenthesized description stripping."""

    def test_strip_parenthesized_description(self):
        """'LGPL2.1+ (the library)' should normalize to LGPL-2.1-or-later."""
        spdx_id, _text = normalize_license("LGPL2.1+ (the library)")
        assert spdx_id == "LGPL-2.1-or-later"

    def test_strip_parenthesized_expat(self):
        """'Expat (MIT/X11)' should normalize to MIT."""
        spdx_id, _text = normalize_license("Expat (MIT/X11)")
        assert spdx_id == "MIT"

    def test_valid_spdx_not_stripped(self):
        """Valid SPDX ID should be returned as-is without modification."""
        spdx_id, _text = normalize_license("MIT")
        assert spdx_id == "MIT"

    def test_gpl2_plus_parenthesized(self):
        """'GPL2+ (tests and examples)' should normalize to GPL-2.0-or-later."""
        spdx_id, _text = normalize_license("GPL2+ (tests and examples)")
        assert spdx_id == "GPL-2.0-or-later"

    def test_unknown_license_with_parens_preserves_original(self):
        """Unknown license with parenthesized description should not lose information."""
        spdx_id, _text = normalize_license("CustomLicense (foo)")
        # The original string should be preserved since stripping doesn't yield
        # a valid SPDX ID or known alias
        assert spdx_id == "CustomLicense (foo)"


class TestValidateSpdxExpression:
    """What counts as an SPDX identifier for schema purposes."""

    def test_empty_is_not_valid(self):
        assert validate_spdx_expression("") is False

    @pytest.mark.parametrize("value", ["NOASSERTION", "NONE"])
    def test_the_special_values_are_accepted(self, value):
        assert validate_spdx_expression(value) is True

    @pytest.mark.parametrize("value", ["Artistic-dist", "ClArtistic"])
    def test_scancode_only_keys_are_rejected(self, value):
        """license-expression knows these; the SPDX list does not."""
        assert validate_spdx_expression(value) is False

    def test_a_well_formed_license_ref_is_accepted(self):
        assert validate_spdx_expression("LicenseRef-Acme-1.0") is True

    @pytest.mark.parametrize("value", ["LicenseRef-", "LicenseRef-has spaces", "LicenseRef-under_score"])
    def test_a_malformed_license_ref_is_rejected(self, value):
        assert validate_spdx_expression(value) is False

    def test_a_compound_expression_is_valid(self):
        assert validate_spdx_expression("MIT OR Apache-2.0") is True

    def test_an_unparseable_expression_is_rejected(self):
        assert validate_spdx_expression("MIT OR OR") is False


class TestIsSpdxIdentifier:
    """Identifier-shaped, as opposed to a wall of licence text."""

    def test_empty_is_not_an_identifier(self):
        assert is_spdx_identifier("") is False

    def test_a_long_string_is_not_an_identifier(self):
        assert is_spdx_identifier("MIT " * 40) is False

    def test_a_multiline_string_is_not_an_identifier(self):
        assert is_spdx_identifier("MIT\nand\nmore\ntext") is False

    def test_a_real_id_is(self):
        assert is_spdx_identifier("Apache-2.0") is True


class TestIsLicenseText:
    def test_empty_is_not_text(self):
        assert is_license_text("") is False

    def test_a_short_identifier_is_not_text(self):
        assert is_license_text("MIT") is False

    def test_a_long_body_is_text(self):
        assert is_license_text("x" * 200) is True

    def test_several_newlines_make_it_text(self):
        assert is_license_text("a\nb\nc\nd") is True


class TestNormalizeLicenseListTexts:
    """Full licence bodies are kept whole and given unique keys."""

    def test_empty_entries_are_dropped(self):
        assert normalize_license_list(["", None or ""]) == ([], {})

    def test_a_full_text_is_not_split_on_its_commas(self):
        body = "Copyright notice, with commas, and the word and inside it. " + ("x" * 120)
        normalized, texts = normalize_license_list([body])
        assert normalized == ["LicenseRef-Custom"]
        assert texts["LicenseRef-Custom"] == body.strip()

    def test_two_distinct_bodies_get_distinct_keys(self):
        first = "First licence body. " + ("a" * 120)
        second = "Second licence body. " + ("b" * 120)
        normalized, texts = normalize_license_list([first, second])
        assert len(set(normalized)) == 2, normalized
        assert len(texts) == 2
        assert sorted(texts) == sorted(normalized)

    def test_three_bodies_keep_incrementing_the_suffix(self):
        bodies = [f"Body number {n}. " + ("z" * 120) for n in range(3)]
        normalized, texts = normalize_license_list(bodies)
        assert len(set(normalized)) == 3
        assert len(texts) == 3


class TestGetSpdxLicenseInfo:
    def test_empty_is_none(self):
        assert get_spdx_license_info("") is None

    @pytest.mark.parametrize("value", ["NOASSERTION", "NONE"])
    def test_special_values_are_flagged_as_special(self, value):
        info = get_spdx_license_info(value)
        assert info == {"id": value, "name": value, "is_special": True}

    def test_a_license_ref_is_flagged_as_custom(self):
        info = get_spdx_license_info("LicenseRef-Acme")
        assert info is not None and info["is_custom"] is True

    @pytest.mark.parametrize("spelling", ["Apache-2.0", "apache-2.0", "APACHE-2.0"])
    def test_a_known_id_comes_back_canonicalised(self, spelling):
        """Regression: the table is keyed by canonical spelling.

        Lowercasing the input before the lookup matched only the 65 ids that
        are already lowercase, so MIT, Apache-2.0 and 2380 others returned
        None from a function documented as case-insensitive.
        """
        info = get_spdx_license_info(spelling)
        assert info is not None, spelling
        assert info["id"] == "Apache-2.0"
        assert info["is_custom"] is False

    def test_the_common_ids_are_all_found(self):
        for spdx_id in ("MIT", "BSD-3-Clause", "GPL-2.0-only", "ISC"):
            assert get_spdx_license_info(spdx_id) is not None, spdx_id

    def test_an_unknown_id_is_none(self):
        assert get_spdx_license_info("Totally-Made-Up-9.9") is None
