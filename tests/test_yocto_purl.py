"""Tests for Yocto PURL generation and injection."""

import json
from copy import deepcopy

from packageurl import PackageURL

from sbomify_action._yocto.purl import (
    _has_yocto_purl_spdx22,
    generate_yocto_purl,
    inject_yocto_purls_spdx3,
    inject_yocto_purls_spdx22,
)

# ---------------------------------------------------------------------------
# Fixtures: minimal SPDX 2.2 and SPDX 3 documents
# ---------------------------------------------------------------------------

SPDX22_BASE = {
    "spdxVersion": "SPDX-2.2",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "test",
    "packages": [
        {
            "SPDXID": "SPDXRef-busybox",
            "name": "busybox",
            "versionInfo": "1.36.1",
        }
    ],
}

SPDX3_BASE = {
    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    "@graph": [
        {
            "type": "SpdxDocument",
            "spdxId": "urn:spdx:doc",
            "name": "test",
        },
        {
            "type": "software_Package",
            "spdxId": "urn:spdx:pkg-busybox",
            "name": "busybox",
            "packageVersion": "1.36.1",
        },
    ],
}


def _write_json(tmp_path, data, name="test.spdx.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return str(path)


# ===================================================================
# TestGenerateYoctoPurl
# ===================================================================


class TestGenerateYoctoPurl:
    def test_name_and_version(self):
        assert generate_yocto_purl("busybox", "1.36.1") == "pkg:yocto/busybox@1.36.1"

    def test_name_only(self):
        assert generate_yocto_purl("busybox") == "pkg:yocto/busybox"

    def test_empty_version_treated_as_none(self):
        assert generate_yocto_purl("busybox", "") == "pkg:yocto/busybox"

    def test_output_is_parseable(self):
        purl_str = generate_yocto_purl("zlib", "1.3.1")
        parsed = PackageURL.from_string(purl_str)
        assert parsed.type == "yocto"
        assert parsed.name == "zlib"
        assert parsed.version == "1.3.1"

    def test_none_version(self):
        purl_str = generate_yocto_purl("base-files", None)
        parsed = PackageURL.from_string(purl_str)
        assert parsed.version is None


# ===================================================================
# TestHasYoctoPurlSpdx22
# ===================================================================


class TestHasYoctoPurlSpdx22:
    def test_no_external_refs(self):
        assert _has_yocto_purl_spdx22({"name": "busybox"}) is False

    def test_empty_external_refs(self):
        assert _has_yocto_purl_spdx22({"externalRefs": []}) is False

    def test_has_yocto_purl(self):
        pkg = {
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:yocto/busybox@1.36.1",
                }
            ]
        }
        assert _has_yocto_purl_spdx22(pkg) is True

    def test_has_non_yocto_purl(self):
        pkg = {
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/lodash@4.17.21",
                }
            ]
        }
        assert _has_yocto_purl_spdx22(pkg) is False

    def test_has_non_purl_ref(self):
        pkg = {
            "externalRefs": [
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*",
                }
            ]
        }
        assert _has_yocto_purl_spdx22(pkg) is False


# ===================================================================
# TestInjectYoctoPurlsSpdx22
# ===================================================================


class TestInjectYoctoPurlsSpdx22:
    def test_injects_purl_into_package_missing_one(self, tmp_path):
        data = deepcopy(SPDX22_BASE)
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx22(path)

        assert count == 1
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        pkg = result["packages"][0]
        assert len(pkg["externalRefs"]) == 1
        ref = pkg["externalRefs"][0]
        assert ref["referenceCategory"] == "PACKAGE-MANAGER"
        assert ref["referenceType"] == "purl"
        assert ref["referenceLocator"] == "pkg:yocto/busybox@1.36.1"

    def test_skips_package_with_existing_yocto_purl(self, tmp_path):
        data = deepcopy(SPDX22_BASE)
        data["packages"][0]["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:yocto/busybox@1.36.1",
            }
        ]
        path = _write_json(tmp_path, data)
        original = json.loads(tmp_path.joinpath("test.spdx.json").read_text())

        count = inject_yocto_purls_spdx22(path)

        assert count == 0
        after = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        assert after == original

    def test_adds_yocto_purl_alongside_non_yocto_purl(self, tmp_path):
        data = deepcopy(SPDX22_BASE)
        data["packages"][0]["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:npm/lodash@4.17.21",
            }
        ]
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx22(path)

        assert count == 1
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        refs = result["packages"][0]["externalRefs"]
        assert len(refs) == 2
        locators = [r["referenceLocator"] for r in refs]
        assert "pkg:npm/lodash@4.17.21" in locators
        assert "pkg:yocto/busybox@1.36.1" in locators

    def test_handles_multiple_packages(self, tmp_path):
        data = deepcopy(SPDX22_BASE)
        data["packages"].append(
            {
                "SPDXID": "SPDXRef-zlib",
                "name": "zlib",
                "versionInfo": "1.3.1",
            }
        )
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx22(path)

        assert count == 2
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        assert result["packages"][0]["externalRefs"][0]["referenceLocator"] == "pkg:yocto/busybox@1.36.1"
        assert result["packages"][1]["externalRefs"][0]["referenceLocator"] == "pkg:yocto/zlib@1.3.1"

    def test_handles_missing_version_info(self, tmp_path):
        data = deepcopy(SPDX22_BASE)
        del data["packages"][0]["versionInfo"]
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx22(path)

        assert count == 1
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        assert result["packages"][0]["externalRefs"][0]["referenceLocator"] == "pkg:yocto/busybox"

    def test_preserves_existing_external_refs(self, tmp_path):
        data = deepcopy(SPDX22_BASE)
        data["packages"][0]["externalRefs"] = [
            {
                "referenceCategory": "SECURITY",
                "referenceType": "cpe23Type",
                "referenceLocator": "cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*",
            }
        ]
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx22(path)

        assert count == 1
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        refs = result["packages"][0]["externalRefs"]
        assert len(refs) == 2
        assert refs[0]["referenceType"] == "cpe23Type"
        assert refs[1]["referenceLocator"] == "pkg:yocto/busybox@1.36.1"

    def test_idempotent(self, tmp_path):
        data = deepcopy(SPDX22_BASE)
        path = _write_json(tmp_path, data)

        first = inject_yocto_purls_spdx22(path)
        second = inject_yocto_purls_spdx22(path)

        assert first == 1
        assert second == 0
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        assert len(result["packages"][0]["externalRefs"]) == 1

    def test_uses_real_fixture(self, tmp_path):
        """Test against the real busybox.spdx.json test fixture."""
        import shutil
        from pathlib import Path

        fixture = Path(__file__).parent / "test-data" / "yocto" / "busybox.spdx.json"
        dest = tmp_path / "busybox.spdx.json"
        shutil.copy(fixture, dest)

        count = inject_yocto_purls_spdx22(str(dest))

        assert count == 1
        result = json.loads(dest.read_text())
        pkg = result["packages"][0]
        ref = pkg["externalRefs"][0]
        assert ref["referenceLocator"] == "pkg:yocto/busybox@1.36.1"


# ===================================================================
# TestInjectYoctoPurlsSpdx3
# ===================================================================


class TestInjectYoctoPurlsSpdx3:
    def test_injects_package_url_into_package_missing_one(self, tmp_path):
        data = deepcopy(SPDX3_BASE)
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx3(path)

        assert count == 1
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        pkg = result["@graph"][1]
        assert pkg["packageUrl"] == "pkg:yocto/busybox@1.36.1"

    def test_skips_package_with_existing_yocto_purl(self, tmp_path):
        data = deepcopy(SPDX3_BASE)
        data["@graph"][1]["packageUrl"] = "pkg:yocto/busybox@1.36.1"
        path = _write_json(tmp_path, data)
        original = json.loads(tmp_path.joinpath("test.spdx.json").read_text())

        count = inject_yocto_purls_spdx3(path)

        assert count == 0
        after = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        assert after == original

    def test_skips_package_with_existing_non_yocto_purl(self, tmp_path):
        data = deepcopy(SPDX3_BASE)
        data["@graph"][1]["packageUrl"] = "pkg:npm/lodash@4.17.21"
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx3(path)

        assert count == 0
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        assert result["@graph"][1]["packageUrl"] == "pkg:npm/lodash@4.17.21"

    def test_handles_software_package_type(self, tmp_path):
        data = deepcopy(SPDX3_BASE)
        # Already uses software_Package — verify it works
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx3(path)

        assert count == 1
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        assert result["@graph"][1]["packageUrl"] == "pkg:yocto/busybox@1.36.1"

    def test_handles_package_type(self, tmp_path):
        data = deepcopy(SPDX3_BASE)
        data["@graph"][1]["type"] = "Package"
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx3(path)

        assert count == 1

    def test_skips_non_package_elements(self, tmp_path):
        data = deepcopy(SPDX3_BASE)
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx3(path)

        # Only the software_Package should be injected, not SpdxDocument
        assert count == 1
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        assert "packageUrl" not in result["@graph"][0]

    def test_handles_multiple_packages(self, tmp_path):
        data = deepcopy(SPDX3_BASE)
        data["@graph"].append(
            {
                "type": "software_Package",
                "spdxId": "urn:spdx:pkg-zlib",
                "name": "zlib",
                "packageVersion": "1.3.1",
            }
        )
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx3(path)

        assert count == 2
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        assert result["@graph"][1]["packageUrl"] == "pkg:yocto/busybox@1.36.1"
        assert result["@graph"][2]["packageUrl"] == "pkg:yocto/zlib@1.3.1"

    def test_idempotent(self, tmp_path):
        data = deepcopy(SPDX3_BASE)
        path = _write_json(tmp_path, data)

        first = inject_yocto_purls_spdx3(path)
        second = inject_yocto_purls_spdx3(path)

        assert first == 1
        assert second == 0
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        assert result["@graph"][1]["packageUrl"] == "pkg:yocto/busybox@1.36.1"

    def test_handles_at_type_key(self, tmp_path):
        """SPDX 3 JSON-LD may use @type instead of type."""
        data = deepcopy(SPDX3_BASE)
        pkg = data["@graph"][1]
        pkg["@type"] = pkg.pop("type")
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx3(path)

        assert count == 1

    def test_handles_missing_version(self, tmp_path):
        data = deepcopy(SPDX3_BASE)
        del data["@graph"][1]["packageVersion"]
        path = _write_json(tmp_path, data)

        count = inject_yocto_purls_spdx3(path)

        assert count == 1
        result = json.loads(tmp_path.joinpath("test.spdx.json").read_text())
        assert result["@graph"][1]["packageUrl"] == "pkg:yocto/busybox"
