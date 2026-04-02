"""Regression test for SPDX 2.x version override via documentDescribes.

Ensures the version override targets the root package identified by
documentDescribes, not blindly packages[0].
"""

import json
import tempfile
import unittest
from unittest.mock import MagicMock

from sbomify_action.cli.main import _apply_sbom_version_override


def _make_spdx2_json(root_spdxid: str = "SPDXRef-Root", root_version: str = "1.0.0") -> dict:
    """Create a minimal SPDX 2.3 JSON where packages[0] is NOT the root."""
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "dataLicense": "CC0-1.0",
        "name": "test",
        "documentNamespace": "https://example.com/test",
        "documentDescribes": [root_spdxid],
        "packages": [
            {
                "SPDXID": "SPDXRef-Dep",
                "name": "some-dependency",
                "versionInfo": "0.1.0",
                "downloadLocation": "NOASSERTION",
            },
            {
                "SPDXID": root_spdxid,
                "name": "root-package",
                "versionInfo": root_version,
                "downloadLocation": "NOASSERTION",
            },
        ],
    }


class TestSpdx2VersionOverride(unittest.TestCase):
    """Test SPDX 2.x version override finds root via documentDescribes."""

    def _write_and_override(self, sbom_json: dict, new_version: str) -> dict:
        """Write SBOM to temp file, apply override, return result."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(sbom_json, f)
            f.flush()
            path = f.name

        config = MagicMock()
        config.component_version = new_version
        _apply_sbom_version_override(path, config)

        with open(path) as f:
            return json.load(f)

    def test_version_applied_to_document_describes_root(self):
        """Version override should target the documentDescribes root, not packages[0]."""
        sbom = _make_spdx2_json(root_spdxid="SPDXRef-Root", root_version="sha256:abc123")
        result = self._write_and_override(sbom, "v2.0.0")

        # Root package (packages[1]) should have new version
        root_pkg = next(p for p in result["packages"] if p["SPDXID"] == "SPDXRef-Root")
        self.assertEqual(root_pkg["versionInfo"], "v2.0.0")

        # Dependency (packages[0]) should be unchanged
        dep_pkg = next(p for p in result["packages"] if p["SPDXID"] == "SPDXRef-Dep")
        self.assertEqual(dep_pkg["versionInfo"], "0.1.0")

    def test_fallback_to_packages_0_when_no_document_describes(self):
        """Without documentDescribes, should fall back to packages[0]."""
        sbom = _make_spdx2_json()
        del sbom["documentDescribes"]
        result = self._write_and_override(sbom, "v3.0.0")

        # packages[0] gets the override as fallback
        self.assertEqual(result["packages"][0]["versionInfo"], "v3.0.0")

    def test_invalid_document_describes_type_falls_back(self):
        """If documentDescribes is not a list, should fall back to packages[0]."""
        sbom = _make_spdx2_json()
        sbom["documentDescribes"] = {"invalid": "type"}
        result = self._write_and_override(sbom, "v4.0.0")

        # Falls back to packages[0]
        self.assertEqual(result["packages"][0]["versionInfo"], "v4.0.0")
