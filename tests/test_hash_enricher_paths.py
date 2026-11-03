"""Behaviour of the hash enricher around the edges.

Hash enrichment is additive and best-effort: it must never be the reason a
run fails, and it must not overwrite hashes the SBOM already carries unless
told to. These are the paths where it decides to do nothing.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cyclonedx.model import HashAlgorithm as CdxHashAlgorithm
from cyclonedx.model import HashType
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType

from sbomify_action._hash_enrichment.enricher import (
    HashEnricher,
    create_default_registry,
    enrich_sbom_with_hashes,
)


def _sri(payload: bytes) -> str:
    return f"sha512-{base64.b64encode(hashlib.sha512(payload).digest()).decode()}"


def _hex(payload: bytes) -> str:
    return hashlib.sha512(payload).hexdigest()


@pytest.fixture
def npm_lock(tmp_path: Path) -> Path:
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.21", "integrity": _sri(b"lodash")}}})
    )
    return lock


def _bom_with(component: Component) -> Bom:
    bom = Bom()
    bom.components.add(component)
    return bom


class TestEnrichCycloneDX:
    def test_a_matching_component_gains_the_hash(self, npm_lock: Path):
        bom = _bom_with(Component(name="lodash", version="4.17.21", type=ComponentType.LIBRARY))

        stats = HashEnricher().enrich_cyclonedx(bom, npm_lock)

        (component,) = bom.components
        assert stats["hashes_added"] == 1
        assert stats["components_matched"] == 1
        assert {h.content for h in component.hashes} == {_hex(b"lodash")}

    def test_an_empty_lockfile_changes_nothing(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({"packages": {}}))
        bom = _bom_with(Component(name="lodash", version="4.17.21", type=ComponentType.LIBRARY))

        stats = HashEnricher().enrich_cyclonedx(bom, lock)

        assert stats == {
            "lockfile_packages": 0,
            "sbom_components": 0,
            "components_matched": 0,
            "hashes_added": 0,
            "hashes_skipped": 0,
        }

    def test_a_bom_with_no_components_is_not_an_error(self, npm_lock: Path):
        stats = HashEnricher().enrich_cyclonedx(Bom(), npm_lock)
        assert stats["sbom_components"] == 0
        assert stats["hashes_added"] == 0

    def test_a_component_with_no_version_is_skipped(self, npm_lock: Path):
        bom = _bom_with(Component(name="lodash", type=ComponentType.LIBRARY))
        stats = HashEnricher().enrich_cyclonedx(bom, npm_lock)
        assert stats["components_matched"] == 0

    def test_a_component_that_is_not_in_the_lockfile_is_skipped(self, npm_lock: Path):
        bom = _bom_with(Component(name="absent", version="1.0.0", type=ComponentType.LIBRARY))
        stats = HashEnricher().enrich_cyclonedx(bom, npm_lock)
        assert stats["components_matched"] == 0
        assert stats["hashes_added"] == 0

    def test_existing_hashes_are_left_alone_by_default(self, npm_lock: Path):
        """Whatever the generator recorded is more authoritative than a guess."""
        original = HashType(alg=CdxHashAlgorithm.SHA_512, content="a" * 128)
        component = Component(name="lodash", version="4.17.21", type=ComponentType.LIBRARY, hashes=[original])
        bom = _bom_with(component)

        stats = HashEnricher().enrich_cyclonedx(bom, npm_lock)

        assert stats["hashes_added"] == 0
        assert stats["hashes_skipped"] == 1
        assert {h.content for h in next(iter(bom.components)).hashes} == {"a" * 128}

    def test_overwrite_replaces_them(self, npm_lock: Path):
        original = HashType(alg=CdxHashAlgorithm.SHA_512, content="a" * 128)
        component = Component(name="lodash", version="4.17.21", type=ComponentType.LIBRARY, hashes=[original])
        bom = _bom_with(component)

        stats = HashEnricher().enrich_cyclonedx(bom, npm_lock, overwrite_existing=True)

        assert stats["hashes_added"] == 1
        assert {h.content for h in next(iter(bom.components)).hashes} == {_hex(b"lodash")}

    def test_the_same_hash_twice_is_counted_as_skipped(self, npm_lock: Path):
        """Re-running must be idempotent, not additive."""
        component = Component(name="lodash", version="4.17.21", type=ComponentType.LIBRARY)
        bom = _bom_with(component)

        HashEnricher().enrich_cyclonedx(bom, npm_lock)
        stats = HashEnricher().enrich_cyclonedx(bom, npm_lock, overwrite_existing=False)

        assert stats["hashes_added"] == 0
        assert stats["hashes_skipped"] >= 1

    def test_an_unknown_lockfile_type_yields_no_hashes(self, tmp_path: Path):
        lock = tmp_path / "Gemfile.lock"
        lock.write_text("GEM\n")
        bom = _bom_with(Component(name="rails", version="7.0.0", type=ComponentType.LIBRARY))

        stats = HashEnricher().enrich_cyclonedx(bom, lock)

        assert stats["lockfile_packages"] == 0


class TestEnrichSpdx:
    def _document(self, name: str = "lodash", version: str = "4.17.21") -> dict:
        return {
            "spdxVersion": "SPDX-2.3",
            "packages": [{"name": name, "versionInfo": version, "SPDXID": "SPDXRef-Package-0"}],
        }

    def test_a_matching_package_gains_a_checksum(self, npm_lock: Path):
        doc = self._document()

        stats = HashEnricher().enrich_spdx(doc, npm_lock)

        assert stats["hashes_added"] == 1
        (checksum,) = doc["packages"][0]["checksums"]
        assert checksum["checksumValue"] == _hex(b"lodash")
        assert checksum["algorithm"] == "SHA512"

    def test_a_document_with_no_packages_is_not_an_error(self, npm_lock: Path):
        stats = HashEnricher().enrich_spdx({"spdxVersion": "SPDX-2.3"}, npm_lock)
        assert stats["hashes_added"] == 0

    def test_a_package_without_a_version_is_skipped(self, npm_lock: Path):
        doc = {"spdxVersion": "SPDX-2.3", "packages": [{"name": "lodash", "SPDXID": "SPDXRef-0"}]}
        stats = HashEnricher().enrich_spdx(doc, npm_lock)
        assert stats["components_matched"] == 0

    def test_existing_checksums_are_left_alone_by_default(self, npm_lock: Path):
        doc = self._document()
        doc["packages"][0]["checksums"] = [{"algorithm": "SHA512", "checksumValue": "a" * 128}]

        stats = HashEnricher().enrich_spdx(doc, npm_lock)

        assert stats["hashes_added"] == 0
        assert doc["packages"][0]["checksums"] == [{"algorithm": "SHA512", "checksumValue": "a" * 128}]

    def test_overwrite_replaces_them(self, npm_lock: Path):
        doc = self._document()
        doc["packages"][0]["checksums"] = [{"algorithm": "SHA512", "checksumValue": "a" * 128}]

        stats = HashEnricher().enrich_spdx(doc, npm_lock, overwrite_existing=True)

        assert stats["hashes_added"] == 1
        assert doc["packages"][0]["checksums"][0]["checksumValue"] == _hex(b"lodash")


class TestEnrichSbomWithHashes:
    """The file-level entry point, and the formats it declines to touch."""

    def test_a_cyclonedx_file_is_rewritten_in_place(self, tmp_path: Path, npm_lock: Path):
        sbom = tmp_path / "sbom.json"
        sbom.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "version": 1,
                    "components": [{"type": "library", "name": "lodash", "version": "4.17.21"}],
                }
            )
        )

        stats = enrich_sbom_with_hashes(str(sbom), str(npm_lock))

        assert stats["hashes_added"] == 1
        written = json.loads(sbom.read_text())
        assert written["components"][0]["hashes"][0]["content"] == _hex(b"lodash")

    def test_an_spdx_file_is_rewritten_in_place(self, tmp_path: Path, npm_lock: Path):
        sbom = tmp_path / "sbom.spdx.json"
        sbom.write_text(
            json.dumps(
                {
                    "spdxVersion": "SPDX-2.3",
                    "packages": [{"name": "lodash", "versionInfo": "4.17.21", "SPDXID": "SPDXRef-0"}],
                }
            )
        )

        stats = enrich_sbom_with_hashes(str(sbom), str(npm_lock))

        assert stats["hashes_added"] == 1
        written = json.loads(sbom.read_text())
        assert written["packages"][0]["checksums"][0]["checksumValue"] == _hex(b"lodash")

    def test_spdx3_is_passed_through_untouched(self, tmp_path: Path, npm_lock: Path):
        """SPDX 3 hash enrichment is not implemented; it must no-op, not raise."""
        payload = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [{"type": "software_Package", "name": "lodash"}],
        }
        sbom = tmp_path / "sbom.spdx3.json"
        sbom.write_text(json.dumps(payload))

        stats = enrich_sbom_with_hashes(str(sbom), str(npm_lock))

        assert stats["hashes_added"] == 0
        assert json.loads(sbom.read_text()) == payload, "the file must not be rewritten"

    def test_an_unrecognised_document_is_declined(self, tmp_path: Path, npm_lock: Path):
        payload = {"something": "else"}
        sbom = tmp_path / "mystery.json"
        sbom.write_text(json.dumps(payload))

        stats = enrich_sbom_with_hashes(str(sbom), str(npm_lock))

        assert stats == {
            "lockfile_packages": 0,
            "sbom_components": 0,
            "components_matched": 0,
            "hashes_added": 0,
            "hashes_skipped": 0,
        }
        assert json.loads(sbom.read_text()) == payload


class TestDefaultRegistry:
    def test_it_covers_every_shipped_parser(self):
        registry = create_default_registry()
        assert {
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "uv.lock",
            "Cargo.lock",
        } <= registry.supported_files
