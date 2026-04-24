"""Tests for the upstream-wins SBOM merge logic."""

from sbomify_action._generation.sbom_merge import (
    SBOMIFY_SOURCE_PROP,
    SOURCE_DOCKERHUB,
    SOURCE_SYFT,
    merge_cyclonedx,
    merge_spdx,
)

# --- Helpers ---


def _get_prop(comp, name):
    for p in comp.get("properties", []):
        if p.get("name") == name:
            return p.get("value")
    return None


def _find_by_name(items, name):
    for c in items:
        if c.get("name") == name:
            return c
    return None


# --- CycloneDX tests ---


class TestMergeCycloneDX:
    def test_disjoint_purls_unions(self):
        upstream = {
            "components": [
                {"name": "libc", "purl": "pkg:deb/debian/libc@2.36", "bom-ref": "u-libc"},
            ],
        }
        syft = {
            "components": [
                {"name": "requests", "purl": "pkg:pypi/requests@2.31", "bom-ref": "s-requests"},
            ],
        }

        merged = merge_cyclonedx(upstream, syft)
        assert len(merged["components"]) == 2

        libc = _find_by_name(merged["components"], "libc")
        requests = _find_by_name(merged["components"], "requests")

        assert _get_prop(libc, SBOMIFY_SOURCE_PROP) == SOURCE_DOCKERHUB
        assert _get_prop(requests, SBOMIFY_SOURCE_PROP) == SOURCE_SYFT

    def test_overlapping_purl_upstream_wins(self):
        upstream = {
            "components": [
                {
                    "name": "openssl",
                    "purl": "pkg:deb/debian/openssl@3.0.13",
                    "version": "3.0.13",
                    "description": "upstream desc",
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                    "bom-ref": "u-openssl",
                },
            ],
        }
        syft = {
            "components": [
                {
                    "name": "openssl",
                    "purl": "pkg:deb/debian/openssl@3.0.13",
                    "version": "3.0.13",
                    "description": "syft desc — should not overwrite",
                    "licenses": [{"license": {"id": "MIT"}}],
                    "bom-ref": "s-openssl",
                },
            ],
        }

        merged = merge_cyclonedx(upstream, syft)
        assert len(merged["components"]) == 1
        openssl = merged["components"][0]
        assert openssl["description"] == "upstream desc"
        assert openssl["licenses"][0]["license"]["id"] == "Apache-2.0"
        # Syft should not add a new overlay for this PURL.
        assert _get_prop(openssl, SBOMIFY_SOURCE_PROP) == SOURCE_DOCKERHUB

    def test_overlapping_purl_fills_empty_fields(self):
        upstream = {
            "components": [
                {
                    "name": "libx",
                    "purl": "pkg:deb/debian/libx@1.0",
                    "bom-ref": "u-libx",
                    # description, licenses, supplier all missing
                },
            ],
        }
        syft = {
            "components": [
                {
                    "name": "libx",
                    "purl": "pkg:deb/debian/libx@1.0",
                    "description": "syft description",
                    "licenses": [{"license": {"id": "MIT"}}],
                    "supplier": {"name": "Syft supplier"},
                    "externalReferences": [{"type": "website", "url": "https://example.org/libx"}],
                },
            ],
        }

        merged = merge_cyclonedx(upstream, syft)
        libx = merged["components"][0]
        assert libx["description"] == "syft description"
        assert libx["licenses"][0]["license"]["id"] == "MIT"
        assert libx["supplier"]["name"] == "Syft supplier"
        assert any(r.get("url") == "https://example.org/libx" for r in libx.get("externalReferences", []))

    def test_bom_ref_collision_rewritten(self):
        upstream = {
            "components": [
                {"name": "a", "purl": "pkg:deb/debian/a@1", "bom-ref": "ref-1"},
            ],
        }
        syft = {
            "components": [
                # Same bom-ref as upstream but different PURL → should be renamed.
                {"name": "b", "purl": "pkg:pypi/b@2", "bom-ref": "ref-1"},
            ],
        }
        merged = merge_cyclonedx(upstream, syft)
        refs = {c["bom-ref"] for c in merged["components"]}
        assert "ref-1" in refs
        assert len(refs) == 2

    def test_syft_component_without_purl_is_added(self):
        upstream = {"components": []}
        syft = {"components": [{"name": "mystery", "bom-ref": "s-mystery"}]}
        merged = merge_cyclonedx(upstream, syft)
        assert len(merged["components"]) == 1
        assert _get_prop(merged["components"][0], SBOMIFY_SOURCE_PROP) == SOURCE_SYFT

    def test_purl_namespace_mismatch_falls_back_to_loose(self):
        """Amazon Linux's upstream BuildKit SBOM emits
        ``pkg:rpm/amazonlinux/bash@...`` while Syft emits ``pkg:rpm/amzn/bash@...``.
        Same package, but different namespace defeats strict identity. The
        loose-fallback dedup (type+name+version) must catch this."""
        upstream = {
            "components": [
                {
                    "name": "bash",
                    "version": "4.2.46-34.amzn2",
                    "purl": "pkg:rpm/amazonlinux/bash@4.2.46-34.amzn2?os_name=amazonlinux&os_version=2",
                    "bom-ref": "u-bash",
                },
            ],
        }
        syft = {
            "components": [
                {
                    "name": "bash",
                    "version": "4.2.46-34.amzn2",
                    "purl": "pkg:rpm/amzn/bash@4.2.46-34.amzn2?arch=x86_64&distro=amzn-2",
                    "bom-ref": "s-bash",
                    "description": "The GNU Bourne Again SHell",
                },
            ],
        }
        merged = merge_cyclonedx(upstream, syft)
        assert len(merged["components"]) == 1
        bash = merged["components"][0]
        # Upstream's PURL is preserved.
        assert bash["purl"] == "pkg:rpm/amazonlinux/bash@4.2.46-34.amzn2?os_name=amazonlinux&os_version=2"
        # But syft's description filled the empty upstream field.
        assert bash["description"] == "The GNU Bourne Again SHell"

    def test_purl_qualifiers_ignored_in_dedup(self):
        """Same package emitted with different qualifier styles by different
        generators must still dedupe. Docker/BuildKit uses
        ``os_distro=trixie&os_name=debian&os_version=13`` while Syft uses
        ``arch=amd64&distro=debian-13`` — same deb package, though."""
        upstream = {
            "components": [
                {
                    "name": "acl",
                    "version": "2.3.2-2",
                    "purl": "pkg:deb/debian/acl@2.3.2-2?os_distro=trixie&os_name=debian&os_version=13",
                    "bom-ref": "u-acl",
                },
            ],
        }
        syft = {
            "components": [
                {
                    "name": "acl",
                    "version": "2.3.2-2",
                    "purl": "pkg:deb/debian/acl@2.3.2-2?arch=amd64&distro=debian-13&upstream=acl",
                    "bom-ref": "s-acl",
                    "description": "Access control list utilities",
                },
            ],
        }
        merged = merge_cyclonedx(upstream, syft)
        # Should collapse to one component — upstream wins, gets syft's description.
        assert len(merged["components"]) == 1
        acl = merged["components"][0]
        # Upstream's PURL is preserved (upstream wins).
        assert "os_distro=trixie" in acl["purl"]
        assert acl["description"] == "Access control list utilities"


# --- SPDX tests ---


def _spdx_pkg(spdx_id, name, version=None, purl=None, **fields):
    pkg = {"SPDXID": spdx_id, "name": name, "downloadLocation": "NOASSERTION"}
    if version:
        pkg["versionInfo"] = version
    if purl:
        pkg["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ]
    pkg.update(fields)
    return pkg


class TestMergeSpdx:
    def test_disjoint_purls_unions(self):
        upstream = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [_spdx_pkg("SPDXRef-libc", "libc", "2.36", "pkg:deb/debian/libc@2.36")],
        }
        syft = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [_spdx_pkg("SPDXRef-req", "requests", "2.31", "pkg:pypi/requests@2.31")],
        }
        merged = merge_spdx(upstream, syft)
        names = {p["name"] for p in merged["packages"]}
        assert names == {"libc", "requests"}

    def test_overlapping_purl_upstream_wins(self):
        upstream = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                _spdx_pkg(
                    "SPDXRef-openssl",
                    "openssl",
                    "3.0.13",
                    "pkg:deb/debian/openssl@3.0.13",
                    description="upstream desc",
                    licenseDeclared="Apache-2.0",
                ),
            ],
        }
        syft = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                _spdx_pkg(
                    "SPDXRef-openssl-syft",
                    "openssl",
                    "3.0.13",
                    "pkg:deb/debian/openssl@3.0.13",
                    description="syft desc — should not overwrite",
                    licenseDeclared="MIT",
                ),
            ],
        }
        merged = merge_spdx(upstream, syft)
        assert len(merged["packages"]) == 1
        openssl = merged["packages"][0]
        assert openssl["description"] == "upstream desc"
        assert openssl["licenseDeclared"] == "Apache-2.0"

    def test_fills_empty_upstream_fields_and_noassertion(self):
        upstream = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                _spdx_pkg(
                    "SPDXRef-libx",
                    "libx",
                    "1.0",
                    "pkg:deb/debian/libx@1.0",
                    licenseDeclared="NOASSERTION",
                ),
            ],
        }
        syft = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                _spdx_pkg(
                    "SPDXRef-libx-syft",
                    "libx",
                    "1.0",
                    "pkg:deb/debian/libx@1.0",
                    description="syft description",
                    licenseDeclared="MIT",
                    supplier="Organization: Syft Supplier",
                ),
            ],
        }
        merged = merge_spdx(upstream, syft)
        libx = merged["packages"][0]
        assert libx["description"] == "syft description"
        assert libx["licenseDeclared"] == "MIT"
        assert libx["supplier"] == "Organization: Syft Supplier"

    def test_spdx_id_collision_rewritten(self):
        upstream = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [_spdx_pkg("SPDXRef-pkg", "a", "1", "pkg:deb/debian/a@1")],
        }
        syft = {
            "SPDXID": "SPDXRef-DOCUMENT",
            # Same SPDXID but different PURL → rename.
            "packages": [_spdx_pkg("SPDXRef-pkg", "b", "2", "pkg:pypi/b@2")],
        }
        merged = merge_spdx(upstream, syft)
        ids = {p["SPDXID"] for p in merged["packages"]}
        assert "SPDXRef-pkg" in ids
        assert len(ids) == 2

    def test_extracted_licensing_infos_carried_over(self):
        """Syft emits LicenseRef-<hash> identifiers in package license fields
        that are defined in hasExtractedLicensingInfos. Dropping that section
        produces invalid SPDX with dangling license references."""
        upstream = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [_spdx_pkg("SPDXRef-base", "base", "1", "pkg:deb/base@1")],
        }
        syft = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                _spdx_pkg(
                    "SPDXRef-extra",
                    "extra",
                    "1",
                    "pkg:pypi/extra@1",
                    licenseDeclared="LicenseRef-custom-1",
                ),
            ],
            "hasExtractedLicensingInfos": [
                {"licenseId": "LicenseRef-custom-1", "extractedText": "Custom license text"},
                {"licenseId": "LicenseRef-custom-2", "extractedText": "Another"},
            ],
        }
        merged = merge_spdx(upstream, syft)
        license_ids = {e["licenseId"] for e in merged.get("hasExtractedLicensingInfos", [])}
        assert license_ids == {"LicenseRef-custom-1", "LicenseRef-custom-2"}

    def test_extracted_licensing_infos_deduped(self):
        upstream = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [],
            "hasExtractedLicensingInfos": [
                {"licenseId": "LicenseRef-shared", "extractedText": "upstream version"},
            ],
        }
        syft = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [],
            "hasExtractedLicensingInfos": [
                # Same licenseId — upstream wins, Syft entry is dropped.
                {"licenseId": "LicenseRef-shared", "extractedText": "syft version"},
                {"licenseId": "LicenseRef-syft-only", "extractedText": "syft-only"},
            ],
        }
        merged = merge_spdx(upstream, syft)
        entries = {e["licenseId"]: e["extractedText"] for e in merged["hasExtractedLicensingInfos"]}
        assert entries == {
            "LicenseRef-shared": "upstream version",
            "LicenseRef-syft-only": "syft-only",
        }

    def test_relationships_remapped(self):
        upstream = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [_spdx_pkg("SPDXRef-base", "base", "1", "pkg:deb/base@1")],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-base",
                }
            ],
        }
        syft = {
            "SPDXID": "SPDXRef-syft-doc",
            "packages": [_spdx_pkg("SPDXRef-extra", "extra", "1", "pkg:pypi/extra@1")],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-syft-doc",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-extra",
                }
            ],
        }
        merged = merge_spdx(upstream, syft)
        # The Syft DOCUMENT relationship should be remapped to upstream's DOCUMENT SPDXID.
        describes_upstream = any(
            r["spdxElementId"] == "SPDXRef-DOCUMENT" and r["relatedSpdxElement"] == "SPDXRef-extra"
            for r in merged["relationships"]
        )
        assert describes_upstream
        # Dedup: original upstream DESCRIBES of SPDXRef-base still present, only once.
        base_rel_count = sum(
            1
            for r in merged["relationships"]
            if r["relatedSpdxElement"] == "SPDXRef-base" and r["relationshipType"] == "DESCRIBES"
        )
        assert base_rel_count == 1
