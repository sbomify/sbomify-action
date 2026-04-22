"""Tests for Chainguard base image detection and SBOM reuse."""

import base64
import json
from unittest.mock import patch

import pytest

from sbomify_action._generation.chainguard import (
    ChainguardBaseImage,
    _parse_purl_docker_uri,
    convert_spdx_to_cyclonedx,
    detect_chainguard_image,
    fetch_chainguard_sbom,
)

# --- Fixtures ---


CHAINGUARD_CONFIG = json.dumps(
    {
        "author": "github.com/chainguard-dev/apko",
        "config": {
            "Labels": {
                "dev.chainguard.image.title": "python",
                "org.opencontainers.image.authors": "Chainguard Team https://www.chainguard.dev/",
            }
        },
    }
)

NON_CHAINGUARD_CONFIG = json.dumps(
    {
        "author": "docker.io",
        "config": {"Labels": {"maintainer": "NGINX Docker Maintainers"}},
    }
)

MANIFEST_LIST = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:amd64digest000000000000000000000000000000000000000000000000000000",
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:arm64digest000000000000000000000000000000000000000000000000000000",
                "platform": {"architecture": "arm64", "os": "linux"},
            },
        ],
    }
)

MANIFEST_WITH_ATTESTATION = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:imagedigest0000000000000000000000000000000000000000000000000000",
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:attdigest00000000000000000000000000000000000000000000000000000000",
                "annotations": {
                    "vnd.docker.reference.digest": "sha256:imagedigest0000000000000000000000000000000000000000000000000000",
                    "vnd.docker.reference.type": "attestation-manifest",
                },
                "platform": {"architecture": "unknown", "os": "unknown"},
            },
        ],
    }
)

ATTESTATION_MANIFEST = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [
            {
                "mediaType": "application/vnd.in-toto+json",
                "digest": "sha256:provdigest00000000000000000000000000000000000000000000000000000",
                "annotations": {
                    "in-toto.io/predicate-type": "https://slsa.dev/provenance/v1",
                },
            }
        ],
    }
)

PROVENANCE_WITH_CHAINGUARD = json.dumps(
    {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "resolvedDependencies": [
                    {
                        "uri": "pkg:docker/cgr.dev/chainguard/python?digest=sha256:chainguarddigest000000000000000000000000000000000000000000000000&platform=linux%2Famd64",
                        "digest": {"sha256": "chainguarddigest000000000000000000000000000000000000000000000000"},
                    },
                    {
                        "uri": "pkg:docker/alpine@3.21?platform=linux%2Famd64",
                        "digest": {"sha256": "alpinedigest0000000000000000000000000000000000000000000000000000"},
                    },
                ]
            }
        },
    }
)

PROVENANCE_WITHOUT_CHAINGUARD = json.dumps(
    {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "resolvedDependencies": [
                    {
                        "uri": "pkg:docker/python@3.13-slim?platform=linux%2Famd64",
                        "digest": {"sha256": "pythondigest000000000000000000000000000000000000000000000000000"},
                    },
                ]
            }
        },
    }
)

SAMPLE_SPDX_SBOM = {
    "SPDXID": "SPDXRef-DOCUMENT",
    "spdxVersion": "SPDX-2.3",
    "creationInfo": {
        "created": "2026-03-24T21:51:39Z",
        "creators": ["Tool: apko (v1.1.14)", "Organization: Chainguard, Inc"],
        "licenseListVersion": "3.27",
    },
    "dataLicense": "CC0-1.0",
    "documentDescribes": ["SPDXRef-Package-image"],
    "documentNamespace": "https://spdx.org/spdxdocs/apko/",
    "name": "sbom-chainguard-python",
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-image",
            "name": "sha256:abc123",
            "versionInfo": "sha256:abc123",
            "description": "Multi-arch image index",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceLocator": "pkg:oci/index@sha256:abc123?mediaType=application%2Fvnd.oci.image.index.v1%2Bjson",
                    "referenceType": "purl",
                }
            ],
            "filesAnalyzed": False,
            "primaryPackagePurpose": "CONTAINER",
            "supplier": "Organization: Chainguard, Inc.",
        },
        {
            "SPDXID": "SPDXRef-Package-glibc",
            "name": "glibc",
            "versionInfo": "2.43-r3",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceLocator": "pkg:apk/wolfi/glibc@2.43-r3?arch=x86_64&distro=wolfi",
                    "referenceType": "purl",
                }
            ],
            "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": "deadbeef" * 8}],
            "supplier": "Organization: Wolfi",
        },
        {
            "SPDXID": "SPDXRef-Package-libssl3",
            "name": "libssl3",
            "versionInfo": "3.6.1-r4",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceLocator": "pkg:apk/wolfi/libssl3@3.6.1-r4?arch=x86_64&distro=wolfi",
                    "referenceType": "purl",
                }
            ],
            "filesAnalyzed": False,
            "supplier": "Organization: Wolfi",
        },
    ],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": "SPDXRef-Package-image",
            "relationshipType": "DESCRIBES",
        },
    ],
}


def _make_cosign_attestation_output(spdx_doc: dict) -> str:
    """Build cosign download attestation output for a given SPDX doc."""
    payload = {
        "predicateType": "https://spdx.dev/Document",
        "predicate": spdx_doc,
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    envelope = {"payloadType": "application/vnd.in-toto+json", "payload": encoded}
    return json.dumps(envelope)


# --- Tests ---


class TestParseDockerPurl:
    def test_chainguard_purl(self):
        uri = "pkg:docker/cgr.dev/chainguard/python?digest=sha256:abc123&platform=linux%2Famd64"
        result = _parse_purl_docker_uri(uri)
        assert result == ("cgr.dev/chainguard/python", "sha256:abc123")

    def test_purl_with_tag(self):
        uri = "pkg:docker/alpine@3.21?platform=linux%2Famd64"
        result = _parse_purl_docker_uri(uri)
        assert result is None  # No digest

    def test_purl_with_tag_and_digest(self):
        uri = "pkg:docker/oven/bun@1.3-debian?digest=sha256:abc123&platform=linux%2Famd64"
        result = _parse_purl_docker_uri(uri)
        assert result == ("oven/bun", "sha256:abc123")

    def test_non_docker_purl(self):
        assert _parse_purl_docker_uri("pkg:npm/vue@3.0.0") is None

    def test_no_query(self):
        assert _parse_purl_docker_uri("pkg:docker/nginx") is None


class TestDetectDirectChainguard:
    @patch("sbomify_action._generation.chainguard.shutil.which", return_value="/usr/local/bin/crane")
    @patch("sbomify_action._generation.chainguard._run_crane")
    def test_direct_chainguard_image(self, mock_crane, mock_which):
        mock_crane.side_effect = [
            # 1. _is_chainguard_config: crane config
            CHAINGUARD_CONFIG,
            # 2. _resolve_platform_digest: crane manifest (manifest list)
            MANIFEST_LIST,
        ]

        result = detect_chainguard_image("cgr.dev/chainguard/python:latest")
        assert result is not None
        assert result.image_ref == "cgr.dev/chainguard/python"
        # Digest depends on current platform (amd64 or arm64)
        assert result.digest.startswith("sha256:")

    @patch("sbomify_action._generation.chainguard.shutil.which", return_value="/usr/local/bin/crane")
    @patch("sbomify_action._generation.chainguard._run_crane")
    def test_non_chainguard_returns_none(self, mock_crane, mock_which):
        # Not cgr.dev prefix, so tries provenance path
        # crane manifest for provenance detection — return simple manifest (no attestation)
        simple_manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": "sha256:abc123",
                        "platform": {"architecture": "amd64", "os": "linux"},
                    },
                ],
            }
        )
        mock_crane.side_effect = [simple_manifest]

        result = detect_chainguard_image("nginx:latest")
        assert result is None

    @patch("sbomify_action._generation.chainguard.shutil.which", return_value=None)
    def test_crane_not_available(self, mock_which):
        result = detect_chainguard_image("cgr.dev/chainguard/python:latest")
        assert result is None


class TestDetectFromProvenance:
    @patch("sbomify_action._generation.chainguard.shutil.which", return_value="/usr/local/bin/crane")
    @patch("sbomify_action._generation.chainguard._run_crane")
    def test_detects_chainguard_base_in_provenance(self, mock_crane, mock_which):
        # Resolve platform digest for the found Chainguard image
        chainguard_manifest_list = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": "sha256:platformdigest0000000000000000000000000000000000000000000000000",
                        "platform": {"architecture": "amd64", "os": "linux"},
                    },
                ],
            }
        )

        mock_crane.side_effect = [
            # detect_chainguard_image -> _detect_chainguard_from_provenance:
            # 1. crane manifest (image index with attestation)
            MANIFEST_WITH_ATTESTATION,
            # 2. crane manifest (attestation manifest)
            ATTESTATION_MANIFEST,
            # 3. crane blob (provenance)
            PROVENANCE_WITH_CHAINGUARD,
            # 4. _resolve_platform_digest: crane manifest for the Chainguard image
            chainguard_manifest_list,
        ]

        result = detect_chainguard_image("sbomifyhub/sbomify:latest")
        assert result is not None
        assert result.image_ref == "cgr.dev/chainguard/python"
        assert result.digest.startswith("sha256:")

    @patch("sbomify_action._generation.chainguard.shutil.which", return_value="/usr/local/bin/crane")
    @patch("sbomify_action._generation.chainguard._run_crane")
    def test_no_chainguard_in_provenance(self, mock_crane, mock_which):
        mock_crane.side_effect = [
            MANIFEST_WITH_ATTESTATION,
            ATTESTATION_MANIFEST,
            PROVENANCE_WITHOUT_CHAINGUARD,
        ]

        result = detect_chainguard_image("myapp:latest")
        assert result is None

    @patch("sbomify_action._generation.chainguard.shutil.which", return_value="/usr/local/bin/crane")
    @patch("sbomify_action._generation.chainguard._run_crane")
    def test_no_attestation_manifest(self, mock_crane, mock_which):
        # Image index without attestation manifest
        simple_manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": "sha256:abc123",
                        "platform": {"architecture": "amd64", "os": "linux"},
                    },
                ],
            }
        )
        mock_crane.side_effect = [simple_manifest]

        result = detect_chainguard_image("oldimage:latest")
        assert result is None


class TestFetchChainguardSbom:
    @patch("sbomify_action._generation.chainguard.shutil.which", return_value="/usr/local/bin/cosign")
    @patch("sbomify_action._generation.chainguard._run_cosign")
    def test_fetches_spdx_sbom(self, mock_cosign, mock_which):
        cosign_output = _make_cosign_attestation_output(SAMPLE_SPDX_SBOM)
        mock_cosign.return_value = cosign_output

        info = ChainguardBaseImage(
            image_ref="cgr.dev/chainguard/python",
            digest="sha256:abc123",
        )
        result = fetch_chainguard_sbom(info)

        assert result["spdxVersion"] == "SPDX-2.3"
        assert len(result["packages"]) == 3

    @patch("sbomify_action._generation.chainguard.shutil.which", return_value="/usr/local/bin/cosign")
    @patch("sbomify_action._generation.chainguard._run_cosign")
    def test_no_spdx_attestation_raises(self, mock_cosign, mock_which):
        # Return a non-SPDX attestation
        payload = {"predicateType": "https://slsa.dev/provenance/v1", "predicate": {}}
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        envelope = {"payload": encoded}
        mock_cosign.return_value = json.dumps(envelope)

        info = ChainguardBaseImage(image_ref="cgr.dev/chainguard/python", digest="sha256:abc")

        with pytest.raises(RuntimeError, match="No SPDX SBOM found"):
            fetch_chainguard_sbom(info)

    @patch("sbomify_action._generation.chainguard.shutil.which", return_value=None)
    def test_cosign_not_available_raises(self, mock_which):
        info = ChainguardBaseImage(image_ref="cgr.dev/chainguard/python", digest="sha256:abc")
        with pytest.raises(RuntimeError, match="cosign not found"):
            fetch_chainguard_sbom(info)


class TestConvertSpdxToCyclonedx:
    def test_converts_basic_sbom(self):
        result = convert_spdx_to_cyclonedx(SAMPLE_SPDX_SBOM, "1.6")

        # Parse the result as JSON
        cdx = json.loads(result)
        assert cdx["bomFormat"] == "CycloneDX"
        assert cdx["specVersion"] == "1.6"

        # Should have components (glibc, libssl3 — image is metadata.component)
        assert len(cdx.get("components", [])) == 2

        # Check metadata.component is the described package
        meta_comp = cdx.get("metadata", {}).get("component", {})
        assert meta_comp.get("type") == "container"

        # Check a component has the correct PURL
        component_names = {c["name"] for c in cdx["components"]}
        assert "glibc" in component_names
        assert "libssl3" in component_names

        # Check purl is set
        for comp in cdx["components"]:
            if comp["name"] == "glibc":
                assert "pkg:apk/wolfi/glibc" in comp.get("purl", "")
                assert comp["version"] == "2.43-r3"

    def test_converts_with_supplier(self):
        result = convert_spdx_to_cyclonedx(SAMPLE_SPDX_SBOM, "1.6")
        cdx = json.loads(result)

        for comp in cdx["components"]:
            if comp["name"] == "glibc":
                supplier = comp.get("supplier", {})
                assert supplier.get("name") == "Wolfi"

    def test_converts_with_hashes(self):
        result = convert_spdx_to_cyclonedx(SAMPLE_SPDX_SBOM, "1.6")
        cdx = json.loads(result)

        for comp in cdx["components"]:
            if comp["name"] == "glibc":
                assert len(comp.get("hashes", [])) > 0
                assert comp["hashes"][0]["alg"] == "SHA-256"

    def test_converts_with_creation_info(self):
        result = convert_spdx_to_cyclonedx(SAMPLE_SPDX_SBOM, "1.6")
        cdx = json.loads(result)

        metadata = cdx.get("metadata", {})
        assert "timestamp" in metadata

    def test_spec_version_1_5(self):
        result = convert_spdx_to_cyclonedx(SAMPLE_SPDX_SBOM, "1.5")
        cdx = json.loads(result)
        assert cdx["specVersion"] == "1.5"

    def test_empty_packages(self):
        empty_sbom = {
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": []},
            "packages": [],
            "documentDescribes": [],
        }
        result = convert_spdx_to_cyclonedx(empty_sbom, "1.6")
        cdx = json.loads(result)
        assert cdx["bomFormat"] == "CycloneDX"
        assert len(cdx.get("components", [])) == 0
