"""Tests for the shared BuildKit / in-toto attestation helpers."""

import base64
import json
import subprocess
from unittest.mock import patch

import pytest

from sbomify_action._generation.buildkit_provenance import (
    SPDX_DOCUMENT,
    _classify_registry_error,
    extract_repo,
    fetch_build_provenance,
    fetch_buildkit_spdx_attestation,
    fetch_cosign_spdx_predicate,
    iter_resolved_dependencies,
    parse_docker_resolved_dependency,
    parse_purl_docker_uri,
    run_cosign,
    run_crane,
)

# --- Fixtures ---

MANIFEST_WITH_ATTESTATION = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:imagedigest",
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:attdigest",
                "annotations": {
                    "vnd.docker.reference.digest": "sha256:imagedigest",
                    "vnd.docker.reference.type": "attestation-manifest",
                },
                "platform": {"architecture": "unknown", "os": "unknown"},
            },
        ],
    }
)

ATTESTATION_MANIFEST_WITH_SPDX = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [
            {
                "mediaType": "application/vnd.in-toto+json",
                "digest": "sha256:spdxlayer",
                "annotations": {"in-toto.io/predicate-type": SPDX_DOCUMENT},
            },
            {
                "mediaType": "application/vnd.in-toto+json",
                "digest": "sha256:provlayer",
                "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"},
            },
        ],
    }
)

SPDX_STATEMENT = json.dumps(
    {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": SPDX_DOCUMENT,
        "predicate": {
            "spdxVersion": "SPDX-2.3",
            "packages": [{"name": "alpine", "SPDXID": "SPDXRef-alpine"}],
        },
    }
)


class TestExtractRepo:
    def test_simple_tag(self):
        assert extract_repo("nginx:latest") == "nginx"

    def test_registry_with_port(self):
        assert extract_repo("localhost:5000/repo/image:tag") == "localhost:5000/repo/image"

    def test_digest_ref(self):
        assert extract_repo("nginx@sha256:abc") == "nginx"

    def test_no_tag_or_digest(self):
        assert extract_repo("docker.io/library/python") == "docker.io/library/python"


class TestParsePurlDockerUri:
    def test_parses_digest_from_query(self):
        uri = "pkg:docker/library/python?digest=sha256:abc&platform=linux%2Famd64"
        assert parse_purl_docker_uri(uri) == ("library/python", "sha256:abc")

    def test_strips_tag_from_path(self):
        uri = "pkg:docker/library/python@3.11?digest=sha256:abc"
        assert parse_purl_docker_uri(uri) == ("library/python", "sha256:abc")

    def test_returns_none_without_digest(self):
        assert parse_purl_docker_uri("pkg:docker/library/python@3.11?platform=linux%2Famd64") is None

    def test_non_docker_purl(self):
        assert parse_purl_docker_uri("pkg:npm/vue@3.0.0") is None


class TestParseDockerResolvedDependency:
    def test_digest_from_uri_qualifier(self):
        dep = {
            "uri": "pkg:docker/library/python@3.11?digest=sha256:uri-digest&platform=linux%2Famd64",
            "digest": {"sha256": "field-digest"},
        }
        # URI qualifier wins when present.
        assert parse_docker_resolved_dependency(dep) == ("library/python", "sha256:uri-digest")

    def test_digest_from_sibling_field(self):
        """Docker Hub BuildKit provenance commonly puts the digest in the sibling field."""
        dep = {
            "uri": "pkg:docker/library/python@3.11?platform=linux%2Famd64",
            "digest": {"sha256": "field-digest"},
        }
        assert parse_docker_resolved_dependency(dep) == ("library/python", "sha256:field-digest")

    def test_dhi_ref_with_field_digest(self):
        dep = {
            "uri": "pkg:docker/dhi.io/python?platform=linux%2Famd64",
            "digest": {"sha256": "dhi-digest"},
        }
        assert parse_docker_resolved_dependency(dep) == ("dhi.io/python", "sha256:dhi-digest")

    def test_no_query_no_field(self):
        assert parse_docker_resolved_dependency({"uri": "pkg:docker/library/python"}) is None

    def test_non_docker_uri(self):
        assert parse_docker_resolved_dependency({"uri": "pkg:npm/left-pad@1.0.0"}) is None

    def test_missing_uri(self):
        assert parse_docker_resolved_dependency({}) is None


class TestIterResolvedDependencies:
    def test_yields_entries(self):
        statement = {
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {"uri": "pkg:docker/library/python"},
                        {"uri": "pkg:docker/library/nginx"},
                    ]
                }
            }
        }
        deps = list(iter_resolved_dependencies(statement))
        assert len(deps) == 2

    def test_empty_when_missing(self):
        assert list(iter_resolved_dependencies({})) == []


class TestFetchBuildkitAttestationStatement:
    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_fetches_spdx_layer(self, mock_crane):
        mock_crane.side_effect = [
            MANIFEST_WITH_ATTESTATION,
            ATTESTATION_MANIFEST_WITH_SPDX,
            SPDX_STATEMENT,
        ]

        predicate = fetch_buildkit_spdx_attestation("docker.io/library/python:3.11")
        assert predicate is not None
        assert predicate["spdxVersion"] == "SPDX-2.3"
        assert predicate["packages"][0]["name"] == "alpine"

    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_no_attestation_sibling(self, mock_crane):
        # Plain manifest list with no attestation-manifest sibling.
        mock_crane.side_effect = [
            json.dumps(
                {
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [
                        {
                            "digest": "sha256:x",
                            "platform": {"architecture": "amd64", "os": "linux"},
                        }
                    ],
                }
            )
        ]

        assert fetch_buildkit_spdx_attestation("docker.io/library/old:1.0") is None

    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_no_matching_predicate_layer(self, mock_crane):
        att_with_only_provenance = json.dumps(
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "layers": [
                    {
                        "digest": "sha256:provlayer",
                        "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"},
                    }
                ],
            }
        )
        mock_crane.side_effect = [MANIFEST_WITH_ATTESTATION, att_with_only_provenance]

        assert fetch_buildkit_spdx_attestation("docker.io/library/python:3.11") is None

    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_fetch_build_provenance_routes_to_provenance_predicate(self, mock_crane):
        provenance_statement = json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v0.1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {"buildDefinition": {"resolvedDependencies": []}},
            }
        )
        mock_crane.side_effect = [
            MANIFEST_WITH_ATTESTATION,
            ATTESTATION_MANIFEST_WITH_SPDX,
            provenance_statement,
        ]
        statement = fetch_build_provenance("user/image:v1")
        assert statement is not None
        assert statement["predicateType"] == "https://slsa.dev/provenance/v1"


class TestFetchCosignSpdxPredicate:
    @patch("sbomify_action._generation.buildkit_provenance.run_cosign")
    def test_extracts_spdx_predicate(self, mock_cosign):
        payload = {
            "predicateType": SPDX_DOCUMENT,
            "predicate": {"spdxVersion": "SPDX-2.3", "packages": []},
        }
        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(payload).encode()).decode(),
        }
        mock_cosign.return_value = json.dumps(envelope)

        predicate = fetch_cosign_spdx_predicate("dhi.io/python@sha256:abc")
        assert predicate is not None
        assert predicate["spdxVersion"] == "SPDX-2.3"

    @patch("sbomify_action._generation.buildkit_provenance.run_cosign")
    def test_skips_non_spdx_envelopes(self, mock_cosign):
        provenance_payload = {
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {},
        }
        envelope = {"payload": base64.b64encode(json.dumps(provenance_payload).encode()).decode()}
        mock_cosign.return_value = json.dumps(envelope)

        assert fetch_cosign_spdx_predicate("dhi.io/python@sha256:abc") is None

    @patch("sbomify_action._generation.buildkit_provenance.run_cosign")
    def test_extra_args_are_passed(self, mock_cosign):
        mock_cosign.return_value = ""
        fetch_cosign_spdx_predicate(
            "dhi.io/python@sha256:abc",
            extra_cosign_args=["--key", "https://example/key.pub", "--insecure-ignore-tlog=true"],
        )
        call_args = mock_cosign.call_args[0][0]
        assert "--key" in call_args
        assert "https://example/key.pub" in call_args
        assert "--insecure-ignore-tlog=true" in call_args


class TestClassifyRegistryError:
    def test_rate_limit_variants(self):
        for stderr in [
            "Error: TOOMANYREQUESTS: You have reached your unauthenticated pull rate limit.",
            "unexpected status: 429 Too Many Requests",
            "rate limit exceeded",
        ]:
            hint = _classify_registry_error(stderr)
            assert hint is not None
            assert "docker login" in hint.lower()
            assert "rate limit" in hint.lower()

    def test_unauthorized(self):
        stderr = "401 Unauthorized: authentication required"
        hint = _classify_registry_error(stderr)
        assert hint is not None
        assert "docker login" in hint.lower()

    def test_not_found(self):
        hint = _classify_registry_error("Error: manifest not found (404)")
        assert hint is not None
        assert "not found" in hint.lower()

    def test_unknown_error_returns_none(self):
        assert _classify_registry_error("some other transport failure") is None
        assert _classify_registry_error("") is None


class TestRunCraneSurfacesHints:
    @patch("sbomify_action._generation.buildkit_provenance.subprocess.run")
    def test_rate_limit_logged_at_warning(self, mock_run, caplog):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["crane", "manifest", "python:3.11"],
            returncode=1,
            stdout="",
            stderr="Error: TOOMANYREQUESTS: You have reached your unauthenticated pull rate limit.",
        )
        import logging

        with caplog.at_level(logging.WARNING, logger="sbomify_action"):
            with pytest.raises(subprocess.CalledProcessError):
                run_crane(["manifest", "python:3.11"])

        # At least one WARNING must mention rate limit + docker login.
        assert any(
            "rate limit" in rec.message.lower() and "docker login" in rec.message.lower() for rec in caplog.records
        )

    @patch("sbomify_action._generation.buildkit_provenance.subprocess.run")
    def test_success_passes_stdout(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["crane", "manifest", "python:3.11"],
            returncode=0,
            stdout='{"ok": true}',
            stderr="",
        )
        assert run_crane(["manifest", "python:3.11"]) == '{"ok": true}'

    @patch("sbomify_action._generation.buildkit_provenance.subprocess.run")
    def test_cosign_401_surfaces(self, mock_run, caplog):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["cosign", "download", "attestation", "dhi.io/python"],
            returncode=1,
            stdout="",
            stderr="GET https://dhi.io/token: 401 Unauthorized",
        )
        import logging

        with caplog.at_level(logging.WARNING, logger="sbomify_action"):
            with pytest.raises(subprocess.CalledProcessError):
                run_cosign(["download", "attestation", "dhi.io/python"])

        assert any("docker login" in rec.message.lower() and "401" in rec.message for rec in caplog.records)
