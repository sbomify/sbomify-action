"""Tests for Docker Hub base image detection and upstream SBOM fetch."""

import base64
import json
from unittest.mock import patch

from sbomify_action._generation.buildkit_provenance import SPDX_DOCUMENT
from sbomify_action._generation.dockerhub import (
    DockerHubBaseImage,
    _classify_ref,
    detect_dockerhub_image,
    fetch_dockerhub_sbom,
)

# --- Fixtures ---

MANIFEST_LIST_PLAIN = json.dumps(
    {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "digest": "sha256:amd64digest",
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
                "digest": "sha256:arm64digest",
                "platform": {"architecture": "arm64", "os": "linux"},
            },
        ],
    }
)

MANIFEST_LIST_WITH_ATTESTATION = json.dumps(
    {
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "digest": "sha256:imagedigest",
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
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
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [
            {
                "digest": "sha256:spdxlayer",
                "annotations": {"in-toto.io/predicate-type": SPDX_DOCUMENT},
            }
        ],
    }
)

PYTHON_SPDX_STATEMENT = json.dumps(
    {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": SPDX_DOCUMENT,
        "predicate": {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "debian-base", "SPDXID": "SPDXRef-base"},
                {"name": "libssl3", "SPDXID": "SPDXRef-libssl"},
            ],
        },
    }
)

PROVENANCE_WITH_DOCKERHUB_BASE = json.dumps(
    {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "resolvedDependencies": [
                    {
                        "uri": "pkg:docker/library/python@3.11?platform=linux%2Famd64",
                        "digest": {"sha256": "pythondigest"},
                    }
                ]
            }
        },
    }
)

PROVENANCE_WITH_DHI_BASE = json.dumps(
    {
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "resolvedDependencies": [
                    {
                        "uri": "pkg:docker/dhi.io/python@latest?platform=linux%2Famd64",
                        "digest": {"sha256": "dhidigest"},
                    }
                ]
            }
        },
    }
)

PROVENANCE_WITH_CUSTOM_BASE = json.dumps(
    {
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "resolvedDependencies": [
                    {
                        "uri": "pkg:docker/ghcr.io/user/custom@v1?platform=linux%2Famd64",
                        "digest": {"sha256": "customdigest"},
                    }
                ]
            }
        },
    }
)


# --- Classification ---


class TestClassifyRef:
    def test_bare_name(self):
        assert _classify_ref("python") == "official"
        assert _classify_ref("python:3.11") == "official"

    def test_library_shorthand(self):
        assert _classify_ref("library/nginx") == "official"
        assert _classify_ref("library/nginx:alpine") == "official"

    def test_full_docker_io_library(self):
        assert _classify_ref("docker.io/library/redis") == "official"
        assert _classify_ref("docker.io/library/redis:7") == "official"
        assert _classify_ref("index.docker.io/library/redis") == "official"

    def test_dhi(self):
        assert _classify_ref("dhi.io/python") == "dhi"
        assert _classify_ref("dhi.io/python:3.11") == "dhi"

    def test_docker_io_user_repo_not_official(self):
        assert _classify_ref("docker.io/myuser/myapp") is None

    def test_implicit_user_repo_not_official(self):
        # two-part shorthand without "library/" prefix → user/repo on Docker Hub
        assert _classify_ref("myuser/myapp") is None

    def test_other_registries(self):
        assert _classify_ref("ghcr.io/foo/bar") is None
        assert _classify_ref("gcr.io/proj/img") is None
        assert _classify_ref("quay.io/org/img") is None
        assert _classify_ref("localhost:5000/foo/bar") is None


# --- Direct detection ---


class TestDetectDirect:
    @patch("sbomify_action._generation.buildkit_provenance.shutil.which", return_value="/usr/bin/crane")
    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_library_shorthand(self, mock_crane, mock_which):
        mock_crane.side_effect = [MANIFEST_LIST_PLAIN]

        result = detect_dockerhub_image("library/python:3.11")
        assert result is not None
        assert result.tier == "official"
        assert result.image_ref == "docker.io/library/python"
        assert result.digest.startswith("sha256:")

    @patch("sbomify_action._generation.buildkit_provenance.shutil.which", return_value="/usr/bin/crane")
    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_bare_name(self, mock_crane, mock_which):
        mock_crane.side_effect = [MANIFEST_LIST_PLAIN]

        result = detect_dockerhub_image("python:3.11")
        assert result is not None
        assert result.tier == "official"
        assert result.image_ref == "docker.io/library/python"

    @patch("sbomify_action._generation.buildkit_provenance.shutil.which", return_value="/usr/bin/crane")
    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_dhi(self, mock_crane, mock_which):
        mock_crane.side_effect = [MANIFEST_LIST_PLAIN]

        result = detect_dockerhub_image("dhi.io/python:latest")
        assert result is not None
        assert result.tier == "dhi"
        assert result.image_ref == "dhi.io/python"

    @patch("sbomify_action._generation.buildkit_provenance.shutil.which", return_value="/usr/bin/crane")
    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_other_registry_returns_none(self, mock_crane, mock_which):
        # Provenance path will also be attempted — give it an empty manifest.
        mock_crane.side_effect = [
            json.dumps({"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []}),
        ]
        result = detect_dockerhub_image("ghcr.io/foo/bar:latest")
        assert result is None

    @patch("sbomify_action._generation.buildkit_provenance.shutil.which", return_value=None)
    def test_crane_not_available(self, mock_which):
        result = detect_dockerhub_image("python:3.11")
        assert result is None


# --- Provenance detection ---


class TestDetectFromProvenance:
    @patch("sbomify_action._generation.buildkit_provenance.shutil.which", return_value="/usr/bin/crane")
    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_detects_library_base(self, mock_crane, mock_which):
        python_manifest_list = json.dumps(
            {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "digest": "sha256:pythonamd64",
                        "platform": {"architecture": "amd64", "os": "linux"},
                    },
                    {
                        "digest": "sha256:pythonarm64",
                        "platform": {"architecture": "arm64", "os": "linux"},
                    },
                ],
            }
        )
        mock_crane.side_effect = [
            # 1. Direct detection path: user's image is ghcr.io/... (not a hub image),
            # _classify_ref returns None → _detect_direct returns None without calling crane.
            # 2. Provenance path: image index w/ attestation
            MANIFEST_LIST_WITH_ATTESTATION,
            # 3. attestation manifest — contains provenance layer too (not just SPDX)
            json.dumps(
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "layers": [
                        {
                            "digest": "sha256:provlayer",
                            "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"},
                        }
                    ],
                }
            ),
            # 4. provenance blob
            PROVENANCE_WITH_DOCKERHUB_BASE,
            # 5. resolve_platform_digest for the found base
            python_manifest_list,
        ]

        result = detect_dockerhub_image("ghcr.io/myorg/myapp:v1")
        assert result is not None
        assert result.tier == "official"
        assert result.image_ref == "docker.io/library/python"

    @patch("sbomify_action._generation.buildkit_provenance.shutil.which", return_value="/usr/bin/crane")
    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_detects_dhi_base(self, mock_crane, mock_which):
        dhi_manifest_list = json.dumps(
            {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "digest": "sha256:dhiamd64",
                        "platform": {"architecture": "amd64", "os": "linux"},
                    },
                    {
                        "digest": "sha256:dhiarm64",
                        "platform": {"architecture": "arm64", "os": "linux"},
                    },
                ],
            }
        )
        mock_crane.side_effect = [
            MANIFEST_LIST_WITH_ATTESTATION,
            json.dumps(
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "layers": [
                        {
                            "digest": "sha256:provlayer",
                            "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"},
                        }
                    ],
                }
            ),
            PROVENANCE_WITH_DHI_BASE,
            dhi_manifest_list,
        ]

        result = detect_dockerhub_image("ghcr.io/myorg/app:v1")
        assert result is not None
        assert result.tier == "dhi"
        assert result.image_ref == "dhi.io/python"

    @patch("sbomify_action._generation.buildkit_provenance.shutil.which", return_value="/usr/bin/crane")
    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_ignores_non_dockerhub_base(self, mock_crane, mock_which):
        mock_crane.side_effect = [
            MANIFEST_LIST_WITH_ATTESTATION,
            json.dumps(
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "layers": [
                        {
                            "digest": "sha256:provlayer",
                            "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"},
                        }
                    ],
                }
            ),
            PROVENANCE_WITH_CUSTOM_BASE,
        ]

        result = detect_dockerhub_image("ghcr.io/myorg/app:v1")
        assert result is None


# --- SBOM fetch ---


class TestFetchDockerhubSbom:
    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_official_fetches_via_crane(self, mock_crane):
        mock_crane.side_effect = [
            MANIFEST_LIST_WITH_ATTESTATION,
            ATTESTATION_MANIFEST_WITH_SPDX,
            PYTHON_SPDX_STATEMENT,
        ]
        info = DockerHubBaseImage(
            image_ref="docker.io/library/python",
            index_ref="docker.io/library/python:3.11",
            digest="sha256:imagedigest",
            tier="official",
        )
        result = fetch_dockerhub_sbom(info)
        assert result is not None
        assert result["spdxVersion"] == "SPDX-2.3"
        assert len(result["packages"]) == 2

    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_official_multi_arch_picks_matching_sibling(self, mock_crane):
        """Multi-arch indexes have one attestation-manifest per platform.
        Must pick the sibling whose vnd.docker.reference.digest equals our
        platform digest — otherwise we'd fetch another platform's SBOM."""
        multi_arch_index = json.dumps(
            {
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "digest": "sha256:amd64image",
                        "platform": {"architecture": "amd64", "os": "linux"},
                    },
                    {
                        "digest": "sha256:amd64att",
                        "annotations": {
                            "vnd.docker.reference.digest": "sha256:amd64image",
                            "vnd.docker.reference.type": "attestation-manifest",
                        },
                        "platform": {"architecture": "unknown", "os": "unknown"},
                    },
                    {
                        "digest": "sha256:arm64image",
                        "platform": {"architecture": "arm64", "os": "linux"},
                    },
                    {
                        "digest": "sha256:arm64att",
                        "annotations": {
                            "vnd.docker.reference.digest": "sha256:arm64image",
                            "vnd.docker.reference.type": "attestation-manifest",
                        },
                        "platform": {"architecture": "unknown", "os": "unknown"},
                    },
                ],
            }
        )
        arm64_att_manifest = json.dumps(
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "layers": [
                    {
                        "digest": "sha256:arm64spdx",
                        "annotations": {"in-toto.io/predicate-type": SPDX_DOCUMENT},
                    }
                ],
            }
        )
        arm64_spdx = json.dumps(
            {
                "predicateType": SPDX_DOCUMENT,
                "predicate": {
                    "spdxVersion": "SPDX-2.3",
                    "packages": [{"name": "arm64-pkg"}],
                },
            }
        )
        mock_crane.side_effect = [multi_arch_index, arm64_att_manifest, arm64_spdx]

        info = DockerHubBaseImage(
            image_ref="docker.io/library/python",
            index_ref="docker.io/library/python:3.11",
            digest="sha256:arm64image",
            tier="official",
        )
        result = fetch_dockerhub_sbom(info)
        assert result is not None
        assert result["packages"][0]["name"] == "arm64-pkg"

        # Second crane call should have fetched the arm64 attestation manifest.
        second_call_args = mock_crane.call_args_list[1][0][0]
        assert second_call_args[1].endswith("@sha256:arm64att")

    @patch("sbomify_action._generation.buildkit_provenance.run_crane")
    def test_official_no_attestation_returns_none(self, mock_crane):
        """Some older Official Images don't ship SBOM attestations."""
        mock_crane.side_effect = [
            json.dumps(
                {
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [
                        {
                            "digest": "sha256:only",
                            "platform": {"architecture": "amd64", "os": "linux"},
                        }
                    ],
                }
            )
        ]
        info = DockerHubBaseImage(
            image_ref="docker.io/library/old",
            index_ref="docker.io/library/old:1.0",
            digest="sha256:only",
            tier="official",
        )
        assert fetch_dockerhub_sbom(info) is None

    @patch("sbomify_action._generation.buildkit_provenance.shutil.which", return_value="/usr/bin/cosign")
    @patch("sbomify_action._generation.buildkit_provenance.run_cosign")
    def test_dhi_fetches_via_cosign_with_key_and_tlog_flags(self, mock_cosign, mock_which):
        payload = {
            "predicateType": SPDX_DOCUMENT,
            "predicate": {"spdxVersion": "SPDX-2.3", "packages": [{"name": "dhi-pkg"}]},
        }
        envelope = {"payload": base64.b64encode(json.dumps(payload).encode()).decode()}
        mock_cosign.return_value = json.dumps(envelope)

        info = DockerHubBaseImage(
            image_ref="dhi.io/python",
            index_ref="dhi.io/python:latest",
            digest="sha256:dhidigest",
            tier="dhi",
        )
        result = fetch_dockerhub_sbom(info)
        assert result is not None
        assert result["spdxVersion"] == "SPDX-2.3"

        # Verify the DHI-specific flags were passed through.
        call_args = mock_cosign.call_args[0][0]
        assert "--key" in call_args
        assert "--insecure-ignore-tlog=true" in call_args

    @patch("sbomify_action._generation.buildkit_provenance.shutil.which", return_value="/usr/bin/cosign")
    @patch("sbomify_action._generation.buildkit_provenance.run_cosign")
    def test_dhi_uses_verify_attestation_not_download(self, mock_cosign, mock_which):
        """Regression guard: DHI must invoke `cosign verify-attestation` so
        Docker's signature is actually checked. Downgrading to `download
        attestation` would silently accept tampered SBOMs."""
        payload = {
            "predicateType": SPDX_DOCUMENT,
            "predicate": {"spdxVersion": "SPDX-2.3", "packages": []},
        }
        envelope = {"payload": base64.b64encode(json.dumps(payload).encode()).decode()}
        mock_cosign.return_value = json.dumps(envelope)

        info = DockerHubBaseImage(
            image_ref="dhi.io/python",
            index_ref="dhi.io/python:latest",
            digest="sha256:dhidigest",
            tier="dhi",
        )
        fetch_dockerhub_sbom(info)

        call_args = mock_cosign.call_args[0][0]
        assert call_args[0] == "verify-attestation"
        # --type spdxjson so cosign filters for SPDX-shaped attestations.
        assert "--type" in call_args
        assert "spdxjson" in call_args
        assert "download" not in call_args

    @patch("sbomify_action._generation.buildkit_provenance.shutil.which", return_value=None)
    def test_dhi_without_cosign_returns_none(self, mock_which):
        info = DockerHubBaseImage(
            image_ref="dhi.io/python",
            index_ref="dhi.io/python:latest",
            digest="sha256:dhidigest",
            tier="dhi",
        )
        assert fetch_dockerhub_sbom(info) is None
