"""Scheme-prefixed image references, and telling a missing daemon from a missing image.

`syft scan` accepts a source scheme in front of a reference --
`docker-archive:/tmp/image.tar` is how you scan an image without a daemon at
all. sbomify passes DOCKER_IMAGE through verbatim, so that syntax already
works today; these tests pin the two things around it that did not.
"""

import pytest

from sbomify_action._generation.generators.cdxgen import CdxgenImageGenerator
from sbomify_action._generation.generators.trivy import TrivyImageGenerator
from sbomify_action._generation.protocol import GenerationInput
from sbomify_action._generation.utils import (
    detect_docker_daemon_unreachable,
    image_ref_scheme,
)


class TestImageRefScheme:
    """A scheme is a fixed vocabulary, not "whatever precedes a colon"."""

    @pytest.mark.parametrize(
        "reference,expected",
        [
            ("docker-archive:/tmp/image.tar", "docker-archive"),
            ("oci-archive:/tmp/image.tar", "oci-archive"),
            ("oci-dir:/tmp/ocidir", "oci-dir"),
            ("registry:ghcr.io/acme/app:1.0", "registry"),
            ("docker:alpine:3.20", "docker"),
            ("podman:alpine:3.20", "podman"),
            ("dir:/src", "dir"),
        ],
    )
    def test_recognises_syft_schemes(self, reference: str, expected: str):
        assert image_ref_scheme(reference) == expected

    @pytest.mark.parametrize(
        "reference",
        [
            "alpine:3.20",
            "ghcr.io/sbomify/sbomify-action:26.8.0",
            # A registry host with a port is the case a naive split-on-colon
            # gets wrong, and it is a completely ordinary reference.
            "localhost:5000/app:latest",
            "my-app@sha256:0123456789abcdef",
            "my-app",
            "",
        ],
    )
    def test_plain_references_have_no_scheme(self, reference: str):
        assert image_ref_scheme(reference) is None

    def test_none_is_tolerated(self):
        assert image_ref_scheme(None) is None


class TestGeneratorsDeclinePrefixedRefs:
    """Only syft speaks this syntax, so the others must stand down.

    trivy reads an archive through `--input <path>` and cdxgen through a bare
    path; handed a prefixed value each looks for an image literally named
    "docker-archive:/tmp/image.tar". Claiming the input and then failing is
    fatal in our own container, so declining is what lets syft take it.
    """

    @pytest.mark.parametrize("generator", [TrivyImageGenerator(), CdxgenImageGenerator()])
    def test_declines_scheme_prefixed_reference(self, generator):
        input = GenerationInput(
            docker_image="docker-archive:/tmp/image.tar",
            output_file="out.json",
            output_format="cyclonedx",
        )
        assert generator.supports(input) is False

    @pytest.mark.parametrize("generator", [TrivyImageGenerator(), CdxgenImageGenerator()])
    def test_plain_reference_is_not_declined_for_this_reason(self, generator):
        """A tagged reference must not be mistaken for a scheme.

        Asserts the scheme check specifically, rather than `supports() is
        True`: whether the generator claims a plain reference also depends on
        the tool being installed, which is not what this test is about.
        """
        input = GenerationInput(
            docker_image="alpine:3.20",
            output_file="out.json",
            output_format="cyclonedx",
        )
        assert image_ref_scheme(input.docker_image) is None


class TestDaemonUnreachableDetection:
    """A missing daemon and a missing image are different failures.

    syft falls through to the registry when it cannot reach the socket, so the
    error the user sees is about registry credentials. Without this the run is
    reported as an authentication problem and the socket is never suspected.
    """

    @pytest.mark.parametrize(
        "output",
        [
            "failed to connect to Docker daemon. Ensure Docker is running and accessible",
            "docker: docker not available: failed to connect to Docker daemon",
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
            "dial unix /var/run/docker.sock: connect: permission denied",
            "permission denied while trying to connect to the Docker daemon socket",
        ],
    )
    def test_detects_unreachable_daemon(self, output: str):
        assert detect_docker_daemon_unreachable(output) is True

    @pytest.mark.parametrize(
        "output",
        [
            "MANIFEST_UNKNOWN: manifest unknown",
            "manifest for alpine:nonexistent not found",
            "pull access denied",
            "some other error",
            "",
        ],
    )
    def test_does_not_fire_on_other_failures(self, output: str):
        assert detect_docker_daemon_unreachable(output) is False
