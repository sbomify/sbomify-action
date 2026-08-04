"""The intended generator must win for each ecosystem.

The design is a slim core image that pulls in what an ecosystem needs so the
SBOM is the best available for it -- not merely that some SBOM appears. The
fallback chain quietly undermines that: when the intended generator declines
or fails, a lower-priority one produces output that looks like success.

Three defects lived that way until strict mode surfaced them, and all three
were invisible because syft covered for the tool that should have run. These
tests assert the routing directly, against fixtures that look like real
projects -- manifest as well as lock file -- so a regression fails here
rather than silently degrading someone's SBOM.

Routing only: no generator is executed, so this stays fast and needs no
network. scripts/ecosystem_matrix.py runs the real thing and checks output
quality.
"""

from pathlib import Path

import pytest

from sbomify_action._generation.generator import create_default_registry
from sbomify_action._generation.protocol import GenerationInput

PROJECTS = Path(__file__).parent / "test-data" / "projects"

#: (fixture directory, lock file, generator that must produce the SBOM).
#:
#: cyclonedx-py and cyclonedx-cargo are native and outrank cdxgen; cdxgen
#: outranks syft everywhere it applies. uv.lock is cdxgen's because
#: cyclonedx-py explicitly does not support it.
INTENDED = [
    ("python-requirements", "requirements.txt", "cyclonedx-py"),
    ("python-pipenv", "Pipfile.lock", "cyclonedx-py"),
    ("python-uv", "uv.lock", "cdxgen-fs"),
    ("rust", "Cargo.lock", "cyclonedx-cargo"),
    ("javascript", "package-lock.json", "cdxgen-fs"),
    # The JVM goes to its own build systems' plugins, not to cdxgen. Measured
    # on whole real projects: 106 components for spring-petclinic and 340 for
    # Keycloak against syft's 42 and 92, with cdxgen failing outright on both.
    ("java", "pom.xml", "cyclonedx-maven"),
    ("java-gradle", "build.gradle", "cyclonedx-gradle"),
    ("scala", "build.sbt", "cyclonedx-sbt"),
    ("go", "go.mod", "cyclonedx-gomod"),
    ("ruby", "Gemfile.lock", "cdxgen-fs"),
    ("dart", "pubspec.lock", "cdxgen-fs"),
    ("elixir", "mix.lock", "cdxgen-fs"),
    ("cpp", "conan.lock", "cdxgen-fs"),
]


@pytest.mark.parametrize(("project", "lock_file", "expected"), INTENDED)
def test_intended_generator_is_first_in_the_chain(project, lock_file, expected, monkeypatch):
    """The best tool for the ecosystem must be the one that gets asked first."""
    # Availability is probed at import time against PATH, which a developer
    # machine will not have. Routing is what is under test, not installation.
    for module, flag in (
        ("cyclonedx_py", "_CYCLONEDX_PY_AVAILABLE"),
        ("cyclonedx_cargo", "_CARGO_CYCLONEDX_AVAILABLE"),
        ("cdxgen", "_CDXGEN_AVAILABLE"),
        ("syft", "_SYFT_AVAILABLE"),
    ):
        monkeypatch.setattr(f"sbomify_action._generation.generators.{module}.{flag}", True)
    # cyclonedx-gomod is fetched rather than probed, and gates on being in
    # our own image.
    monkeypatch.setenv("SBOMIFY_FETCH_RUNTIMES", "1")

    lock = PROJECTS / project / lock_file
    assert lock.exists(), f"fixture missing: {lock}"

    generators = create_default_registry().get_generators_for(
        GenerationInput(lock_file=str(lock), output_format="cyclonedx")
    )

    assert generators, f"{project}: nothing claims {lock_file}"
    assert generators[0].name == expected, (
        f"{project}: expected {expected} to run first, got "
        f"{[g.name for g in generators]} -- a lower-priority generator taking over "
        f"produces a worse SBOM while still looking like success"
    )


@pytest.mark.parametrize(("project", "lock_file", "_expected"), INTENDED)
def test_every_fixture_carries_its_manifest(project, lock_file, _expected):
    """A lock file without its manifest exercises the fallback, not the design.

    That is exactly how the bare fixtures in the parent directory hid three
    defects, so the projects here must not repeat it.
    """
    from sbomify_action._generation.utils import LOCK_FILE_MANIFESTS, has_required_manifest

    lock = PROJECTS / project / lock_file
    required = LOCK_FILE_MANIFESTS.get(lock_file)
    if required:
        assert (lock.parent / required).exists(), (
            f"{project}: {lock_file} needs {required} beside it or the generator declines"
        )
    assert has_required_manifest(str(lock))


def test_jvm_has_no_fallback():
    """Nothing but cdxgen reads JVM build files.

    Worth pinning: syft catalogs compiled jars, not pom.xml or gradle, so if
    cdxgen ever stops claiming these the ecosystem goes unserved rather than
    degrading to something worse.
    """
    from sbomify_action._generation.utils import CDXGEN_LOCK_FILES, SYFT_LOCK_FILES

    for build_file in ("pom.xml", "build.gradle", "build.gradle.kts", "build.sbt"):
        assert build_file in CDXGEN_LOCK_FILES, build_file
        assert build_file not in SYFT_LOCK_FILES, build_file


def test_no_supported_lock_file_is_unserved():
    """Every discoverable lock file must have a generator that claims it."""
    from sbomify_action._generation.utils import (
        ALL_LOCK_FILES,
        CDXGEN_LOCK_FILES,
        CYCLONEDX_PY_LOCK_FILES,
        SYFT_LOCK_FILES,
    )

    claimed = set(CDXGEN_LOCK_FILES) | set(SYFT_LOCK_FILES) | set(CYCLONEDX_PY_LOCK_FILES) | {"Cargo.lock"}
    unserved = sorted(set(ALL_LOCK_FILES) - claimed)
    assert unserved == [], f"discoverable but no generator claims them: {unserved}"


def test_container_images_go_to_syft_not_cdxgen(monkeypatch):
    """For container images syft is the better tool, unlike lock files.

    Measured over the 27 image pairs in tests/test-data:

        total components   cdxgen 7389   syft 77795   (10.5x)
        per-image wins     syft 27       cdxgen 0
        distroless/static  cdxgen 0      syft 951

    cdxgen still leads for lock files, where it is genuinely better. Getting
    this backwards produced container SBOMs an order of magnitude thinner
    than they should have been, and nothing caught it because a short SBOM
    still looks like a successful one.
    """
    for module, flag in (("cdxgen", "_CDXGEN_AVAILABLE"), ("syft", "_SYFT_AVAILABLE")):
        monkeypatch.setattr(f"sbomify_action._generation.generators.{module}.{flag}", True)

    chain = [
        g.name
        for g in create_default_registry().get_generators_for(
            GenerationInput(docker_image="alpine:3.20", output_format="cyclonedx")
        )
    ]

    assert chain, "nothing claims container images"
    assert chain[0] == "syft-image", f"syft must lead for container images, got {chain}"


def test_cdxgen_still_leads_for_lock_files(monkeypatch):
    """The container demotion must not leak into filesystem scanning."""
    from sbomify_action._generation.generators import CdxgenFsGenerator, SyftFsGenerator

    assert CdxgenFsGenerator().priority < SyftFsGenerator().priority


def test_a_bare_go_module_falls_to_syft(monkeypatch, tmp_path):
    """No Go source means cyclonedx-gomod must decline rather than panic.

    Given only go.mod and go.sum it dies with "index out of range [0] with
    length 0". Pointing the action at bare module files is legitimate, so
    syft keeps that case.
    """
    monkeypatch.setenv("SBOMIFY_FETCH_RUNTIMES", "1")
    monkeypatch.setattr("sbomify_action._generation.generators.syft._SYFT_AVAILABLE", True)
    monkeypatch.setattr("sbomify_action._generation.generators.cdxgen._CDXGEN_AVAILABLE", False)

    (tmp_path / "go.mod").write_text("module example.com/x\n")
    (tmp_path / "go.sum").write_text("")

    chain = [
        g.name
        for g in create_default_registry().get_generators_for(
            GenerationInput(lock_file=str(tmp_path / "go.mod"), output_format="cyclonedx")
        )
    ]

    assert "cyclonedx-gomod" not in chain, "must not claim a module with no source"
    assert chain[0] == "syft-fs"
