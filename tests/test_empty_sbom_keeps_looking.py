"""An SBOM with no components must not stop the generator ladder.

apache/dubbo: cyclonedx-maven wrote a document holding its aggregator POM
and nothing else, and exited 0. The registry returned on the first
generator that exited 0, so cdxgen -- next in line, which produces 763
components for that project -- was never reached.

Exit status alone cannot tell "this project has no dependencies" from "I
could not read this input". Emptiness is therefore treated as "keep
looking" rather than as failure: an empty SBOM is still returned when
nothing else finds anything, because a project without dependencies is
entitled to one.
"""

import json
from pathlib import Path

import pytest

from sbomify_action._generation.protocol import FormatVersion, GenerationInput
from sbomify_action._generation.registry import GeneratorRegistry, _describes_nothing
from sbomify_action._generation.result import GenerationResult


class _Stub:
    """Generator that writes a fixed component list and reports success."""

    def __init__(self, name, priority, components):
        self._name, self._priority, self._components = name, priority, components
        self.ran = False

    name = property(lambda self: self._name)
    command = property(lambda self: self._name)
    priority = property(lambda self: self._priority)

    @property
    def supported_formats(self):
        return [FormatVersion("cyclonedx", ("1.6",), "1.6")]

    def supports(self, input):
        return True

    def generate(self, input):
        self.ran = True
        Path(input.output_file).write_text(
            json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": self._components})
        )
        return GenerationResult.success_result(
            output_file=input.output_file,
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name=self._name,
        )


@pytest.fixture(autouse=True)
def outside_container(monkeypatch):
    """Strict mode is about refusing downgrades; it is not what is under test."""
    monkeypatch.delenv("SBOMIFY_IN_CONTAINER", raising=False)
    monkeypatch.setenv("SBOMIFY_ALLOW_GENERATOR_FALLBACK", "1")


def _input(tmp_path):
    return GenerationInput(
        lock_file=str(tmp_path / "pom.xml"),
        output_file=str(tmp_path / "sbom.json"),
        output_format="cyclonedx",
    )


_ONE = [{"name": "guava", "type": "library"}]


def test_a_later_generator_with_components_wins(tmp_path):
    """The dubbo case: 0 from the preferred generator, 763 from the next."""
    empty = _Stub("cyclonedx-maven", 10, [])
    full = _Stub("cdxgen-fs", 20, _ONE)
    registry = GeneratorRegistry()
    registry.register(empty)
    registry.register(full)

    result = registry.generate(_input(tmp_path), validate=False)

    assert full.ran, "the generator that can read this input was never tried"
    assert result.generator_name == "cdxgen-fs"
    assert len(json.loads(Path(result.output_file).read_text())["components"]) == 1


def test_an_empty_result_is_still_returned_when_nothing_does_better(tmp_path):
    """A project with no dependencies is entitled to an empty SBOM.

    Failing here would trade a silent wrong answer for a loud wrong one.
    """
    first = _Stub("cyclonedx-maven", 10, [])
    second = _Stub("cdxgen-fs", 20, [])
    registry = GeneratorRegistry()
    registry.register(first)
    registry.register(second)

    result = registry.generate(_input(tmp_path), validate=False)

    assert result.success
    assert second.ran
    assert json.loads(Path(result.output_file).read_text())["components"] == []


def test_a_non_empty_first_generator_still_short_circuits(tmp_path):
    """The common path must not start running every generator."""
    first = _Stub("cyclonedx-maven", 10, _ONE)
    second = _Stub("cdxgen-fs", 20, _ONE)
    registry = GeneratorRegistry()
    registry.register(first)
    registry.register(second)

    result = registry.generate(_input(tmp_path), validate=False)

    assert result.generator_name == "cyclonedx-maven"
    assert not second.ran, "a good first result must not cost a second run"


def _result_for(path):
    return GenerationResult.success_result(
        output_file=str(path),
        sbom_format="cyclonedx",
        spec_version="1.6",
        generator_name="fake",
    )


def test_zero_cyclonedx_components_describes_nothing(tmp_path):
    out = tmp_path / "b.json"
    out.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    assert _describes_nothing(_result_for(out)) is True


def test_one_cyclonedx_component_is_enough(tmp_path):
    out = tmp_path / "b.json"
    out.write_text(json.dumps({"bomFormat": "CycloneDX", "components": _ONE}))
    assert _describes_nothing(_result_for(out)) is False


def test_spdx_with_only_the_root_package_describes_nothing(tmp_path):
    """SPDX always describes the root, so one package is the same emptiness."""
    out = tmp_path / "s.json"
    out.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "root"}]}))
    assert _describes_nothing(_result_for(out)) is True


def test_spdx_with_a_dependency_is_enough(tmp_path):
    out = tmp_path / "s.json"
    out.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "root"}, {"name": "guava"}]}))
    assert _describes_nothing(_result_for(out)) is False


def test_unreadable_output_is_not_called_empty(tmp_path):
    """Validation is the thing that should speak to a broken document."""
    out = tmp_path / "b.json"
    out.write_text("{not json")
    assert _describes_nothing(_result_for(out)) is False


def test_missing_output_is_not_called_empty(tmp_path):
    assert _describes_nothing(_result_for(tmp_path / "gone.json")) is False


def test_classification_never_fails_the_run(tmp_path, monkeypatch):
    """Deciding "is this empty" must not be able to turn a success into a failure.

    An earlier draft read the file through the module-level ``Path``, which
    another test monkeypatches; the resulting AttributeError escaped, the
    loop caught it as a generator error, and a perfectly good SBOM was
    discarded. Classification is advisory and must stay that way.
    """
    monkeypatch.setattr(
        "sbomify_action._generation.registry.Path",
        lambda _p: type("P", (), {"exists": lambda s: False})(),
    )
    out = tmp_path / "b.json"
    out.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))

    assert _describes_nothing(_result_for(out)) is True
