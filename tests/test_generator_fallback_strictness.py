"""Fallback must not silently downgrade SBOM quality inside our own image.

cyclonedx-cargo shipped broken for every Rust user: it requested CycloneDX
1.6, which cargo-cyclonedx rejects, so it failed on every invocation and syft
quietly generated the SBOM instead. The output looked fine, so nobody noticed.

These tests pin the behaviour that would have surfaced it on day one.
"""

import pytest

from sbomify_action._generation.protocol import FormatVersion, GenerationInput
from sbomify_action._generation.registry import GeneratorRegistry, fallback_is_a_bug
from sbomify_action._generation.result import GenerationResult
from sbomify_action.exceptions import SBOMGenerationError


class _Stub:
    """Minimal generator whose behaviour each test dictates."""

    def __init__(self, name, priority, outcome, error="boom"):
        self._name, self._priority, self._outcome, self._error = name, priority, outcome, error

    name = property(lambda self: self._name)
    command = property(lambda self: self._name)
    priority = property(lambda self: self._priority)

    @property
    def supported_formats(self):
        return [FormatVersion("cyclonedx", ("1.6",), "1.6")]

    def supports(self, input):
        return True

    def generate(self, input):
        if self._outcome == "raise-sbomgen":
            raise SBOMGenerationError(self._error)
        if self._outcome == "success":
            return GenerationResult.success_result(
                output_file=input.output_file,
                sbom_format="cyclonedx",
                spec_version="1.6",
                generator_name=self._name,
            )
        if self._outcome == "declined":
            return GenerationResult.declined_result(
                error_message=self._error,
                sbom_format="cyclonedx",
                spec_version="1.6",
                generator_name=self._name,
            )
        if self._outcome == "raise":
            raise RuntimeError(self._error)
        return GenerationResult.failure_result(
            error_message=self._error,
            sbom_format="cyclonedx",
            spec_version="1.6",
            generator_name=self._name,
        )


@pytest.fixture
def in_container(monkeypatch):
    monkeypatch.setenv("SBOMIFY_IN_CONTAINER", "1")
    monkeypatch.delenv("SBOMIFY_ALLOW_GENERATOR_FALLBACK", raising=False)


@pytest.fixture
def outside_container(monkeypatch, tmp_path):
    monkeypatch.delenv("SBOMIFY_IN_CONTAINER", raising=False)
    monkeypatch.delenv("SBOMIFY_ALLOW_GENERATOR_FALLBACK", raising=False)
    # /.dockerenv is the belt-and-braces check; make sure it cannot fire.
    monkeypatch.setattr(
        "sbomify_action._generation.registry.Path", lambda _: type("P", (), {"exists": lambda s: False})()
    )


def _input(tmp_path):
    return GenerationInput(
        lock_file=str(tmp_path / "Cargo.lock"),
        output_file=str(tmp_path / "sbom.json"),
        output_format="cyclonedx",
    )


def test_native_failure_aborts_in_container(in_container, tmp_path):
    """The exact cyclonedx-cargo bug: native fails, syft would silently cover."""
    registry = GeneratorRegistry()
    registry.register(_Stub("cyclonedx-cargo", 10, "failure", "Unsupported Spec Version '1.6'"))
    registry.register(_Stub("syft-fs", 35, "success"))

    with pytest.raises(SBOMGenerationError) as exc:
        registry.generate(_input(tmp_path), validate=False)

    message = str(exc.value)
    assert "cyclonedx-cargo" in message
    assert "Unsupported Spec Version" in message
    assert "syft-fs" in message, "the error must name what it refused to fall back to"


def test_native_exception_also_aborts_in_container(in_container, tmp_path):
    registry = GeneratorRegistry()
    registry.register(_Stub("cyclonedx-cargo", 10, "raise", "cargo not found"))
    registry.register(_Stub("syft-fs", 35, "success"))

    with pytest.raises(SBOMGenerationError, match="cargo not found"):
        registry.generate(_input(tmp_path), validate=False)


def test_decline_still_falls_through_in_container(in_container, tmp_path):
    """A cargo workspace is a routing decision, not a defect."""
    registry = GeneratorRegistry()
    registry.register(_Stub("cyclonedx-cargo", 10, "declined", "cargo workspace"))
    registry.register(_Stub("syft-fs", 35, "success"))

    result = registry.generate(_input(tmp_path), validate=False)

    assert result.success
    assert result.generator_name == "syft-fs"


def test_last_generator_failing_does_not_raise(in_container, tmp_path):
    """Nothing was downgraded, so report failure normally rather than raising."""
    registry = GeneratorRegistry()
    registry.register(_Stub("syft-fs", 35, "failure", "syft exploded"))

    result = registry.generate(_input(tmp_path), validate=False)

    assert not result.success
    assert "syft exploded" in (result.error_message or "")


def test_outside_the_container_it_falls_back_and_warns(outside_container, tmp_path, caplog):
    """pip installs have unknown environments, so being helpful wins."""
    registry = GeneratorRegistry()
    registry.register(_Stub("cyclonedx-cargo", 10, "failure", "not installed"))
    registry.register(_Stub("syft-fs", 35, "success"))

    with caplog.at_level("WARNING"):
        result = registry.generate(_input(tmp_path), validate=False)

    assert result.success
    assert result.generator_name == "syft-fs"
    assert any("lower-quality" in r.message for r in caplog.records), (
        "a silent downgrade is what hid the bug; it must warn"
    )


def test_escape_hatch_restores_fallback(in_container, monkeypatch, tmp_path):
    monkeypatch.setenv("SBOMIFY_ALLOW_GENERATOR_FALLBACK", "1")
    registry = GeneratorRegistry()
    registry.register(_Stub("cyclonedx-cargo", 10, "failure", "broken"))
    registry.register(_Stub("syft-fs", 35, "success"))

    result = registry.generate(_input(tmp_path), validate=False)

    assert result.success and result.generator_name == "syft-fs"


def test_marker_controls_strictness(monkeypatch):
    monkeypatch.delenv("SBOMIFY_ALLOW_GENERATOR_FALLBACK", raising=False)
    monkeypatch.setenv("SBOMIFY_IN_CONTAINER", "1")
    assert fallback_is_a_bug() is True
    monkeypatch.setenv("SBOMIFY_ALLOW_GENERATOR_FALLBACK", "1")
    assert fallback_is_a_bug() is False


def test_generator_raising_sbomgenerationerror_still_falls_back_outside(outside_container, tmp_path):
    """Strict mode must not change the pip path, even for typed errors.

    run_command raises SBOMGenerationError, so a generator that forgets to
    catch it propagates one. Catching the base class in the retry loop made
    that abort for pip users too -- the exact behaviour strict mode is meant
    to leave alone. Only the internal _DowngradeRefused may bypass fallback.
    """
    registry = GeneratorRegistry()
    registry.register(_Stub("cyclonedx-py", 10, "raise-sbomgen", "cyclonedx-py exploded"))
    registry.register(_Stub("syft-fs", 35, "success"))

    result = registry.generate(_input(tmp_path), validate=False)

    assert result.success
    assert result.generator_name == "syft-fs"


def test_generator_raising_sbomgenerationerror_aborts_in_container(in_container, tmp_path):
    """...but in our own image it is still a defect we shipped."""
    registry = GeneratorRegistry()
    registry.register(_Stub("cyclonedx-py", 10, "raise-sbomgen", "cyclonedx-py exploded"))
    registry.register(_Stub("syft-fs", 35, "success"))

    with pytest.raises(SBOMGenerationError, match="cyclonedx-py exploded"):
        registry.generate(_input(tmp_path), validate=False)
