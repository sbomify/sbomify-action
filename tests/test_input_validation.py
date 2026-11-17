"""Broken input fails clearly instead of crashing or passing silently.

Found by an audit of the action:

- A file whose top level is not a JSON object (``[]``, ``42``, ``null``)
  reached code that called ``.get()`` on it and crashed with
  ``AttributeError``, which telemetry then reported as a defect in the action.
- A CycloneDX ``SBOM_FILE`` that fails its schema (``"components": "oops"``)
  passed Step 1 and was written out unchanged with exit 0.
- ``AUGMENT=true`` with an ``sbomify.json`` that does not parse logged a
  warning, dropped the metadata it holds, and exited 0.
- Transitive dependency discovery and hash enrichment are optional, so a
  network or parse failure in them is a warning. A programming error in them
  was swallowed the same way, with exit 0.
"""

import json
from importlib import import_module
from pathlib import Path
from unittest.mock import Mock

import pytest

from sbomify_action.console import reset_audit_trail
from sbomify_action.exceptions import FileProcessingError, SBOMValidationError

# "sbomify_action.cli.main" as a dotted string resolves to the main() function
# the package re-exports, so patch the module object.
cli_main = import_module("sbomify_action.cli.main")

NOT_OBJECTS = ["[]", "42", "null", '"sbom"']


def test_load_sbom_json_returns_an_object(tmp_path):
    from sbomify_action.serialization import load_sbom_json

    path = tmp_path / "sbom.json"
    path.write_text('{"bomFormat": "CycloneDX"}')
    assert load_sbom_json(str(path)) == {"bomFormat": "CycloneDX"}


@pytest.mark.parametrize("body", NOT_OBJECTS)
def test_load_sbom_json_refuses_anything_but_an_object(tmp_path, body):
    from sbomify_action.serialization import load_sbom_json

    path = tmp_path / "sbom.json"
    path.write_text(body)
    with pytest.raises(SBOMValidationError, match="JSON object"):
        load_sbom_json(str(path))


def _validate(path, tmp_path):
    from sbomify_action.cli.main import validate_sbom

    return validate_sbom(path)


def _detect_silently(path, tmp_path):
    from sbomify_action.cli.main import _detect_sbom_format_silent

    return _detect_sbom_format_silent(path)


def _load(path, tmp_path):
    from sbomify_action.cli.main import load_sbom_from_file

    return load_sbom_from_file(path)


def _augment(path, tmp_path):
    from sbomify_action.augmentation import augment_sbom_from_file

    return augment_sbom_from_file(path, str(tmp_path / "out.json"))


def _enrich(path, tmp_path):
    from sbomify_action.enrichment import enrich_sbom

    return enrich_sbom(path, str(tmp_path / "out.json"))


def _inject(path, tmp_path):
    from sbomify_action.additional_packages import inject_additional_packages

    return inject_additional_packages(path)


def _hashes(path, tmp_path):
    from sbomify_action._hash_enrichment import enrich_sbom_with_hashes

    return enrich_sbom_with_hashes(path, str(tmp_path / "uv.lock"))


def _expand(path, tmp_path):
    from sbomify_action._dependency_expansion.enricher import DependencyEnricher

    return DependencyEnricher().expand_sbom(path, str(tmp_path / "requirements.txt"))


@pytest.mark.parametrize(
    "site",
    [_validate, _detect_silently, _load, _augment, _enrich, _inject, _hashes, _expand],
    ids=lambda f: f.__name__.lstrip("_"),
)
def test_every_reader_refuses_a_non_object_cleanly(tmp_path, monkeypatch, site):
    """Each of these called ``.get()`` on whatever ``json.load`` returned."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ADDITIONAL_PACKAGES", "pkg:pypi/extra@1.0.0")
    path = tmp_path / "sbom.json"
    path.write_text("[]")

    with pytest.raises(SBOMValidationError, match="JSON object"):
        site(str(path), tmp_path)


def test_yocto_discovery_skips_a_non_object_instead_of_crashing(tmp_path):
    from sbomify_action._yocto.parser import discover_packages

    (tmp_path / "broken.spdx.json").write_text("[]")

    with pytest.raises(FileProcessingError, match="No package SBOMs"):
        discover_packages(str(tmp_path))


def _write(tmp_path, document):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(document))
    return str(path)


def test_a_schema_invalid_cyclonedx_sbom_file_is_refused(tmp_path):
    from sbomify_action.cli.main import validate_sbom

    path = _write(tmp_path, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": "oops"})

    with pytest.raises(SBOMValidationError, match="components"):
        validate_sbom(path)


def test_a_cyclonedx_sbom_file_without_a_spec_version_is_refused(tmp_path):
    from sbomify_action.cli.main import validate_sbom

    path = _write(tmp_path, {"bomFormat": "CycloneDX", "components": []})

    with pytest.raises(SBOMValidationError, match="specVersion"):
        validate_sbom(path)


def test_licence_shapes_the_pipeline_repairs_are_not_refused(tmp_path):
    """Trivy writes non-SPDX ids into license.id and cdxgen a bare string into
    license.text. Both fail the schema, and load_cyclonedx_bom repairs both,
    so refusing them here would break inputs the pipeline already handles.

    The trial repair must not reach the audit trail: the real one, later,
    records it, and recording it twice would misstate what was changed.
    """
    from sbomify_action.cli.main import validate_sbom

    path = _write(
        tmp_path,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "a", "licenses": [{"license": {"id": "GPLv2+"}}]},
                {"type": "library", "name": "b", "licenses": [{"license": {"name": "x", "text": "Copyright"}}]},
            ],
        },
    )
    trail = reset_audit_trail()

    assert validate_sbom(path) == "cyclonedx"
    assert trail.entries == []


def _sbom_file_config(tmp_path, monkeypatch, document, **options):
    from sbomify_action.cli.main import build_config

    monkeypatch.chdir(tmp_path)
    return build_config(sbom_file=_write(tmp_path, document), upload=False, output_file="out.json", **options)


def test_the_pipeline_stops_at_step_1_on_a_schema_invalid_sbom_file(tmp_path, monkeypatch):
    from sbomify_action.cli.main import run_pipeline

    config = _sbom_file_config(
        tmp_path, monkeypatch, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": "oops"}
    )

    with pytest.raises(SystemExit) as exc:
        run_pipeline(config)
    assert exc.value.code == 1
    assert not (tmp_path / "out.json").exists()


_COMPONENT = {"type": "library", "name": "a", "version": "1.0"}

#: Inputs the schema refuses and cyclonedx-python-lib normalises: it drops a
#: property it does not model and fills the top-level version 1.4 requires.
NORMALISED_BY_THE_LIBRARY = {
    "unknown-property": {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{**_COMPONENT, "x-vendor": "acme"}],
    },
    "1.4-without-version": {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [_COMPONENT]},
}


@pytest.mark.parametrize("document", NORMALISED_BY_THE_LIBRARY.values(), ids=NORMALISED_BY_THE_LIBRARY.keys())
def test_an_input_augment_normalises_passes_and_the_output_is_valid(tmp_path, monkeypatch, document):
    """Judged before augmentation, these failed a run that writes a valid SBOM."""
    from sbomify_action.cli.main import run_pipeline
    from sbomify_action.validation import validate_sbom_file_auto

    config = _sbom_file_config(tmp_path, monkeypatch, document, augment=True)

    run_pipeline(config)

    assert validate_sbom_file_auto(str(tmp_path / "out.json")).valid is True


@pytest.mark.parametrize(
    "document",
    [
        *NORMALISED_BY_THE_LIBRARY.values(),
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{**_COMPONENT, "hashes": [{"alg": "SHA-256", "content": "zz"}]}],
        },
    ],
    ids=[*NORMALISED_BY_THE_LIBRARY.keys(), "bad-hash-content"],
)
def test_an_invalid_input_passed_through_verbatim_fails_the_final_check(tmp_path, monkeypatch, document):
    """With AUGMENT, ENRICH and every override off nothing re-serialises the
    document, so it would be published as supplied. Step 1 lets it through
    because the library can read it; the check on the final document stops
    it before anything is written or uploaded."""
    from sbomify_action.cli.main import build_config, run_pipeline, validate_sbom

    monkeypatch.chdir(tmp_path)
    upload = Mock()
    monkeypatch.setattr(cli_main, "upload_sbom", upload)
    config = build_config(sbom_file=_write(tmp_path, document), token="t", component_id="c", output_file="out.json")
    assert validate_sbom(config.sbom_file) == "cyclonedx"

    with pytest.raises(SystemExit) as exc:
        run_pipeline(config)
    assert exc.value.code == 1
    assert not (tmp_path / "out.json").exists()
    upload.assert_not_called()


def test_an_invalid_cyclonedx_vex_fails_the_final_check(tmp_path, monkeypatch):
    """Step 1 checked VEX, CBOM and HBOM against the schema too. They are
    uploaded verbatim, so the final check is the one that sees them now."""
    from sbomify_action.cli.main import run_pipeline

    vex = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "vulnerabilities": [{"x-vendor": "acme"}]}
    config = _sbom_file_config(tmp_path, monkeypatch, vex, bom_type="vex")

    with pytest.raises(SystemExit) as exc:
        run_pipeline(config)
    assert exc.value.code == 1
    assert not (tmp_path / "out.json").exists()


def test_a_schema_failure_is_reported_once(tmp_path, monkeypatch, caplog):
    """validate_sbom_data logged the failure, then the step that called it
    logged the same text again in its own message."""
    from sbomify_action.cli.main import run_pipeline

    config = _sbom_file_config(tmp_path, monkeypatch, NORMALISED_BY_THE_LIBRARY["unknown-property"])

    with caplog.at_level("ERROR"), pytest.raises(SystemExit):
        run_pipeline(config)

    assert caplog.text.count("'x-vendor' was unexpected") == 1


def test_licence_shapes_the_pipeline_repairs_pass_the_final_check(tmp_path, monkeypatch):
    """Passed through verbatim, Trivy's and cdxgen's licence shapes reach the
    final check unrepaired. Refusing them there would fail inputs that pass
    on master, so the check repairs a copy first, as Step 1 used to."""
    from sbomify_action.cli.main import run_pipeline

    config = _sbom_file_config(
        tmp_path,
        monkeypatch,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {**_COMPONENT, "licenses": [{"license": {"id": "GPLv2+"}}]},
                {**_COMPONENT, "name": "b", "licenses": [{"license": {"name": "x", "text": "Copyright"}}]},
            ],
        },
    )

    run_pipeline(config)

    assert (tmp_path / "out.json").exists()


def test_an_sbom_file_with_no_components_still_passes(tmp_path, monkeypatch):
    """Only a lock file that yields nothing is suspect. A supplied SBOM that
    lists no components may be exactly right."""
    from sbomify_action.cli.main import run_pipeline

    config = _sbom_file_config(
        tmp_path, monkeypatch, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    )

    run_pipeline(config)

    assert json.loads((tmp_path / "out.json").read_text())["components"] == []


def test_augment_stops_on_an_sbomify_json_it_cannot_read(tmp_path, monkeypatch):
    """AUGMENT=true with a malformed sbomify.json used to log a warning, drop
    the supplier and author metadata, and exit 0."""
    from sbomify_action.cli.main import run_pipeline

    config = _sbom_file_config(
        tmp_path, monkeypatch, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}, augment=True
    )
    (tmp_path / "sbomify.json").write_text('{"supplier": {"name": "Acme"},}')

    with pytest.raises(SystemExit) as exc:
        run_pipeline(config)
    assert exc.value.code == 1


@pytest.fixture
def lock_file_run(tmp_path, monkeypatch):
    """A lock-file run whose generator is stubbed and whose optional steps succeed."""
    from sbomify_action._generation.result import GenerationResult
    from sbomify_action.cli.main import build_config

    monkeypatch.chdir(tmp_path)
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

    def generate(lock_file, output_file, **_):
        Path(output_file).write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [{"type": "library", "name": "flask", "version": "3.0.0"}],
                }
            )
        )
        return GenerationResult.success_result(
            output_file=output_file, sbom_format="cyclonedx", spec_version="1.6", generator_name="stub"
        )

    monkeypatch.setattr(cli_main, "process_lock_file", generate)
    monkeypatch.setattr("sbomify_action._dependency_expansion.supports_dependency_expansion", lambda _: True)
    monkeypatch.setattr(
        "sbomify_action._dependency_expansion.expand_sbom_dependencies",
        Mock(return_value=Mock(added_count=0, discovered_count=0, dependencies=[])),
    )
    monkeypatch.setattr(
        "sbomify_action._hash_enrichment.enrich_sbom_with_hashes",
        Mock(return_value={"hashes_added": 0, "components_matched": 0, "sbom_components": 1}),
    )
    return build_config(lock_file="requirements.txt", upload=False, output_file="out.json")


OPTIONAL_STEPS = [
    "sbomify_action._dependency_expansion.expand_sbom_dependencies",
    "sbomify_action._hash_enrichment.enrich_sbom_with_hashes",
]


@pytest.mark.parametrize("step", OPTIONAL_STEPS, ids=["dependency-discovery", "hash-enrichment"])
@pytest.mark.parametrize(
    "failure",
    [OSError("registry unreachable"), ValueError("lock file does not parse"), SBOMValidationError("not an SBOM")],
    ids=["network", "parse", "sbom"],
)
def test_an_expected_failure_in_an_optional_step_is_a_warning(lock_file_run, monkeypatch, tmp_path, step, failure):
    from sbomify_action.cli.main import run_pipeline

    monkeypatch.setattr(step, Mock(side_effect=failure))

    run_pipeline(lock_file_run)

    assert (tmp_path / "out.json").exists()


@pytest.mark.parametrize("step", OPTIONAL_STEPS, ids=["dependency-discovery", "hash-enrichment"])
def test_a_programming_error_in_an_optional_step_is_not_swallowed(lock_file_run, monkeypatch, step):
    """These ran under a bare ``except Exception`` and exited 0, so a bug in
    either step shipped an SBOM missing what the step adds and nobody heard."""
    from sbomify_action.cli.main import run_pipeline

    monkeypatch.setattr(step, Mock(side_effect=AttributeError("'NoneType' object has no attribute 'components'")))

    with pytest.raises(AttributeError):
        run_pipeline(lock_file_run)


_SHAPE_BROKEN = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": "oops"}


def test_hash_enrichment_names_a_malformed_sbom_a_parse_error(tmp_path):
    """The CycloneDX deserializer raises AttributeError on this. Named for what
    it is, it stays a warning in Step 1.5 instead of passing for a bug."""
    from sbomify_action._hash_enrichment import enrich_sbom_with_hashes

    with pytest.raises(SBOMValidationError, match="Failed to parse"):
        enrich_sbom_with_hashes(_write(tmp_path, _SHAPE_BROKEN), str(tmp_path / "uv.lock"))


def test_dependency_expansion_names_a_malformed_sbom_a_parse_error(tmp_path):
    from sbomify_action._dependency_expansion.enricher import DependencyEnricher

    path = Path(_write(tmp_path, _SHAPE_BROKEN))
    with pytest.raises(SBOMValidationError, match="Failed to parse"):
        DependencyEnricher()._enrich_cyclonedx(path, json.loads(path.read_text()), [], "stub")
