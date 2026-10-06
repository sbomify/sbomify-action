"""Document upload (DOCUMENT_FILE): client, upload module, config and pipeline.

Documents are the one artifact the action publishes without parsing: a PDF is
opaque bytes plus metadata, uploaded to a component of type ``document``. These
tests pin the contract on both sides — the multipart request the backend
expects, and the config rules that keep SBOM machinery away from a signed
report.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sbomify_action._upload import DocumentUploadInput, DocumentUploadResult
from sbomify_action._upload.documents import MAX_DOCUMENT_SIZE
from sbomify_action._upload.documents import upload_document as upload_document_input
from sbomify_action.cli.main import SBOMIFY_PRODUCTION_API, build_config, run_pipeline
from sbomify_action.exceptions import AuthError
from sbomify_action.sbomify_api import SbomifyApiClient
from sbomify_action.upload import upload_document

PDF_BYTES = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"


def _response(status_code: int = 201, json_body: object = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.ok = 200 <= status_code < 300
    response.json.return_value = {"id": "doc-123"} if json_body is None else json_body
    return response


@pytest.fixture
def pdf(tmp_path):
    """A small on-disk PDF to upload."""
    path = tmp_path / "pentest-report.pdf"
    path.write_bytes(PDF_BYTES)
    return path


# ---------------------------------------------------------------------------
# DocumentUploadInput


def test_input_defaults_name_to_file_stem():
    input = DocumentUploadInput(document_file="reports/pentest-2026.pdf")
    assert input.resolved_name == "pentest-2026"
    assert input.document_type == "other"
    assert input.version == "1.0"


def test_input_keeps_explicit_name():
    input = DocumentUploadInput(document_file="a.pdf", name="Annual Pentest")
    assert input.resolved_name == "Annual Pentest"


def test_input_rejects_unknown_document_type():
    with pytest.raises(ValueError, match="Invalid document_type"):
        DocumentUploadInput(document_file="a.pdf", document_type="pentest")


def test_input_rejects_unknown_compliance_subcategory():
    with pytest.raises(ValueError, match="Invalid compliance_subcategory"):
        DocumentUploadInput(document_file="a.pdf", document_type="compliance", compliance_subcategory="pci")


def test_input_drops_subcategory_for_non_compliance_types():
    """The backend only reads the subcategory for compliance documents, so an
    input that keeps one for a manual would report state that is never sent."""
    input = DocumentUploadInput(document_file="a.pdf", document_type="manual", compliance_subcategory="soc2")
    assert input.compliance_subcategory is None


def test_input_keeps_subcategory_for_compliance_documents():
    input = DocumentUploadInput(document_file="a.pdf", document_type="compliance", compliance_subcategory="SOC2")
    assert input.compliance_subcategory == "soc2"


def test_input_validates_subcategory_before_dropping_it():
    """A typo is a typo even on a type that would discard the value."""
    with pytest.raises(ValueError, match="Invalid compliance_subcategory"):
        DocumentUploadInput(document_file="a.pdf", document_type="manual", compliance_subcategory="pci")


def test_input_normalizes_case():
    input = DocumentUploadInput(
        document_file="a.pdf",
        document_type="Pentest-Report",
        compliance_subcategory=None,
    )
    assert input.document_type == "pentest-report"


def test_input_requires_a_file():
    with pytest.raises(ValueError, match="document_file is required"):
        DocumentUploadInput(document_file="")


def test_result_rejects_inconsistent_state():
    with pytest.raises(ValueError):
        DocumentUploadResult(success=False)
    with pytest.raises(ValueError):
        DocumentUploadResult(success=True, error_message="boom")


# ---------------------------------------------------------------------------
# SbomifyApiClient.upload_document


def test_client_posts_multipart_to_documents_endpoint():
    """The backend's raw-body branch reads request.body, which Django caps at
    DATA_UPLOAD_MAX_MEMORY_SIZE and which drops the filename — so the client
    must use the multipart branch, form fields included."""
    session = MagicMock()
    session.request.return_value = _response()
    client = SbomifyApiClient(SBOMIFY_PRODUCTION_API, "tok", session=session)

    client.upload_document(
        "comp-1",
        PDF_BYTES,
        name="Pentest 2026",
        version="2026.1",
        document_type="pentest-report",
        description="Annual test",
        filename="pentest-report.pdf",
        content_type="application/pdf",
    )

    args, kwargs = session.request.call_args
    assert args[0] == "POST"
    assert args[1] == "https://app.sbomify.com/api/v1/documents/"
    assert kwargs["files"] == {"document_file": ("pentest-report.pdf", PDF_BYTES, "application/pdf")}
    assert kwargs["data"] == {
        "component_id": "comp-1",
        "name": "Pentest 2026",
        "version": "2026.1",
        "document_type": "pentest-report",
        "description": "Annual test",
    }
    # requests must own the Content-Type so the multipart boundary matches.
    assert "Content-Type" not in kwargs["headers"]
    assert kwargs["headers"]["Authorization"] == "Bearer tok"


def test_client_sends_compliance_subcategory_only_for_compliance_documents():
    session = MagicMock()
    session.request.return_value = _response()
    client = SbomifyApiClient(SBOMIFY_PRODUCTION_API, "tok", session=session)

    client.upload_document("c", PDF_BYTES, name="SOC 2", document_type="compliance", compliance_subcategory="soc2")
    assert session.request.call_args.kwargs["data"]["compliance_subcategory"] == "soc2"

    client.upload_document("c", PDF_BYTES, name="Manual", document_type="manual", compliance_subcategory="soc2")
    assert "compliance_subcategory" not in session.request.call_args.kwargs["data"]


def test_client_rejects_invalid_document_type():
    client = SbomifyApiClient(SBOMIFY_PRODUCTION_API, "tok", session=MagicMock())
    with pytest.raises(ValueError, match="Invalid document_type"):
        client.upload_document("c", PDF_BYTES, name="x", document_type="pdf")


def test_client_tags_document_into_release_with_document_id():
    """The release-artifact endpoint takes exactly one of sbom_id/document_id;
    sending a document under sbom_id would attach the wrong artifact kind."""
    session = MagicMock()
    session.request.return_value = _response(200, {})
    client = SbomifyApiClient(SBOMIFY_PRODUCTION_API, "tok", session=session)

    client.tag_artifact_with_release("doc-1", "rel-1", artifact_kind="document")
    assert session.request.call_args.kwargs["json"] == {"document_id": "doc-1"}

    client.tag_artifact_with_release("sbom-1", "rel-1")
    assert session.request.call_args.kwargs["json"] == {"sbom_id": "sbom-1"}


def test_client_rejects_unknown_artifact_kind():
    client = SbomifyApiClient(SBOMIFY_PRODUCTION_API, "tok", session=MagicMock())
    with pytest.raises(ValueError, match="Invalid artifact_kind"):
        client.tag_artifact_with_release("x", "rel", artifact_kind="vex")


# ---------------------------------------------------------------------------
# upload_document()


def test_upload_returns_document_id(pdf):
    with patch("sbomify_action._upload.documents.SbomifyApiClient") as client_cls:
        client_cls.return_value.upload_document.return_value = _response()
        result = upload_document(
            document_file=str(pdf),
            token="tok",
            component_id="comp-1",
            document_type="pentest-report",
        )

    assert result.success
    assert result.document_id == "doc-123"
    kwargs = client_cls.return_value.upload_document.call_args.kwargs
    assert kwargs["name"] == "pentest-report"
    assert kwargs["content_type"] == "application/pdf"
    assert kwargs["document_payload"] == PDF_BYTES


def test_upload_without_credentials_fails_before_any_request(pdf):
    with patch("sbomify_action._upload.documents.SbomifyApiClient") as client_cls:
        result = upload_document(document_file=str(pdf), token=None, component_id="c")
    assert not result.success
    assert "not configured" in result.error_message
    client_cls.assert_not_called()


def test_upload_missing_file_reports_the_path(tmp_path):
    result = upload_document(document_file=str(tmp_path / "nope.pdf"), token="t", component_id="c")
    assert not result.success
    assert "not found" in result.error_message


def test_upload_rejects_empty_file(tmp_path):
    empty = tmp_path / "empty.pdf"
    empty.write_bytes(b"")
    result = upload_document(document_file=str(empty), token="t", component_id="c")
    assert not result.success
    assert "empty" in result.error_message


def test_upload_rejects_oversized_file_without_reading_it(tmp_path):
    """A 40-minute build should not end in a server-side 400 a size check could
    have called first — and the check must come off stat(), not off pulling a
    multi-gigabyte file into memory only to refuse it."""
    big = tmp_path / "big.pdf"
    with big.open("wb") as fh:
        fh.truncate(MAX_DOCUMENT_SIZE + 1)  # sparse: no bytes actually written

    with (
        patch("sbomify_action._upload.documents.SbomifyApiClient") as client_cls,
        patch.object(Path, "read_bytes", side_effect=AssertionError("file was read into memory")) as read_bytes,
    ):
        result = upload_document(document_file=str(big), token="t", component_id="c")

    assert not result.success
    assert "50 MB" in result.error_message
    read_bytes.assert_not_called()
    client_cls.assert_not_called()


def test_upload_rejects_a_file_that_grew_past_the_limit_after_the_stat(pdf):
    """stat() is a hint, not a promise: a file can grow between the stat and the
    read, so the payload gets the final say."""
    with (
        patch("sbomify_action._upload.documents.SbomifyApiClient") as client_cls,
        patch.object(Path, "read_bytes", return_value=b"x" * (MAX_DOCUMENT_SIZE + 1)),
    ):
        result = upload_document(document_file=str(pdf), token="t", component_id="c")

    assert not result.success
    assert "50 MB" in result.error_message
    client_cls.assert_not_called()


def test_upload_404_explains_the_component_type(pdf):
    with patch("sbomify_action._upload.documents.SbomifyApiClient") as client_cls:
        client_cls.return_value.upload_document.return_value = _response(404, {"detail": "not found"})
        result = upload_document(document_file=str(pdf), token="t", component_id="c")

    assert not result.success
    assert result.error_code == "COMPONENT_NOT_FOUND"
    assert "type 'document'" in result.error_message


def test_upload_auth_failure_is_tagged(pdf):
    with patch("sbomify_action._upload.documents.SbomifyApiClient") as client_cls:
        client_cls.return_value.upload_document.side_effect = AuthError("Authentication failed [401]")
        result = upload_document(document_file=str(pdf), token="bad", component_id="c")

    assert not result.success
    assert result.error_code == "AUTH_FAILED"


def test_upload_surfaces_api_error_detail(pdf):
    with patch("sbomify_action._upload.documents.SbomifyApiClient") as client_cls:
        client_cls.return_value.upload_document.return_value = _response(
            400, {"detail": "File size must be less than 50MB", "error_code": "BAD_REQUEST"}
        )
        result = upload_document(document_file=str(pdf), token="t", component_id="c")

    assert not result.success
    assert result.error_code == "BAD_REQUEST"
    assert "File size must be less than 50MB" in result.error_message


def test_upload_input_form_accepts_a_prebuilt_input(pdf):
    with patch("sbomify_action._upload.documents.SbomifyApiClient") as client_cls:
        client_cls.return_value.upload_document.return_value = _response()
        result = upload_document_input(
            DocumentUploadInput(document_file=str(pdf), name="Report"),
            token="t",
            component_id="c",
        )
    assert result.success


# ---------------------------------------------------------------------------
# Config


def _doc_config(pdf, monkeypatch, tmp_path, **overrides):
    monkeypatch.chdir(tmp_path)
    kwargs = dict(
        token="tok",
        component_id="comp-1",
        document_file=str(pdf),
    )
    kwargs.update(overrides)
    return build_config(**kwargs)


def test_config_marks_document_upload(pdf, monkeypatch, tmp_path):
    config = _doc_config(pdf, monkeypatch, tmp_path, document_type="pentest-report")
    assert config.is_document_upload
    assert config.document_type == "pentest-report"
    assert config.document_version == "1.0"


def test_config_falls_back_to_component_version(pdf, monkeypatch, tmp_path):
    """Most workflows already compute COMPONENT_VERSION and mean the same thing
    by it; the backend's "1.0" default would stamp every upload identically."""
    config = _doc_config(pdf, monkeypatch, tmp_path, component_version="2026.4.1")
    assert config.document_version == "2026.4.1"


def test_config_prefers_explicit_document_version(pdf, monkeypatch, tmp_path):
    config = _doc_config(pdf, monkeypatch, tmp_path, component_version="2026.4.1", document_version="7")
    assert config.document_version == "7"


def test_config_rejects_document_with_lock_file(pdf, monkeypatch, tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n")
    with pytest.raises(SystemExit):
        _doc_config(pdf, monkeypatch, tmp_path, lock_file="requirements.txt")


def test_config_rejects_document_upload_with_uploads_disabled(pdf, monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        _doc_config(pdf, monkeypatch, tmp_path, upload=False)


def test_config_rejects_non_sbomify_destination(pdf, monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        _doc_config(pdf, monkeypatch, tmp_path, upload_destinations=["sbomify", "dependency-track"])


def test_config_rejects_bad_document_type(pdf, monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        _doc_config(pdf, monkeypatch, tmp_path, document_type="invoice")


def test_config_rejects_bom_type_with_document(pdf, monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        _doc_config(pdf, monkeypatch, tmp_path, bom_type="vex")


def test_config_drops_subcategory_for_non_compliance_type(pdf, monkeypatch, tmp_path):
    config = _doc_config(pdf, monkeypatch, tmp_path, document_type="manual", document_compliance_subcategory="soc2")
    assert config.document_compliance_subcategory is None


def test_config_disables_augment_and_enrich(pdf, monkeypatch, tmp_path):
    """Augmentation and enrichment rewrite an SBOM; there is nothing in a PDF
    for them to touch, so they are dropped rather than silently attempted."""
    config = _doc_config(pdf, monkeypatch, tmp_path, augment=True, enrich=True)
    assert not config.augment
    assert not config.enrich


# ---------------------------------------------------------------------------
# Pipeline


def test_pipeline_uploads_the_document(pdf, monkeypatch, tmp_path):
    config = _doc_config(pdf, monkeypatch, tmp_path, document_type="pentest-report", document_name="Pentest")

    with patch("sbomify_action.cli.main.upload_document") as upload:
        upload.return_value = DocumentUploadResult(success=True, document_id="doc-9")
        run_pipeline(config)

    kwargs = upload.call_args.kwargs
    assert kwargs["document_file"] == str(pdf)
    assert kwargs["component_id"] == "comp-1"
    assert kwargs["document_type"] == "pentest-report"
    assert kwargs["name"] == "Pentest"
    # No SBOM was generated, so nothing should have been written.
    assert not (tmp_path / "sbom_output.json").exists()


def test_pipeline_exits_nonzero_on_upload_failure(pdf, monkeypatch, tmp_path):
    config = _doc_config(pdf, monkeypatch, tmp_path)

    with patch("sbomify_action.cli.main.upload_document") as upload:
        upload.return_value = DocumentUploadResult(success=False, error_message="boom")
        with pytest.raises(SystemExit) as exc:
            run_pipeline(config)

    assert exc.value.code == 1


def test_pipeline_tags_document_into_release(pdf, monkeypatch, tmp_path):
    config = _doc_config(pdf, monkeypatch, tmp_path, product_releases='["prod-1:v1.2.3"]')

    with (
        patch("sbomify_action.cli.main.upload_document") as upload,
        patch("sbomify_action._processors.orchestrator.ProcessorRegistry.process_all") as process_all,
    ):
        upload.return_value = DocumentUploadResult(success=True, document_id="doc-9")
        process_all.return_value = []
        run_pipeline(config)

    processor_input = process_all.call_args.args[0]
    assert processor_input.sbom_id == "doc-9"
    assert processor_input.artifact_kind == "document"
    # A document run writes no OUTPUT_FILE; naming one would point processors
    # at a path that does not exist.
    assert processor_input.sbom_file is None


def test_pipeline_numbers_document_steps_consecutively(pdf, monkeypatch, tmp_path):
    """A document run has two steps, not six: post-upload processing must not
    announce itself as step 6 straight after step 1."""
    config = _doc_config(pdf, monkeypatch, tmp_path, product_releases='["prod-1:v1.2.3"]')

    with (
        patch("sbomify_action.cli.main.upload_document") as upload,
        patch("sbomify_action.cli.main._log_step_header") as step_header,
        patch("sbomify_action._processors.orchestrator.ProcessorRegistry.process_all") as process_all,
    ):
        upload.return_value = DocumentUploadResult(success=True, document_id="doc-9")
        process_all.return_value = []
        run_pipeline(config)

    assert [call.args[0] for call in step_header.call_args_list] == [1, 2]
