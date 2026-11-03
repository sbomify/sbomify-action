"""Document upload to the sbomify platform.

Documents (a pentest report, a SOC 2 attestation, release notes, a signed
declaration of conformity) are artifacts a component carries alongside its
SBOMs, and the EU CRA, FDA and PCI DSS ask for several of them by name. They
are not BOMs: they are opaque bytes with their own metadata, they live on a
``document`` component, and the backend takes them at ``/api/v1/documents/``
rather than the artifact endpoint.

That is why this sits beside the destination plugins rather than being one.
``Destination.upload()`` speaks :class:`UploadInput`, which requires an SBOM
format and validates the payload as CycloneDX or SPDX — none of which is true
of a PDF. Only sbomify accepts documents, so the plugin indirection would buy
nothing anyway: Dependency Track has no endpoint to send one to.
"""

from __future__ import annotations

import mimetypes
import os
from dataclasses import dataclass
from pathlib import Path

from sbomify_action.exceptions import APIError, AuthError
from sbomify_action.logging_config import logger
from sbomify_action.sbomify_api import (
    VALID_COMPLIANCE_SUBCATEGORIES,
    VALID_DOCUMENT_TYPES,
    SbomifyApiClient,
    clean_validation_error,
)

# Default sbomify production API (kept in step with the SBOM destination).
SBOMIFY_PRODUCTION_API = "https://app.sbomify.com"

# Upload timeout in seconds (overridable via SBOMIFY_UPLOAD_TIMEOUT env var).
try:
    UPLOAD_TIMEOUT = int(os.environ.get("SBOMIFY_UPLOAD_TIMEOUT", "120"))
except ValueError:
    UPLOAD_TIMEOUT = 120

# The backend rejects anything larger (documents/apis.py). Checked here too so
# a 40-minute build doesn't end in a 400 that a stat() call could have called
# in advance.
MAX_DOCUMENT_SIZE = 50 * 1024 * 1024


@dataclass
class DocumentUploadInput:
    """Input parameters for a document upload.

    Attributes:
        document_file: Path to the document to upload
        name: Document name shown in sbomify (defaults to the file stem)
        version: Document version (the backend defaults to "1.0")
        document_type: Type recorded on the document; see VALID_DOCUMENT_TYPES
        description: Free-text description
        compliance_subcategory: nda/soc2/iso27001, only for document_type="compliance"
    """

    document_file: str
    name: str | None = None
    version: str = "1.0"
    document_type: str = "other"
    description: str = ""
    compliance_subcategory: str | None = None

    def __post_init__(self) -> None:
        """Validate input parameters."""
        if not self.document_file:
            raise ValueError("document_file is required")
        self.document_type = (self.document_type or "other").lower()
        if self.document_type not in VALID_DOCUMENT_TYPES:
            raise ValueError(
                f"Invalid document_type: {self.document_type}. "
                f"Must be one of: {', '.join(sorted(VALID_DOCUMENT_TYPES))}"
            )
        if self.compliance_subcategory:
            self.compliance_subcategory = self.compliance_subcategory.lower()
            if self.compliance_subcategory not in VALID_COMPLIANCE_SUBCATEGORIES:
                raise ValueError(
                    f"Invalid compliance_subcategory: {self.compliance_subcategory}. "
                    f"Must be one of: {', '.join(sorted(VALID_COMPLIANCE_SUBCATEGORIES))}"
                )
            # Validated before being dropped, so a typo is still a typo even on
            # a type that would discard the value. Cleared here rather than only
            # at the client boundary, so what the caller can read back is what
            # will actually be sent.
            if self.document_type != "compliance":
                logger.warning(
                    f"compliance_subcategory only applies to document_type='compliance'; "
                    f"ignoring it for document_type='{self.document_type}'."
                )
                self.compliance_subcategory = None
        else:
            self.compliance_subcategory = None
        if not self.version:
            self.version = "1.0"

    @property
    def resolved_name(self) -> str:
        """Name to record, falling back to the file name without its suffix."""
        if self.name:
            return self.name
        return Path(self.document_file).stem or Path(self.document_file).name


@dataclass
class DocumentUploadResult:
    """Result of a document upload.

    Deliberately separate from :class:`~sbomify_action._upload.result.UploadResult`:
    that one carries ``sbom_id``, ``validated`` and ``validation_error``, none of
    which mean anything for a PDF, and stuffing a document id into a field named
    ``sbom_id`` is exactly the kind of thing that later gets tagged into a
    release as the wrong artifact kind.
    """

    success: bool
    document_id: str | None = None
    error_message: str | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        """Validate result state."""
        if self.success and self.error_message:
            raise ValueError("Successful result should not have error_message")
        if not self.success and not self.error_message:
            raise ValueError("Failed result must have error_message")


def _guess_content_type(file_name: str) -> str:
    """Best-effort MIME type for the document, defaulting to octet-stream."""
    guessed, _ = mimetypes.guess_type(file_name)
    return guessed or "application/octet-stream"


def upload_document(
    input: DocumentUploadInput,
    *,
    token: str | None,
    component_id: str | None,
    api_base_url: str | None = None,
) -> DocumentUploadResult:
    """Upload a document to a sbomify ``document`` component.

    Args:
        input: What to upload, and the metadata to record with it
        token: sbomify API token
        component_id: Document component to upload to
        api_base_url: API base URL (defaults to production)

    Returns:
        DocumentUploadResult with the new document id on success.
    """
    if not token or not component_id:
        return DocumentUploadResult(
            success=False,
            error_message="sbomify document upload is not configured (missing token or component_id)",
        )

    path = Path(input.document_file)
    # stat() first: the size checks below are the reason a 2 GB file must not
    # reach read_bytes(), and reading it in only to reject it would defeat them.
    try:
        file_size = path.stat().st_size
    except FileNotFoundError:
        return DocumentUploadResult(success=False, error_message=f"Document file not found: {input.document_file}")
    except OSError as e:
        return DocumentUploadResult(success=False, error_message=f"Failed to read document file: {e}")

    if file_size > MAX_DOCUMENT_SIZE:
        return DocumentUploadResult(
            success=False,
            error_message=(
                f"Document is {file_size:,} bytes; sbomify accepts at most "
                f"{MAX_DOCUMENT_SIZE:,} bytes (50 MB) per document."
            ),
        )
    try:
        payload = path.read_bytes()
    except FileNotFoundError:
        return DocumentUploadResult(success=False, error_message=f"Document file not found: {input.document_file}")
    except OSError as e:
        return DocumentUploadResult(success=False, error_message=f"Failed to read document file: {e}")

    # st_size is a hint, not a promise -- a file can grow between the stat and
    # the read, and virtual files report 0 while having content -- so the
    # payload, not the stat, decides. Emptiness is only checked here for that
    # reason: rejecting a 0-byte stat early would save no memory and would
    # refuse a file that does have bytes to read.
    if len(payload) > MAX_DOCUMENT_SIZE:
        return DocumentUploadResult(
            success=False,
            error_message=(
                f"Document is {len(payload):,} bytes; sbomify accepts at most "
                f"{MAX_DOCUMENT_SIZE:,} bytes (50 MB) per document."
            ),
        )
    if not payload:
        return DocumentUploadResult(success=False, error_message=f"Document file is empty: {input.document_file}")

    name = input.resolved_name
    content_type = _guess_content_type(path.name)
    logger.info(
        f"Uploading document '{name}' ({input.document_type}, {len(payload):,} bytes, {content_type}) "
        f"to component: {component_id}"
    )

    client = SbomifyApiClient(api_base_url or SBOMIFY_PRODUCTION_API, token, timeout=UPLOAD_TIMEOUT)
    try:
        response = client.upload_document(
            component_id=str(component_id),
            document_payload=payload,
            name=name,
            version=input.version,
            document_type=input.document_type,
            description=input.description,
            compliance_subcategory=input.compliance_subcategory,
            filename=path.name,
            content_type=content_type,
        )
    except AuthError as e:
        # Same contract as the SBOM destination: 401 short-circuits inside the
        # client, so tag it with the error code log scrapers already key off.
        return DocumentUploadResult(success=False, error_message=str(e), error_code="AUTH_FAILED")
    except APIError as e:
        return DocumentUploadResult(success=False, error_message=str(e))

    if not response.ok:
        if response.status_code == 404:
            return DocumentUploadResult(
                success=False,
                error_message=(
                    "No document component with this ID exists. Documents upload to a component of type "
                    "'document' — verify COMPONENT_ID, and note that a component created for SBOMs "
                    "(type 'bom') cannot hold documents."
                ),
                error_code="COMPONENT_NOT_FOUND",
            )

        error_code = None
        err_msg = f"Failed to upload document. [{response.status_code}]"
        body = None
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            error_code = body.get("error_code")
            cleaned = clean_validation_error(body.get("detail"))
            if cleaned:
                err_msg += f" - {cleaned}"
        return DocumentUploadResult(success=False, error_message=err_msg, error_code=error_code)

    document_id = None
    try:
        data = response.json()
        if isinstance(data, dict):
            document_id = data.get("id") or data.get("document_id")
    except ValueError:
        logger.warning("Could not extract document ID from upload response")

    if document_id:
        logger.info(f"Document ID: {document_id}")
    logger.info("Document uploaded successfully to sbomify")

    return DocumentUploadResult(success=True, document_id=str(document_id) if document_id else None)
