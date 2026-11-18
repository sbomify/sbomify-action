"""User-side upload and OIDC failures must not reach Sentry as error records.

Sentry's logging integration turns every error-level record into an event,
whatever exception sits under it. Two records slipped past ``before_send``:

* The step-level echo after a 401/403 upload. The per-destination record
  carries the ``[403]`` marker ``before_send`` keys on, but the echo only says
  ``Step 5 (upload) failed: Upload failed for destination(s): sbomify``.
* A missing OIDC binding. The exception type is filtered, but it is caught
  and logged, and its message says ``(403)``, not ``[403]``.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from sbomify_action._upload.result import UploadResult
from sbomify_action.cli.main import build_config, run_pipeline
from sbomify_action.exceptions import OIDCBindingMissingError

AUTHORED_VEX = (
    b'{"bomFormat": "CycloneDX", "specVersion": "1.6",'
    b' "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",'
    b' "version": 1, "vulnerabilities": [{"id": "CVE-2026-0001"}]}\n'
)


def _upload_config(tmp_path, monkeypatch, **overrides):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "authored.vex.cdx.json"
    src.write_bytes(AUTHORED_VEX)
    kwargs = dict(
        sbom_file=str(src),
        bom_type="vex",
        output_file="out.vex.json",
        token="t",
        component_id="comp-1",
        upload=True,
        upload_destinations=["sbomify"],
    )
    kwargs.update(overrides)
    return build_config(**kwargs)


def _run_with_upload_result(config, result: UploadResult) -> None:
    with patch("sbomify_action.cli.main.upload_sbom", return_value=result):
        with pytest.raises(SystemExit) as exc:
            run_pipeline(config)
    assert exc.value.code == 1


def _step5_echo(caplog: pytest.LogCaptureFixture) -> logging.LogRecord:
    [record] = [r for r in caplog.records if r.getMessage().startswith("Step 5 (upload) failed")]
    return record


@pytest.mark.parametrize(
    ("message", "code"),
    [
        ("Failed to upload SBOM file. [403] - Forbidden", None),
        ("Authentication failed [401] - Unauthorized", "AUTH_FAILED"),
    ],
)
def test_a_refused_upload_echo_is_not_an_error(tmp_path, monkeypatch, caplog, message, code):
    config = _upload_config(tmp_path, monkeypatch)
    with caplog.at_level(logging.WARNING):
        _run_with_upload_result(config, UploadResult.failure_result("sbomify", message, error_code=code))

    assert _step5_echo(caplog).levelno == logging.WARNING


def test_a_server_failure_echo_is_still_an_error(tmp_path, monkeypatch, caplog):
    """A 500 is the backend falling over -- that one is worth knowing about."""
    config = _upload_config(tmp_path, monkeypatch)
    with caplog.at_level(logging.WARNING):
        _run_with_upload_result(
            config, UploadResult.failure_result("sbomify", "Failed to upload SBOM file. [500] - Server Error")
        )

    assert _step5_echo(caplog).levelno == logging.ERROR


def test_a_missing_oidc_binding_is_logged_as_a_configuration_error(tmp_path, monkeypatch, caplog):
    binding = OIDCBindingMissingError("sbomify rejected the OIDC token (403): no binding found for component 'c'")
    with (
        patch("sbomify_action.oidc.is_oidc_available", return_value=True),
        patch("sbomify_action.oidc.obtain_sbomify_token_via_oidc", side_effect=binding),
        caplog.at_level(logging.ERROR),
    ):
        config = _upload_config(tmp_path, monkeypatch, token=None)
        with pytest.raises(SystemExit) as exc:
            run_pipeline(config)

    assert exc.value.code == 1
    [record] = [r for r in caplog.records if "no binding found" in r.getMessage()]
    # The prefix is what before_send drops.
    assert record.getMessage().startswith("Configuration error:")
