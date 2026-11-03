"""The pipeline hands SPDX to the upload with validation on, as it does CycloneDX.

Every SPDX 3 write path (overrides, additional packages, an empty SBOM,
augmentation, enrichment) runs before the upload, so the upload is the one
place a document the action wrote or passed through gets checked.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from sbomify_action._upload import UploadResult
from sbomify_action.cli.main import build_config, run_pipeline

SPDX3_FIXTURE = Path(__file__).parent / "test-data" / "spdx3_conformant.json"
CYCLONEDX = '{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}'


@pytest.mark.parametrize(
    ("name", "content", "sbom_format"),
    [("in.spdx3.json", SPDX3_FIXTURE.read_text(), "spdx"), ("in.cdx.json", CYCLONEDX, "cyclonedx")],
    ids=["spdx3", "cyclonedx"],
)
def test_the_upload_validates_both_formats(tmp_path, monkeypatch, name, content, sbom_format):
    monkeypatch.chdir(tmp_path)
    (tmp_path / name).write_text(content)
    config = build_config(token="t", component_id="c", sbom_file=str(tmp_path / name), output_file="out.json")

    with patch(
        "sbomify_action.cli.main.upload_sbom",
        return_value=UploadResult.success_result(destination_name="sbomify", sbom_id="s"),
    ) as upload:
        run_pipeline(config)

    assert upload.call_args.kwargs["sbom_format"] == sbom_format
    assert upload.call_args.kwargs["validate_before_upload"] is True
