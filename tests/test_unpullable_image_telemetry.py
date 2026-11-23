"""An image the registry will not hand over is the user's to fix, not ours.

Step 1 used to log it as a plain ``Step 1 failed`` error, which Sentry's
logging integration turns into an event, so every private image a runner was
not logged in to opened an issue in our error tracker. These run the real
pipeline with the generator stubbed, and check what reaches ``before_send``.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from sbomify_action.cli.main import build_config, run_pipeline
from sbomify_action.exceptions import DockerImageNotFoundError, SBOMGenerationError

IMAGE = "registry.example.com/team/app:1.0"


def _run_step_1(tmp_path, monkeypatch, caplog, error: Exception) -> list[logging.LogRecord]:
    monkeypatch.chdir(tmp_path)
    config = build_config(docker_image=IMAGE, upload=False, output_file="out.json")
    with (
        patch("sbomify_action._generation.chainguard.detect_chainguard_image", return_value=None),
        patch("sbomify_action.cli.main.generate_sbom", side_effect=error),
        caplog.at_level(logging.ERROR),
        pytest.raises(SystemExit) as exc,
    ):
        run_pipeline(config)
    assert exc.value.code == 1
    return [r for r in caplog.records if "Step 1 failed" in r.getMessage()]


def test_an_unpullable_image_is_logged_as_a_configuration_error(tmp_path, monkeypatch, caplog):
    records = _run_step_1(tmp_path, monkeypatch, caplog, DockerImageNotFoundError(image=IMAGE))

    assert records, "step 1 should still say why it failed"
    for record in records:
        # The prefix is what before_send drops; see initialize_sentry.
        assert record.getMessage().startswith("Configuration error: ")
        assert IMAGE in record.getMessage()


def test_a_generator_failure_on_an_image_is_still_reported(tmp_path, monkeypatch, caplog):
    records = _run_step_1(tmp_path, monkeypatch, caplog, SBOMGenerationError("syft crashed"))

    assert records
    assert not any(r.getMessage().startswith("Configuration error: ") for r in records)
