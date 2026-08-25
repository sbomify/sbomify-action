"""Regressions for failures observed in production telemetry.

Each test here reproduces a specific issue from the `github-action` Sentry
project. The Sentry short-id is quoted so the issue can be found again; the
payloads are the ones from the real events, not invented equivalents.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
import sentry_sdk

from sbomify_action._generation.utils import error_signature, log_command_error
from sbomify_action.cli.main import (
    _format_search_locations,
    _is_auth_failure,
    directory_expansion,
    path_expansion,
)
from sbomify_action.exceptions import (
    APIError,
    AuthError,
    DuplicateArtifactError,
    FileProcessingError,
    InputPathNotFoundError,
)
from sbomify_action.serialization import (
    _canonical_spdx_license_id,
    _is_valid_spdx_license_id,
    sanitize_cyclonedx_licenses,
)
from sbomify_action.validation import validate_sbom_data


def _capture_fingerprints(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Record every Sentry fingerprint set while logging, without a live SDK."""
    captured: list[list[str]] = []

    class _Scope:
        _fingerprint: list[str] = []

        @property
        def fingerprint(self) -> list[str]:
            return self._fingerprint

        @fingerprint.setter
        def fingerprint(self, value: list[str]) -> None:
            self._fingerprint = value
            captured.append(value)

        def __enter__(self) -> "_Scope":
            return self

        def __exit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(sentry_sdk, "new_scope", lambda: _Scope())
    return captured


def _capture_before_send(monkeypatch: pytest.MonkeyPatch) -> Callable[..., object]:
    """Return the real ``before_send``, which is defined inside initialize_sentry.

    Captured by intercepting the init call rather than duplicating the
    predicate here, so these tests exercise the shipped filter.
    """
    captured: dict[str, object] = {}

    def fake_init(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr("sentry_sdk.init", fake_init)
    monkeypatch.setattr("sentry_sdk.set_tag", lambda *a, **k: None)
    monkeypatch.setattr("sentry_sdk.set_context", lambda *a, **k: None)
    monkeypatch.delenv("TELEMETRY", raising=False)

    from sbomify_action.cli.main import initialize_sentry

    initialize_sentry()
    before_send = captured["before_send"]
    assert callable(before_send)
    return before_send


class TestNonSpdxLicenseIds:
    """GITHUB-ACTION-F0 / F1 / F2 — a run died on an unlisted license id.

    Enrichment emitted ``{'license': {'id': 'Libselinux-1.0'}}``; CycloneDX
    rejected it and step 3 aborted. The sanitizer that exists to move bad ids
    to ``license.name`` had passed it, because it asked
    ``license-expression`` (2447 keys, ScanCode's superset) rather than the
    SPDX license list the schema actually validates against (811 ids).
    """

    def test_scancode_only_key_is_not_a_valid_license_id(self) -> None:
        # ScanCode knows it; the SPDX list does not, under this spelling.
        assert _is_valid_spdx_license_id("LicenseRef-scancode-abrms") is False

    def test_licenseref_belongs_in_name_not_id(self) -> None:
        # Valid inside an SPDX *expression*, never a member of the id enum.
        assert _is_valid_spdx_license_id("LicenseRef-Liferay-DXP-EULA-2.0.0-2023-06") is False

    def test_real_spdx_ids_still_pass(self) -> None:
        for value in ("MIT", "Apache-2.0", "GPL-2.0-only", "BSD-3-Clause"):
            assert _is_valid_spdx_license_id(value) is True, value

    def test_wrong_casing_is_corrected_not_discarded(self) -> None:
        # 83 SPDX ids start lowercase, so casing is load-bearing. Demoting
        # these to license.name would lose a perfectly good identifier.
        assert _canonical_spdx_license_id("apache-2.0") == "Apache-2.0"
        assert _canonical_spdx_license_id("Libselinux-1.0") == "libselinux-1.0"

    def test_the_reported_payload_now_validates(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "libselinux",
                    "version": "3.8-3",
                    "licenses": [
                        {
                            "license": {
                                "id": "Libselinux-1.0",
                                "url": "https://sources.debian.org/src/libselinux/3.8-3/LICENSE/",
                            }
                        }
                    ],
                }
            ],
        }
        # Precondition: unsanitized, this is exactly the reported failure.
        assert validate_sbom_data(sbom, "cyclonedx", "1.6").valid is False

        sanitize_cyclonedx_licenses(sbom)
        assert validate_sbom_data(sbom, "cyclonedx", "1.6").valid is True
        # The id survives as the real SPDX identifier rather than being
        # demoted to a free-text name.
        licence = sbom["components"][0]["licenses"][0]["license"]
        assert licence["id"] == "libselinux-1.0"
        assert "name" not in licence

    def test_genuinely_unlisted_license_moves_to_name(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "thing",
                    "version": "1",
                    "licenses": [{"license": {"id": "Totally-Made-Up-1.0"}}],
                }
            ],
        }
        sanitize_cyclonedx_licenses(sbom)
        licence = sbom["components"][0]["licenses"][0]["license"]
        assert "id" not in licence
        assert licence["name"] == "Totally-Made-Up-1.0"
        assert validate_sbom_data(sbom, "cyclonedx", "1.6").valid is True


class TestSearchLocationMessage:
    """GITHUB-ACTION-DP — "Searched in: '/github/workspace/unpacked',
    '/github/workspace/unpacked'".

    Inside the container the working directory *is* /github/workspace, so the
    two locations the message reported were the same one twice — and the bare
    relative path, which is tried first, was never mentioned.
    """

    def test_identical_locations_are_reported_once(self) -> None:
        rendered = _format_search_locations(
            Path("unpacked"),
            Path("/github/workspace/unpacked"),
            Path("/github/workspace/unpacked"),
        )
        assert rendered.count("/github/workspace/unpacked") == 1
        assert "'unpacked'" in rendered

    def test_distinct_locations_are_all_reported(self) -> None:
        rendered = _format_search_locations(
            Path("unpacked"),
            Path("/somewhere/unpacked"),
            Path("/github/workspace/unpacked"),
        )
        assert rendered.count("'") == 6  # three quoted paths

    def test_missing_file_error_lists_each_location_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Reproduce the container's layout, where cwd IS the workspace and the
        # two "different" candidate locations collapse onto each other.
        import pathlib

        monkeypatch.setattr(pathlib.Path, "cwd", classmethod(lambda cls: pathlib.Path("/github/workspace")))
        with pytest.raises(FileProcessingError) as excinfo:
            path_expansion("unpacked")
        message = str(excinfo.value)
        assert message.count("/github/workspace/unpacked") == 1, message
        assert "'unpacked'" in message


class TestToolErrorGrouping:
    """23 Sentry issues for one cdxgen complaint.

    Log-derived events group by message, and the message was raw tool stderr
    — colour codes, paths and line numbers included — so each variant became
    its own issue.
    """

    SECURE_MODE_VARIANTS = [
        "\x1b[1;35mSECURE MODE: DO NOT run cdxgen with root privileges.\x1b[0m",
        "SECURE MODE: DO NOT run cdxgen with root privileges.",
        "\x1b[1;35mSECURE MODE: DO NOT run cdxgen with root privileges.\x1b[0m\nat /github/workspace/x",
    ]

    def test_ansi_and_volatile_variants_share_a_signature(self) -> None:
        signatures = {error_signature(variant) for variant in self.SECURE_MODE_VARIANTS}
        assert len(signatures) == 1, signatures

    def test_paths_and_line_numbers_do_not_split_a_group(self) -> None:
        first = error_signature("cdxgen failed at /github/workspace/a/b.json line 45")
        second = error_signature("cdxgen failed at /github/workspace/c/d.json line 912")
        assert first == second

    def test_genuinely_different_errors_stay_apart(self) -> None:
        assert error_signature("SECURE MODE: DO NOT run cdxgen with root privileges.") != error_signature(
            "Ensure docker/podman service or Docker for Desktop is running."
        )

    def test_empty_output_has_no_signature(self) -> None:
        assert error_signature("") == ""
        assert error_signature("\n  \n") == ""

    def test_error_level_actually_applies_the_fingerprint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The grouping is wired up, not merely available.

        The first version of this gated on ``log_fn is logger.error``. Attribute
        access builds a fresh bound method every time, so that identity check is
        always False and the fingerprint was never applied — while a test of
        ``error_signature`` alone still passed. Assert the wiring.
        """
        captured = _capture_fingerprints(monkeypatch)
        log_command_error("cdxgen", "\x1b[1;35mSECURE MODE: DO NOT run cdxgen with root privileges.\x1b[0m", "")
        assert captured, "error-level tool failures are not being fingerprinted"
        assert captured[0][:2] == ["tool-error", "cdxgen"]
        assert "SECURE MODE" in captured[0][2]

    def test_two_variants_of_one_failure_get_the_same_fingerprint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured = _capture_fingerprints(monkeypatch)
        for variant in self.SECURE_MODE_VARIANTS:
            log_command_error("cdxgen", variant, "")
        assert len(captured) == len(self.SECURE_MODE_VARIANTS)
        assert len({tuple(f) for f in captured}) == 1, captured

    @pytest.mark.parametrize("level", ["debug", "warning"])
    def test_non_error_levels_are_not_fingerprinted(self, monkeypatch: pytest.MonkeyPatch, level: str) -> None:
        # Those don't become Sentry events, so there is nothing to group.
        captured = _capture_fingerprints(monkeypatch)
        log_command_error("cdxgen", "some failure", "", level=level)
        assert captured == []

    def test_ansi_is_stripped_from_the_logged_message(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("ERROR"):
            log_command_error("cdxgen", "\x1b[1;35mSECURE MODE\x1b[0m", "")
        assert "\x1b[" not in caplog.text
        assert "SECURE MODE" in caplog.text

    def test_a_broken_telemetry_scope_cannot_break_generation(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Reporting a tool failure must not be able to cause one.

        This runs on the SBOM generation error path. Losing the grouping is a
        cosmetic degradation; raising here would turn "the tool failed" into
        "sbomify-action crashed".
        """

        def exploding_scope():  # noqa: ANN202
            raise RuntimeError("sentry is having a bad day")

        monkeypatch.setattr(sentry_sdk, "new_scope", exploding_scope)
        with caplog.at_level("ERROR"):
            log_command_error("cdxgen", "the tool failed", "")
        # Still exactly one error record, carrying the real failure.
        errors = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(errors) == 1, [r.getMessage() for r in errors]
        assert "the tool failed" in errors[0].getMessage()

    def test_the_error_is_logged_exactly_once_when_grouping_works(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _capture_fingerprints(monkeypatch)
        with caplog.at_level("ERROR"):
            log_command_error("cdxgen", "the tool failed", "")
        errors = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(errors) == 1, [r.getMessage() for r in errors]


class TestDuplicateArtifactClassification:
    """~10% of all reported events were "this version already exists".

    Re-running a workflow on the same commit lands here. The run should still
    fail — nothing new was published — but it is an expected outcome, so it
    is typed to be filtered from telemetry alongside the other user-side
    conditions.
    """

    def test_is_an_api_error_so_existing_handlers_still_catch_it(self) -> None:
        assert issubclass(DuplicateArtifactError, APIError)

    def test_is_filtered_by_before_send(self, monkeypatch: pytest.MonkeyPatch) -> None:
        before_send = _capture_before_send(monkeypatch)

        event: dict[str, object] = {"message": "Upload failed for destination(s): sbomify"}
        duplicate_hint = {"exc_info": (DuplicateArtifactError, DuplicateArtifactError("dup"), None)}
        assert before_send(event, duplicate_hint) is None

        # A real API failure still reaches Sentry.
        api_hint = {"exc_info": (APIError, APIError("boom"), None)}
        assert before_send(event, api_hint) is event


class TestMissingInputPathClassification:
    """GITHUB-ACTION-DP, 35 events: "Specified input file ... not found".

    The user pointed LOCK_FILE at something that is not there. The message
    already names every location searched; the stack trace behind it is not
    a defect in the action.
    """

    def test_is_a_file_processing_error_so_existing_handlers_still_catch_it(self) -> None:
        assert issubclass(InputPathNotFoundError, FileProcessingError)

    def test_path_expansion_raises_the_narrow_type(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.chdir(tmp_path)
        with pytest.raises(InputPathNotFoundError):
            path_expansion("definitely-not-here.json")

    def test_a_flag_shaped_path_raises_the_narrow_type(self) -> None:
        with pytest.raises(InputPathNotFoundError):
            path_expansion("--lock-file")

    def test_missing_source_directory_raises_the_narrow_type(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        with pytest.raises(InputPathNotFoundError):
            directory_expansion("no-such-dir")

    def test_a_pipeline_bug_is_still_reported(self) -> None:
        """ "No SBOM file found from previous step" is a defect, not user input."""
        assert not isinstance(FileProcessingError("No SBOM file found from previous step"), InputPathNotFoundError)

    def test_is_filtered_by_before_send(self, monkeypatch: pytest.MonkeyPatch) -> None:
        before_send = _capture_before_send(monkeypatch)

        event: dict[str, object] = {"message": "Specified input file 'package-lock.json' not found."}
        missing_hint = {
            "exc_info": (
                InputPathNotFoundError,
                InputPathNotFoundError("Specified input file 'package-lock.json' not found."),
                None,
            )
        }
        assert before_send(event, missing_hint) is None

        # A file failure that is genuinely ours still reaches Sentry.
        pipeline_hint = {
            "exc_info": (
                FileProcessingError,
                FileProcessingError("No SBOM file found from previous step"),
                None,
            )
        }
        assert before_send(event, pipeline_hint) is event


class TestAuthFailureClassification:
    """GITHUB-ACTION-GA / EA / EB / DB / DC / DS / DT (403) and DA (401).

    401 is a token that is missing, wrong or expired. 403 is a valid token
    refused the operation: a binding that was never created, a component in
    a different product. The backend's detail string says what to fix; the
    action cannot change either outcome.

    These arrive as *log records*, not exceptions — step 5 catches the
    APIError and logs it — so a type-based filter would silently do nothing.
    """

    def test_the_reported_messages_are_recognised(self) -> None:
        for message in (
            "Upload to sbomify failed: Failed to upload SBOM file. [403] - Forbidden",
            "Error processing release: Failed to create release. [403] - Component is not part of product",
            "sbomify rejected the OIDC token (403): no binding found [403] - nope",
            "Upload to sbomify failed: Authentication failed [401] - Unauthorized",
        ):
            assert _is_auth_failure(message) is True, message

    def test_other_statuses_are_left_alone(self) -> None:
        """A 500 is the backend falling over — that is worth knowing about."""
        for message in (
            "Failed to create release. [500] - Internal Server Error",
            "Failed to upload SBOM file. [404] - Not Found",
            "Everything is fine",
        ):
            assert _is_auth_failure(message) is False, message

    def test_a_logged_403_is_filtered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        before_send = _capture_before_send(monkeypatch)

        # The shape Sentry's logging integration produces: no exc_info.
        event: dict[str, object] = {
            "logentry": {"formatted": "Upload to sbomify failed: Failed to upload SBOM file. [403] - Forbidden"}
        }
        assert before_send(event, {}) is None

    def test_a_logged_401_is_filtered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        before_send = _capture_before_send(monkeypatch)

        event: dict[str, object] = {
            "logentry": {"formatted": "Upload to sbomify failed: Authentication failed [401] - Unauthorized"}
        }
        assert before_send(event, {}) is None

    def test_a_raised_403_is_filtered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        before_send = _capture_before_send(monkeypatch)

        event: dict[str, object] = {"message": "Failed to create release. [403] - nope"}
        hint = {"exc_info": (APIError, APIError("Failed to create release. [403] - nope"), None)}
        assert before_send(event, hint) is None

    def test_a_raised_auth_error_is_filtered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """AuthError subclasses APIError, so the 401 path is covered too."""
        before_send = _capture_before_send(monkeypatch)

        event: dict[str, object] = {"message": "Authentication failed [401] - Unauthorized"}
        hint = {"exc_info": (AuthError, AuthError("Authentication failed [401] - Unauthorized"), None)}
        assert before_send(event, hint) is None

    def test_a_real_backend_failure_still_reaches_sentry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        before_send = _capture_before_send(monkeypatch)

        event: dict[str, object] = {"message": "Failed to create release. [500] - Internal Server Error"}
        hint = {"exc_info": (APIError, APIError("Failed to create release. [500] - Internal Server Error"), None)}
        assert before_send(event, hint) is event
