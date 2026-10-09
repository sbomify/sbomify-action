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

from sbomify_action._generation.utils import error_signature, log_command_error, run_command
from sbomify_action._upload.destinations.dependency_track import (
    DependencyTrackConfig,
    DependencyTrackDestination,
)
from sbomify_action._upload.protocol import UploadInput
from sbomify_action._upload.result import UploadResult
from sbomify_action.cli.main import (
    _format_search_locations,
    _is_auth_failure,
    directory_expansion,
    path_expansion,
)
from sbomify_action.exceptions import (
    APIError,
    AuthError,
    DockerImageNotFoundError,
    DuplicateArtifactError,
    FileProcessingError,
    InputPathNotFoundError,
    OIDCBindingMissingError,
    OIDCError,
    OIDCExchangeError,
    SBOMGenerationError,
)
from sbomify_action.logging_config import TELEMETRY_SKIP_KEY, already_reported
from sbomify_action.oidc import exchange_for_sbomify_token
from sbomify_action.serialization import (
    _canonical_spdx_license_id,
    _is_valid_spdx_license_id,
    sanitize_cyclonedx_licenses,
)
from sbomify_action.validation import validate_sbom_data


def _exchange_failure(status: int) -> OIDCError:
    """The ``OIDCError`` the exchange raises for ``status``, no network.

    Driven through the real function so the classification under test is the
    shipped one, not a restatement of it.
    """

    class _Response:
        status_code = status
        text = "{}"

        @staticmethod
        def json() -> dict[str, str]:
            return {"detail": "nope"}

    def _post(*_args: object, **_kwargs: object) -> _Response:
        return _Response()

    import sbomify_action.oidc as oidc_module

    original_post = oidc_module.requests.post
    original_sleep = oidc_module.time.sleep
    oidc_module.requests.post = _post  # type: ignore[assignment]
    oidc_module.time.sleep = lambda _s: None  # type: ignore[assignment]
    try:
        with pytest.raises(OIDCError) as raised:
            exchange_for_sbomify_token("jwt", "cmpnt", "https://app.sbomify.com")
        return raised.value
    finally:
        oidc_module.requests.post = original_post  # type: ignore[assignment]
        oidc_module.time.sleep = original_sleep  # type: ignore[assignment]


def _dependency_track_upload_without_a_project(tmp_path: Path) -> UploadResult:
    """A dependency-track upload with neither a project id nor a name/version."""
    destination = DependencyTrackDestination(
        DependencyTrackConfig(api_key="k", api_url="https://dtrack.example.com/api", project_id=None)
    )
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}')
    return destination.upload(
        UploadInput(
            sbom_file=str(sbom),
            sbom_format="cyclonedx",
            component_name=None,
            component_version=None,
        )
    )


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


class TestBareLicenseTextReachesEveryParser:
    """GITHUB-ACTION-FW — one component's copyright header ended the run.

    cdxgen writes the licence body straight into ``license.text``, where the
    CycloneDX schema wants an attachedText object. cyclonedx-python-lib calls
    ``.items()`` on it while deserializing, so the whole document fails with
    ``AttributeError: 'str' object has no attribute 'items'`` -- naming
    neither the component nor the field.

    ``sanitize_cyclonedx_licenses`` has wrapped that string since the last
    sweep, but only where someone remembered to call it. Four of the six
    ``Bom.from_json`` call sites did; hash enrichment and dependency expansion
    did not, and both still died on this payload. They parse the document the
    user supplied, so neither is an unreachable path.
    """

    #: The shape from the real event: a licence name the schema accepts, and a
    #: copyright line where an attachedText object belongs.
    SBOM: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "re2",
                "version": "2022-06-01",
                "purl": "pkg:generic/re2@2022-06-01",
                "licenses": [{"license": {"name": "BSD-3-Clause", "text": "Copyright 2022 Google"}}],
            }
        ],
    }

    def _sbom_file(self, tmp_path: Path) -> Path:
        import json

        path = tmp_path / "sbom.json"
        path.write_text(json.dumps(self.SBOM))
        return path

    def test_the_loader_parses_what_the_raw_deserializer_refuses(self) -> None:
        import copy

        from cyclonedx.model.bom import Bom

        from sbomify_action.serialization import load_cyclonedx_bom

        with pytest.raises(AttributeError):
            Bom.from_json(copy.deepcopy(self.SBOM))  # type: ignore[attr-defined]

        bom = load_cyclonedx_bom(copy.deepcopy(self.SBOM))
        assert len(bom.components) == 1

    def test_hash_enrichment_survives_it(self, tmp_path: Path) -> None:
        from sbomify_action._hash_enrichment.enricher import enrich_sbom_with_hashes

        lock_file = tmp_path / "uv.lock"
        lock_file.write_text("")

        # Raised AttributeError from Bom.from_json before the loader existed.
        enrich_sbom_with_hashes(str(self._sbom_file(tmp_path)), str(lock_file))

    def test_dependency_expansion_survives_it(self, tmp_path: Path) -> None:
        import copy

        from sbomify_action._dependency_expansion.enricher import DependencyEnricher

        # Same crash, second unguarded call site.
        DependencyEnricher()._enrich_cyclonedx(self._sbom_file(tmp_path), copy.deepcopy(self.SBOM), [], "test")

    def test_nothing_parses_a_cyclonedx_document_without_the_repair(self) -> None:
        """``Bom.from_json`` belongs to ``load_cyclonedx_bom`` and nowhere else.

        The repair and the parse were two statements a caller had to write in
        the right order, and two callers out of six did not. Keeping the raw
        deserializer to one function is what makes a seventh call site safe by
        construction rather than by review.
        """
        import ast

        package = Path(__file__).resolve().parents[1] / "sbomify_action"
        offenders: list[str] = []

        for path in sorted(package.rglob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                if node.func.attr != "from_json":
                    continue
                if getattr(node.func.value, "id", None) != "Bom":
                    continue
                enclosing = [
                    fn.name
                    for fn in ast.walk(tree)
                    if isinstance(fn, ast.FunctionDef) and fn.lineno <= node.lineno <= (fn.end_lineno or fn.lineno)
                ]
                if "load_cyclonedx_bom" in enclosing:
                    continue
                offenders.append(f"{path.relative_to(package)}:{node.lineno}")

        assert not offenders, (
            "Bom.from_json outside load_cyclonedx_bom (the licence repair is skipped there):\n  "
            + "\n  ".join(offenders)
        )


class TestEchoedFailuresAreReportedOnce:
    """GITHUB-ACTION-E5 (62 events) and MN (21): the project's two largest
    issues were both echoes.

    Step 5 logs each destination's failure, then raises, then logs the
    exception again as "Step 5 (upload) failed: Upload failed for
    destination(s): sbomify". Both records become events, so one occurrence
    opened two issues -- and the second one escaped the classification the
    first was judged on, because the wrapper message carries none of the
    detail ``_is_auth_failure`` matches on. Every single E5 event had a
    filtered ``[403]`` sitting in its breadcrumbs.
    """

    def test_the_marker_is_honoured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        before_send = _capture_before_send(monkeypatch)

        echo: dict[str, object] = {
            "logentry": {"formatted": "Step 5 (upload) failed: Upload failed for destination(s): sbomify"},
            "extra": {TELEMETRY_SKIP_KEY: True},
        }
        assert before_send(echo, {}) is None

        # The same message without the marker is still reported: the marker
        # is the whole of the decision, not the wording.
        unmarked: dict[str, object] = {
            "logentry": {"formatted": "Step 5 (upload) failed: Upload failed for destination(s): sbomify"},
        }
        assert before_send(unmarked, {}) is unmarked

    def test_an_event_with_no_extra_at_all_is_unaffected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``extra`` is absent on exception events and may be an explicit None."""
        before_send = _capture_before_send(monkeypatch)

        for event in ({"message": "boom"}, {"message": "boom", "extra": None}):
            assert before_send(dict(event), {}) is not None

    def test_already_reported_marks_only_what_was_reported(self) -> None:
        reported = SBOMGenerationError("syft command failed with return code 1")
        reported.telemetry_reported = True
        assert already_reported(reported) == {TELEMETRY_SKIP_KEY: True}

        # "No SBOM file found from previous step" surfaces for the first time
        # at the step boundary -- nothing logged it below, so it must report.
        assert already_reported(FileProcessingError("No SBOM file found from previous step")) is None

    def test_a_user_side_type_also_suppresses_its_echo(self) -> None:
        """GITHUB-ACTION-K4: "Step 1 failed: ... Docker image ... not found".

        ``before_send`` already dropped the raised ``DockerImageNotFoundError``;
        the one-line echo that followed it went to Sentry anyway.
        """
        assert already_reported(DockerImageNotFoundError("example.com/no-such-image:v1.0.0")) == {
            TELEMETRY_SKIP_KEY: True
        }

    def test_run_command_marks_what_it_logged(self) -> None:
        """The exception carries the flag only when an error record was emitted."""
        with pytest.raises(SBOMGenerationError) as logged:
            run_command(["false"], "syft", log_errors=True)
        assert logged.value.telemetry_reported is True

        # Priority-chain fallback logs at debug, so nothing has been reported
        # and the step boundary is the first and only chance to report it.
        with pytest.raises(SBOMGenerationError) as quiet:
            run_command(["false"], "syft", log_errors=False)
        assert quiet.value.telemetry_reported is False


class TestOidcFailuresAreClassifiedWhereTheyAreLogged:
    """GITHUB-ACTION-EG / F4 / JZ / M6 / MP / MQ / NP / NR (403) and
    GC / MR / NQ (404).

    ``before_send`` lists ``OIDCError`` among the types it drops, with a
    comment saying OIDC failures are user/setup issues. Every caller catches
    them and *logs* instead of letting them propagate, so there is no
    ``exc_info`` by the time Sentry looks -- the entry was dead code, and the
    403s kept arriving. The 403 message says "(403)" in parentheses, so the
    ``[403]`` marker test did not catch them either.
    """

    def test_a_missing_binding_is_user_side(self) -> None:
        assert OIDCBindingMissingError("no binding").user_side is True

    @pytest.mark.parametrize("status", [401, 403, 404, 429])
    def test_the_exchange_classifies_user_side_statuses(self, status: int) -> None:
        exc = _exchange_failure(status)
        assert exc.user_side is True, f"HTTP {status} should not be reported as a defect"

    @pytest.mark.parametrize("status", [500, 502, 503])
    def test_backend_outages_are_still_reported(self, status: int) -> None:
        """Same line ``_USER_SIDE_HTTP_STATUSES`` draws: a 5xx is ours."""
        assert _exchange_failure(status).user_side is False

    def test_no_runner_token_is_user_side(self) -> None:
        """A workflow missing `permissions: id-token: write` is configuration."""
        assert OIDCExchangeError("No OIDC token is available on GitHub Actions.", user_side=True).user_side is True

    def test_the_real_403_message_is_not_caught_by_the_marker_test(self) -> None:
        """Why the type had to carry the classification.

        The message ``oidc.py`` builds for a 403, with a placeholder
        component id. ``_is_auth_failure`` looks for ``[403]``; this says
        ``(403)``, so the marker test reports False and the record went to
        Sentry as a defect.
        """
        assert (
            _is_auth_failure(
                "sbomify rejected the OIDC token (403): no binding found for component "
                "'aBcDeF123456' and this repository. Create an OIDC binding in the sbomify UI "
                "(Component → Settings → Trusted Publishing). Detail: repository not bound to this component"
            )
            is False
        )


class TestDependencyTrackConfiguration:
    """GITHUB-ACTION-MM, 12 events: DTRACK_PROJECT_ID was never set.

    The user asked for the dependency-track destination without the inputs it
    needs. Nothing for the action to fix, and the message already names them.
    """

    def test_the_failure_is_coded_as_configuration(self, tmp_path: Path) -> None:
        result = _dependency_track_upload_without_a_project(tmp_path)
        assert result.success is False
        assert result.error_code == "CONFIGURATION_ERROR"
        assert "DTRACK_PROJECT_ID" in (result.error_message or "")
