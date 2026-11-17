"""Test Sentry error filtering for user vs system errors."""

import json
import os
import unittest
from unittest.mock import patch

import sentry_sdk

from sbomify_action.cli.main import SBOMIFY_VERSION, initialize_sentry
from sbomify_action.exceptions import (
    ConfigurationError,
    ProjectResolutionError,
    SBOMGenerationError,
    SBOMValidationError,
)
from sbomify_action.logging_config import logger
from tests.conftest import NoNetworkTransport

# Use a bogus DSN to prevent any real Sentry events from being sent during tests
MOCK_SENTRY_DSN = "https://00000000000000000000000000000000@example.com/0000000"


def clear_sentry_state():
    """Helper to completely clear Sentry state between tests."""
    # Close the current client
    sentry_sdk.get_client().close()
    # Initialize with minimal config to reset state
    sentry_sdk.init()
    # Clear all scopes
    try:
        # Try to clear global scope (SDK v2.0+)
        sentry_sdk.get_global_scope().clear()
    except (AttributeError, TypeError):
        pass
    try:
        # Try to clear current scope
        sentry_sdk.Scope.get_current_scope().clear()
    except (AttributeError, TypeError):
        pass
    try:
        # Try to clear isolation scope
        sentry_sdk.get_isolation_scope().clear()
    except (AttributeError, TypeError):
        pass


class TestSentryFiltering(unittest.TestCase):
    def setUp(self):
        """Set up each test with a bogus Sentry DSN to prevent real events from being sent."""
        # Patch the environment to use a fake DSN and enable telemetry
        # (overriding the global TELEMETRY=false from conftest.py)
        self.env_patcher = patch.dict(
            os.environ,
            {
                "SENTRY_DSN": MOCK_SENTRY_DSN,
                "TELEMETRY": "true",  # Override global disable for Sentry tests
            },
        )
        self.env_patcher.start()

    def tearDown(self):
        """Clean up after each test."""
        self.env_patcher.stop()

    def test_sentry_filters_validation_errors(self):
        """
        Test that SBOMValidationError is filtered from Sentry.
        This represents user input errors that shouldn't be tracked.
        """
        initialize_sentry()

        # Get the before_send function that was registered (Sentry 2.x API)
        client = sentry_sdk.get_client()

        if client and client.options.get("before_send"):
            before_send = client.options["before_send"]

            # Create a mock event and hint with SBOMValidationError
            event = {"exception": {"values": [{"type": "SBOMValidationError"}]}}
            hint = {
                "exc_info": (
                    SBOMValidationError,
                    SBOMValidationError("Test validation error"),
                    None,
                )
            }

            # Should return None (filtered out)
            result = before_send(event, hint)
            self.assertIsNone(result, "SBOMValidationError should be filtered from Sentry")

    def test_sentry_filters_configuration_errors(self):
        """
        Test that ConfigurationError is filtered from Sentry.
        This represents user configuration errors.
        """
        initialize_sentry()

        client = sentry_sdk.get_client()

        if client and client.options.get("before_send"):
            before_send = client.options["before_send"]

            event = {"exception": {"values": [{"type": "ConfigurationError"}]}}
            hint = {
                "exc_info": (
                    ConfigurationError,
                    ConfigurationError("Test config error"),
                    None,
                )
            }

            result = before_send(event, hint)
            self.assertIsNone(result, "ConfigurationError should be filtered from Sentry")

    def test_sentry_filters_project_resolution_errors(self):
        """A project its package manager cannot read is the user's to fix."""
        initialize_sentry()

        before_send = sentry_sdk.get_client().options["before_send"]
        error = ProjectResolutionError("cargo-cyclonedx could not resolve this project")
        event = {"exception": {"values": [{"type": "ProjectResolutionError"}]}}

        self.assertIsNone(before_send(event, {"exc_info": (ProjectResolutionError, error, None)}))

    def test_sentry_filters_configuration_error_log_messages(self):
        """
        Test that log messages starting with 'Configuration error:' are filtered.
        These come through the logging integration, not as exceptions.
        """
        initialize_sentry()

        client = sentry_sdk.get_client()

        if client and client.options.get("before_send"):
            before_send = client.options["before_send"]

            # Test with 'message' field (common format)
            event_message = {"message": "Configuration error: sbomify API token is not defined"}
            hint = {}

            result = before_send(event_message, hint)
            self.assertIsNone(result, "Configuration error log message should be filtered from Sentry")

            # Test with 'logentry.formatted' field (alternative format)
            event_logentry = {"logentry": {"formatted": "Configuration error: missing required field"}}

            result = before_send(event_logentry, hint)
            self.assertIsNone(result, "Configuration error logentry should be filtered from Sentry")

            # Test that non-configuration error messages are NOT filtered
            event_other = {"message": "Some other error occurred"}

            result = before_send(event_other, hint)
            self.assertIsNotNone(result, "Non-configuration error messages should be sent to Sentry")

    def test_sentry_allows_generation_errors(self):
        """
        Test that SBOMGenerationError is NOT filtered from Sentry.
        This represents tool/system bugs that should be tracked.
        """
        initialize_sentry()

        client = sentry_sdk.get_client()

        if client and client.options.get("before_send"):
            before_send = client.options["before_send"]

            event = {"exception": {"values": [{"type": "SBOMGenerationError"}]}}
            hint = {
                "exc_info": (
                    SBOMGenerationError,
                    SBOMGenerationError("Test generation error"),
                    None,
                )
            }

            result = before_send(event, hint)
            self.assertIsNotNone(result, "SBOMGenerationError should be sent to Sentry")
            self.assertEqual(result, event)

    @patch.dict(
        os.environ,
        {
            "TELEMETRY": "true",  # Enable Sentry for this test
            "SENTRY_DSN": MOCK_SENTRY_DSN,
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "owner/test-repo",
            "GITHUB_WORKFLOW": "Test Workflow",
            "GITHUB_ACTION": "test-action",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "abc123def456789",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_NUMBER": "42",
            "GITHUB_REPOSITORY_VISIBILITY": "public",
        },
        clear=True,
    )
    def test_sentry_github_context_public_repo(self):
        """
        Test that GitHub context is properly set in Sentry for public repos.
        This ensures we can track which repo and workflow triggered errors.
        """
        clear_sentry_state()
        initialize_sentry()

        client = sentry_sdk.get_client()

        # Verify the release is set with the action version
        self.assertEqual(client.options.get("release"), f"sbomify-action@{SBOMIFY_VERSION}")

        # Capture an event to verify tags and context
        captured_event = None

        def capture_event(event, hint):
            nonlocal captured_event
            captured_event = event
            return event

        # Replace before_send to capture the event
        original_before_send = client.options.get("before_send")
        client.options["before_send"] = lambda event, hint: capture_event(
            original_before_send(event, hint) if original_before_send else event, hint
        )

        # Trigger a test event
        try:
            raise SBOMGenerationError("Test exception for context verification")
        except Exception:
            sentry_sdk.capture_exception()

        # Verify the event was captured
        self.assertIsNotNone(captured_event, "Event should have been captured")

        # Verify CI tags are present for public repos
        tags = captured_event.get("tags", {})
        self.assertEqual(tags.get("ci.repository"), "owner/test-repo")
        self.assertEqual(tags.get("ci.workflow"), "Test Workflow")
        self.assertEqual(tags.get("ci.ref"), "refs/heads/main")
        self.assertEqual(tags.get("ci.sha"), "abc123d")  # Short SHA
        self.assertEqual(tags.get("action.version"), SBOMIFY_VERSION)
        self.assertEqual(tags.get("repo.public"), "True")
        self.assertEqual(tags.get("ci.platform"), "github-actions")

        # Verify CI context is present
        contexts = captured_event.get("contexts", {})
        ci_context = contexts.get("ci", {})
        self.assertEqual(ci_context.get("repository"), "owner/test-repo")
        self.assertEqual(ci_context.get("workflow"), "Test Workflow")
        self.assertEqual(ci_context.get("action"), "test-action")
        self.assertEqual(ci_context.get("ref"), "refs/heads/main")
        self.assertEqual(ci_context.get("sha"), "abc123def456789")
        self.assertEqual(ci_context.get("run_id"), "12345")
        self.assertEqual(ci_context.get("run_number"), "42")

    @patch.dict(
        os.environ,
        {
            "TELEMETRY": "true",  # Enable Sentry for this test
            "SENTRY_DSN": MOCK_SENTRY_DSN,
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "owner/private-repo",
            "GITHUB_WORKFLOW": "Secret Workflow",
            "GITHUB_ACTION": "secret-action",
            "GITHUB_REF": "refs/heads/feature/secret-feature",
            "GITHUB_SHA": "abc123def456789",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_NUMBER": "42",
            "GITHUB_REPOSITORY_VISIBILITY": "private",
        },
        clear=True,
    )
    def test_sentry_github_context_private_repo(self):
        """
        Test that GitHub context is NOT sent for private repos (privacy protection).
        This ensures sensitive repo names, workflows, and branches aren't leaked.
        """
        clear_sentry_state()
        initialize_sentry()

        client = sentry_sdk.get_client()

        # Verify the release is set with the action version (always safe)
        self.assertEqual(client.options.get("release"), f"sbomify-action@{SBOMIFY_VERSION}")

        # Capture an event to verify tags and context
        captured_event = None

        def capture_event(event, hint):
            nonlocal captured_event
            captured_event = event
            return event

        # Replace before_send to capture the event
        original_before_send = client.options.get("before_send")
        client.options["before_send"] = lambda event, hint: capture_event(
            original_before_send(event, hint) if original_before_send else event, hint
        )

        # Trigger a test event
        try:
            raise SBOMGenerationError("Test exception for private repo")
        except Exception:
            sentry_sdk.capture_exception()

        # Verify the event was captured
        self.assertIsNotNone(captured_event, "Event should have been captured")

        # Verify CI tags are NOT present for private repos
        tags = captured_event.get("tags", {})
        self.assertIsNone(tags.get("ci.repository"), "Private repo name should not be sent")
        self.assertIsNone(tags.get("ci.workflow"), "Private workflow name should not be sent")
        self.assertIsNone(tags.get("ci.ref"), "Private branch name should not be sent")
        self.assertIsNone(tags.get("ci.sha"), "Private commit SHA should not be sent")
        self.assertEqual(tags.get("repo.public"), "False")
        self.assertEqual(tags.get("ci.platform"), "github-actions")

        # Verify action version is still present (not sensitive)
        self.assertEqual(tags.get("action.version"), SBOMIFY_VERSION)

        # Verify CI context is NOT present
        contexts = captured_event.get("contexts", {})
        ci_context = contexts.get("ci", {})
        self.assertEqual(ci_context, {}, "No CI context should be sent for private repos")

    def test_sentry_non_github_environment(self):
        """
        Test that GitHub context is NOT sent when running outside GitHub Actions.
        This handles local runs, Bitbucket Pipelines, GitLab CI, etc.
        """
        clear_sentry_state()

        # Initialize without any GitHub environment variables
        # but with telemetry enabled for this test
        with patch.dict(os.environ, {"TELEMETRY": "true", "SENTRY_DSN": MOCK_SENTRY_DSN}, clear=True):
            initialize_sentry()

            client = sentry_sdk.get_client()

            # Verify the release is set with the action version (always safe)
            self.assertEqual(client.options.get("release"), f"sbomify-action@{SBOMIFY_VERSION}")

            # Capture an event to verify tags and context
            captured_event = None

            def capture_event(event, hint):
                nonlocal captured_event
                captured_event = event
                return event

            # Replace before_send to capture the event
            original_before_send = client.options.get("before_send")
            client.options["before_send"] = lambda event, hint: capture_event(
                original_before_send(event, hint) if original_before_send else event, hint
            )

            # Trigger a test event
            try:
                raise SBOMGenerationError("Test exception outside GitHub Actions")
            except Exception:
                sentry_sdk.capture_exception()

            # Verify the event was captured
            self.assertIsNotNone(captured_event, "Event should have been captured")

            # Verify CI tags are NOT present
            tags = captured_event.get("tags", {})
            self.assertIsNone(tags.get("ci.repository"), "Repo name should not be sent outside CI")
            self.assertIsNone(tags.get("ci.workflow"), "Workflow name should not be sent outside CI")
            self.assertIsNone(tags.get("ci.ref"), "Branch name should not be sent outside CI")
            self.assertIsNone(tags.get("ci.sha"), "Commit SHA should not be sent outside CI")
            self.assertIsNone(tags.get("repo.public"), "Public repo tag not set outside CI")

            # CI platform should indicate unknown
            self.assertEqual(tags.get("ci.platform"), "unknown")
            # The platform is named additively, so saved searches keyed on
            # ci.platform:unknown keep matching while the detail is available.
            self.assertEqual(tags.get("ci.vendor"), "local")

            # Verify action version is still present (not sensitive)
            self.assertEqual(tags.get("action.version"), SBOMIFY_VERSION)

            # Verify CI context is NOT present
            contexts = captured_event.get("contexts", {})
            ci_context = contexts.get("ci", {})
            self.assertEqual(ci_context, {}, "No CI context should be sent outside CI/CD platforms")

    @patch.dict(
        os.environ,
        {
            "TELEMETRY": "true",  # Enable Sentry for this test
            "SENTRY_DSN": MOCK_SENTRY_DSN,
            "GITLAB_CI": "true",
            "CI_PROJECT_PATH": "group/test-project",
            "CI_PROJECT_VISIBILITY": "public",
            "CI_PIPELINE_SOURCE": "push",
            "CI_COMMIT_REF_NAME": "main",
            "CI_COMMIT_SHORT_SHA": "abc123d",
            "CI_PIPELINE_ID": "12345",
            "CI_JOB_NAME": "test-job",
        },
        clear=True,
    )
    def test_sentry_gitlab_public_project(self):
        """
        Test that GitLab CI context is properly set for public projects.
        """
        clear_sentry_state()
        initialize_sentry()

        client = sentry_sdk.get_client()

        # Verify the release is set with the action version
        self.assertEqual(client.options.get("release"), f"sbomify-action@{SBOMIFY_VERSION}")

        # Capture an event to verify tags and context
        captured_event = None

        def capture_event(event, hint):
            nonlocal captured_event
            captured_event = event
            return event

        original_before_send = client.options.get("before_send")
        client.options["before_send"] = lambda event, hint: capture_event(
            original_before_send(event, hint) if original_before_send else event, hint
        )

        try:
            raise SBOMGenerationError("Test exception in GitLab CI")
        except Exception:
            sentry_sdk.capture_exception()

        self.assertIsNotNone(captured_event, "Event should have been captured")

        # Verify GitLab CI tags are present for public projects
        tags = captured_event.get("tags", {})
        self.assertEqual(tags.get("ci.repository"), "group/test-project")
        self.assertEqual(tags.get("ci.pipeline_source"), "push")
        self.assertEqual(tags.get("ci.ref"), "main")
        self.assertEqual(tags.get("ci.sha"), "abc123d")
        self.assertEqual(tags.get("repo.public"), "True")
        self.assertEqual(tags.get("ci.platform"), "gitlab-ci")

        # Verify CI context is present
        contexts = captured_event.get("contexts", {})
        ci_context = contexts.get("ci", {})
        self.assertEqual(ci_context.get("project"), "group/test-project")
        self.assertEqual(ci_context.get("pipeline_source"), "push")
        self.assertEqual(ci_context.get("ref"), "main")
        self.assertEqual(ci_context.get("sha"), "abc123d")
        self.assertEqual(ci_context.get("pipeline_id"), "12345")
        self.assertEqual(ci_context.get("job_name"), "test-job")

    @patch.dict(
        os.environ,
        {
            "TELEMETRY": "true",  # Enable Sentry for this test
            "SENTRY_DSN": MOCK_SENTRY_DSN,
            "GITLAB_CI": "true",
            "CI_PROJECT_PATH": "group/private-project",
            "CI_PROJECT_VISIBILITY": "private",
            "CI_COMMIT_REF_NAME": "feature/secret",
        },
        clear=True,
    )
    def test_sentry_gitlab_private_project(self):
        """
        Test that GitLab CI context is NOT sent for private projects.
        """
        clear_sentry_state()
        initialize_sentry()

        client = sentry_sdk.get_client()
        captured_event = None

        def capture_event(event, hint):
            nonlocal captured_event
            captured_event = event
            return event

        original_before_send = client.options.get("before_send")
        client.options["before_send"] = lambda event, hint: capture_event(
            original_before_send(event, hint) if original_before_send else event, hint
        )

        try:
            raise SBOMGenerationError("Test exception in private GitLab project")
        except Exception:
            sentry_sdk.capture_exception()

        self.assertIsNotNone(captured_event, "Event should have been captured")

        # Verify CI tags are NOT present for private projects
        tags = captured_event.get("tags", {})
        self.assertIsNone(tags.get("ci.repository"), "Private project name should not be sent")
        self.assertIsNone(tags.get("ci.ref"), "Private branch name should not be sent")
        self.assertEqual(tags.get("repo.public"), "False")
        self.assertEqual(tags.get("ci.platform"), "gitlab-ci")

        # Verify CI context is NOT present
        contexts = captured_event.get("contexts", {})
        ci_context = contexts.get("ci", {})
        self.assertEqual(ci_context, {}, "No CI context should be sent for private projects")

    @patch.dict(
        os.environ,
        {
            "TELEMETRY": "true",  # Enable Sentry for this test
            "SENTRY_DSN": MOCK_SENTRY_DSN,
            "BITBUCKET_PIPELINE_UUID": "{12345678-1234-1234-1234-123456789012}",
            "BITBUCKET_REPO_FULL_NAME": "owner/repo",
            "BITBUCKET_BRANCH": "main",
            "BITBUCKET_COMMIT": "abc123def456789",
        },
        clear=True,
    )
    def test_sentry_bitbucket_pipelines(self):
        """
        Test that Bitbucket Pipelines context is NOT sent (no visibility API).
        For privacy, we treat all Bitbucket repos as private by default.
        """
        clear_sentry_state()
        initialize_sentry()

        client = sentry_sdk.get_client()
        captured_event = None

        def capture_event(event, hint):
            nonlocal captured_event
            captured_event = event
            return event

        original_before_send = client.options.get("before_send")
        client.options["before_send"] = lambda event, hint: capture_event(
            original_before_send(event, hint) if original_before_send else event, hint
        )

        try:
            raise SBOMGenerationError("Test exception in Bitbucket Pipelines")
        except Exception:
            sentry_sdk.capture_exception()

        self.assertIsNotNone(captured_event, "Event should have been captured")

        # Verify CI tags are NOT present (treating as private by default)
        tags = captured_event.get("tags", {})
        self.assertIsNone(tags.get("ci.repository"), "Bitbucket repo name should not be sent")
        self.assertIsNone(tags.get("ci.ref"), "Bitbucket branch name should not be sent")
        self.assertEqual(tags.get("repo.public"), "False")
        self.assertEqual(tags.get("ci.platform"), "bitbucket-pipelines")

        # Verify CI context is NOT present
        contexts = captured_event.get("contexts", {})
        ci_context = contexts.get("ci", {})
        self.assertEqual(ci_context, {}, "No CI context should be sent for Bitbucket (no visibility API)")

    @patch.dict(
        os.environ,
        {
            # clear=True wipes setUp's patch, so both of these have to be
            # restated here or initialize_sentry runs with telemetry defaulting
            # to on and the production DSN it falls back to. Its six siblings
            # above restate them; this one did not, and for a month it was the
            # only thing in the live project still reporting a test exception.
            "TELEMETRY": "true",
            "SENTRY_DSN": MOCK_SENTRY_DSN,
            "TEAMCITY_VERSION": "2024.12",
            "BUILD_VCS_NUMBER": "abc123def4567890abc123def4567890abc123de",
            "TEAMCITY_PROJECT_NAME": "MyProject",
            "TEAMCITY_BUILDCONF_NAME": "Build",
        },
        clear=True,
    )
    def test_sentry_teamcity(self):
        """
        Test that TeamCity context is NOT sent (no visibility API).
        TeamCity is overwhelmingly on-premises, so we treat all repos as
        private by default -- same reasoning as Bitbucket.
        """
        clear_sentry_state()
        initialize_sentry()

        client = sentry_sdk.get_client()
        captured_event = None

        def capture_event(event, hint):
            nonlocal captured_event
            captured_event = event
            return event

        original_before_send = client.options.get("before_send")
        client.options["before_send"] = lambda event, hint: capture_event(
            original_before_send(event, hint) if original_before_send else event, hint
        )

        try:
            raise SBOMGenerationError("Test exception in TeamCity")
        except Exception:
            sentry_sdk.capture_exception()

        self.assertIsNotNone(captured_event, "Event should have been captured")

        tags = captured_event.get("tags", {})
        self.assertIsNone(tags.get("ci.repository"), "TeamCity project name should not be sent")
        self.assertIsNone(tags.get("ci.ref"), "TeamCity branch name should not be sent")
        self.assertEqual(tags.get("repo.public"), "False")
        self.assertEqual(tags.get("ci.platform"), "teamcity")

        contexts = captured_event.get("contexts", {})
        ci_context = contexts.get("ci", {})
        self.assertEqual(ci_context, {}, "No CI context should be sent for TeamCity (no visibility API)")

    @patch.dict(os.environ, {}, clear=True)
    def test_an_empty_environment_still_cannot_reach_the_live_project(self):
        """The fallback DSN is real; the transport under test is not.

        initialize_sentry falls back to the production DSN when SENTRY_DSN is
        unset, and that is the shipped behaviour -- a user who installs the
        action and sets nothing should get telemetry. What must not follow is
        that forgetting the variable in a test sends the test's own exceptions
        to that project, which is exactly what happened here.

        So this asserts the guard rather than the DSN: whatever init decides,
        the envelope stops in this process. The transport is checked before
        anything is captured, so a regression fails here rather than shipping
        the exception it was about to raise.
        """
        clear_sentry_state()
        initialize_sentry()

        client = sentry_sdk.get_client()
        self.assertIsInstance(client.transport, NoNetworkTransport)

        try:
            raise SBOMGenerationError("Stays in the process")
        except SBOMGenerationError:
            sentry_sdk.capture_exception()

        # Captured, and captured *here*: the filter still ran and still let a
        # generation error through, so the assertion those tests make is not
        # quietly passing because nothing happens any more.
        self.assertEqual(len(client.transport.envelopes), 1)

    @patch.dict(os.environ, {"TELEMETRY": "false"}, clear=True)
    def test_sentry_telemetry_disabled(self):
        """
        Test that Sentry can be completely disabled via TELEMETRY=false.
        This gives users full control over telemetry.
        """
        # Close any existing Sentry client and create a fresh one
        sentry_sdk.get_client().close()
        # Force creation of a new disabled client
        sentry_sdk.init()

        # Get the initial state
        client_before = sentry_sdk.get_client()
        release_before = client_before.options.get("release")

        # This should return early without initializing Sentry
        initialize_sentry()

        # Get the client after (should be same/unchanged)
        client_after = sentry_sdk.get_client()
        release_after = client_after.options.get("release")

        # Verify the release was not changed (telemetry should not have initialized)
        self.assertEqual(release_before, release_after, "Release should not change when telemetry is disabled")

        # Verify the release is not our custom release string
        self.assertNotEqual(
            release_after,
            f"sbomify-action@{SBOMIFY_VERSION}",
            "Custom release should not be set when telemetry is disabled",
        )


FAKE_HOME = "/home/telemetry-test-user"
FAKE_WORKSPACE = "/srv/ci/checkout/acme-app"
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjaSJ9.c2lnbmF0dXJl"


class TestTelemetryIsSafeAndDisclosed(unittest.TestCase):
    """What leaves the machine when telemetry is on, and that the user is told.

    Telemetry is on by default, so whoever installs the action has not chosen
    to send anything. These pin down that what is sent carries no hostname,
    command line, token or local path, and that the run says it is sending.
    """

    @patch.dict(os.environ, {"TELEMETRY": "true", "SENTRY_DSN": MOCK_SENTRY_DSN}, clear=True)
    def test_init_sends_no_pii_hostname_or_command_line_and_samples_a_tenth(self):
        clear_sentry_state()
        with patch.object(sentry_sdk, "init", wraps=sentry_sdk.init) as init:
            initialize_sentry()

        options = init.call_args.kwargs
        self.assertIs(options["send_default_pii"], False)
        self.assertEqual(options["traces_sample_rate"], 0.1)
        self.assertEqual(options["profiles_sample_rate"], 0.1)
        # No sentry-trace / baggage headers on requests to registries or a
        # user's Dependency-Track: they carry the release and the DSN key.
        self.assertEqual(options["trace_propagation_targets"], [])

        client = sentry_sdk.get_client()
        try:
            raise SBOMGenerationError("Stays in the process")
        except SBOMGenerationError:
            sentry_sdk.capture_exception()
        event = client.transport.envelopes[-1].get_event()

        # sentry-sdk fills an unset server_name from socket.gethostname(),
        # which on a developer laptop is the laptop's name.
        self.assertFalse(event.get("server_name"))
        # The argv integration would send the command line, --token included.
        self.assertNotIn("sys.argv", event.get("extra", {}))

    @patch.dict(
        os.environ,
        {
            "TELEMETRY": "true",
            "SENTRY_DSN": MOCK_SENTRY_DSN,
            "HOME": FAKE_HOME,
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": FAKE_WORKSPACE,
        },
        clear=True,
    )
    def test_tokens_and_local_paths_are_scrubbed_from_every_event(self):
        clear_sentry_state()
        initialize_sentry()
        client = sentry_sdk.get_client()

        logger.info(f"Reading {FAKE_HOME}/.config/sbomify with Bearer {FAKE_JWT}")
        logger.error(f"cdxgen failed in {FAKE_WORKSPACE}/src: Authorization: Bearer {FAKE_JWT}")
        try:
            raise SBOMGenerationError(f"Could not read {FAKE_HOME}/project/uv.lock (token {FAKE_JWT})")
        except SBOMGenerationError:
            sentry_sdk.capture_exception()

        events = [envelope.get_event() for envelope in client.transport.envelopes]
        log_event, exception_event = events[-2], events[-1]

        self.assertEqual(
            log_event["logentry"]["formatted"],
            "cdxgen failed in <workspace>/src: Authorization: Bearer [REDACTED]",
        )
        self.assertEqual(
            exception_event["exception"]["values"][0]["value"],
            "Could not read <home>/project/uv.lock (token [REDACTED-JWT])",
        )
        breadcrumbs = [crumb.get("message") for crumb in exception_event["breadcrumbs"]["values"]]
        self.assertIn("Reading <home>/.config/sbomify with Bearer [REDACTED]", breadcrumbs)

        # And nowhere else in either event, whichever field it hid in.
        sent = json.dumps(events)
        for leaked in (FAKE_JWT, FAKE_HOME, FAKE_WORKSPACE):
            self.assertNotIn(leaked, sent)

    @patch.dict(
        os.environ,
        {
            "TELEMETRY": "true",
            "SENTRY_DSN": MOCK_SENTRY_DSN,
            "HOME": FAKE_HOME,
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": FAKE_WORKSPACE,
        },
        clear=True,
    )
    def test_paths_in_log_params_extra_and_nested_breadcrumb_data_are_scrubbed(self):
        """Most libraries log ``"%s", path``, which keeps the raw path in params.

        The logging integration also copies ``extra=`` into the event's extra
        and into each breadcrumb's data, where it can sit nested in dicts and
        lists.
        """
        clear_sentry_state()
        initialize_sentry()
        client = sentry_sdk.get_client()

        logger.info("Resolved inputs", extra={"inputs": {"locks": [f"{FAKE_HOME}/project/uv.lock"]}})
        logger.error("Failed reading %s", f"{FAKE_HOME}/project/uv.lock", extra={"cwd": f"{FAKE_WORKSPACE}/src"})

        event = client.transport.envelopes[-1].get_event()
        self.assertEqual(event["logentry"]["params"], ["<home>/project/uv.lock"])
        self.assertEqual(event["extra"]["cwd"], "<workspace>/src")
        crumb = next(crumb for crumb in event["breadcrumbs"]["values"] if crumb.get("message") == "Resolved inputs")
        self.assertEqual(crumb["data"]["inputs"], {"locks": ["<home>/project/uv.lock"]})

        sent = json.dumps(event)
        for leaked in (FAKE_HOME, FAKE_WORKSPACE):
            self.assertNotIn(leaked, sent)

    @patch.dict(
        os.environ,
        {
            "TELEMETRY": "true",
            "SENTRY_DSN": MOCK_SENTRY_DSN,
            "GITHUB_ACTIONS": "true",
            # The image's WORKDIR: short enough to turn up inside URLs.
            "GITHUB_WORKSPACE": "/workspace",
        },
        clear=True,
    )
    def test_a_workspace_name_inside_a_url_is_left_alone(self):
        clear_sentry_state()
        initialize_sentry()
        client = sentry_sdk.get_client()

        logger.info("GET https://h/api/v1/workspaces 200")
        logger.info("GET https://h/workspace/settings 200")
        logger.error("cdxgen failed in /workspace/src and /workspace. Retry in /workspace")

        event = client.transport.envelopes[-1].get_event()
        self.assertEqual(
            event["logentry"]["formatted"],
            "cdxgen failed in <workspace>/src and <workspace>. Retry in <workspace>",
        )
        breadcrumbs = [crumb.get("message") for crumb in event["breadcrumbs"]["values"]]
        self.assertIn("GET https://h/api/v1/workspaces 200", breadcrumbs)
        self.assertIn("GET https://h/workspace/settings 200", breadcrumbs)

    @patch.dict(
        os.environ,
        {"TELEMETRY": "true", "SENTRY_DSN": MOCK_SENTRY_DSN, "HOME": FAKE_HOME},
        clear=True,
    )
    def test_a_home_path_is_scrubbed_after_a_flag_and_before_a_full_stop(self):
        """A home directory is never a URL fragment, so no boundary may spare it."""
        clear_sentry_state()
        initialize_sentry()
        client = sentry_sdk.get_client()

        logger.error(f"cc -I{FAKE_HOME}/include failed reading {FAKE_HOME}.")

        event = client.transport.envelopes[-1].get_event()
        self.assertEqual(event["logentry"]["formatted"], "cc -I<home>/include failed reading <home>.")

    @patch.dict(
        os.environ,
        {"TELEMETRY": "true", "SENTRY_DSN": MOCK_SENTRY_DSN, "HOME": FAKE_HOME},
        clear=True,
    )
    def test_a_sibling_of_home_loses_the_user_name_and_keeps_only_its_suffix(self):
        """/home/alice2 becomes <home>2: the suffix stays, the user name does not."""
        clear_sentry_state()
        initialize_sentry()
        client = sentry_sdk.get_client()

        logger.error(f"Copied {FAKE_HOME}-backup/x to {FAKE_HOME}2/x")

        event = client.transport.envelopes[-1].get_event()
        self.assertEqual(event["logentry"]["formatted"], "Copied <home>-backup/x to <home>2/x")
        self.assertNotIn(os.path.basename(FAKE_HOME), json.dumps(event))

    @patch.dict(os.environ, {"TELEMETRY": "true", "SENTRY_DSN": ""}, clear=True)
    def test_no_notice_when_the_dsn_is_empty(self):
        """An empty DSN sends nothing, so there is nothing to disclose."""
        clear_sentry_state()
        with patch.object(logger, "info") as info:
            initialize_sentry()
        self.assertFalse([call for call in info.call_args_list if "Telemetry is on" in str(call)])

    @patch.dict(os.environ, {"TELEMETRY": "true", "SENTRY_DSN": MOCK_SENTRY_DSN}, clear=True)
    def test_notice_is_printed_once_when_on_and_never_when_off(self):
        clear_sentry_state()
        with self.assertLogs("sbomify_action", level="INFO") as logs:
            initialize_sentry()
        notices = [line for line in logs.output if "--no-telemetry" in line]
        self.assertEqual(len(notices), 1, logs.output)
        self.assertIn("Sentry", notices[0])
        self.assertIn("example.com", notices[0])
        self.assertIn("TELEMETRY=false", notices[0])

        with patch.dict(os.environ, {"TELEMETRY": "false"}), self.assertNoLogs("sbomify_action", level="INFO"):
            initialize_sentry()


if __name__ == "__main__":
    unittest.main()
