"""Custom exceptions for sbomify-action."""


class SbomifyError(Exception):
    """Base exception for all sbomify operations.

    Attributes:
        telemetry_reported: set by the layer that raises when it has already
            logged this failure at error level -- and so already offered it
            to Sentry. The step handler that catches it logs its own one-line
            echo as "already accounted for" rather than as a second
            occurrence. See ``logging_config.already_reported``.
    """

    telemetry_reported = False

    #: Set on types that describe something the *user* changes -- a wrong
    #: path, an image that does not exist, a token that is not allowed -- as
    #: opposed to a defect in the action. ``initialize_sentry`` drops these,
    #: and so does any step-level echo of one: before this existed the type
    #: filter caught the exception while the one-line "Step N failed: ..."
    #: record that followed sailed straight through.
    user_side = False


class ConfigurationError(SbomifyError):
    """Raised when configuration validation fails."""

    user_side = True


class SBOMGenerationError(SbomifyError):
    """Raised when SBOM generation fails.

    Attributes:
        stderr: The stderr output from the failed command (if available)
        stdout: The stdout output from the failed command (if available)
        returncode: The exit code from the failed command (if available)
    """

    def __init__(
        self,
        message: str,
        stderr: str = "",
        stdout: str = "",
        returncode: int | None = None,
    ):
        self.stderr = stderr
        self.stdout = stdout
        self.returncode = returncode
        super().__init__(message)


class DockerImageNotFoundError(SBOMGenerationError):
    """Raised when a Docker image cannot be found in any registry.

    This error is raised when SBOM generation tools (trivy, syft, cdxgen) fail
    because the specified Docker image doesn't exist or the tag is invalid.

    Attributes:
        image: The Docker image that was not found
        message: Detailed error message
    """

    user_side = True

    def __init__(
        self,
        image: str,
        message: str | None = None,
        stderr: str = "",
        stdout: str = "",
        returncode: int | None = None,
    ):
        self.image = image
        if message:
            super().__init__(message, stderr=stderr, stdout=stdout, returncode=returncode)
        else:
            super().__init__(
                f"Docker image '{image}' not found. Verify the image exists in the registry and the tag is correct.",
                stderr=stderr,
                stdout=stdout,
                returncode=returncode,
            )


class ToolNotAvailableError(SBOMGenerationError):
    """Raised when no SBOM generation tools are available for the input.

    This error occurs when sbomify-action is installed via pip but the user
    hasn't installed any of the required external tools (trivy, syft, cdxgen).
    """

    user_side = True

    def __init__(self, input_type: str, lock_file: str | None = None, message: str | None = None):
        self.input_type = input_type
        self.lock_file = lock_file
        super().__init__(message or f"No SBOM generation tools available for {input_type}")


class SBOMValidationError(SbomifyError):
    """Raised when SBOM validation fails."""

    user_side = True


class APIError(SbomifyError):
    """Raised when API operations fail."""


class AuthError(APIError):
    """Raised when the sbomify API rejects credentials (401)."""

    user_side = True


class ForbiddenError(APIError):
    """Raised when the sbomify API returns 403 — authenticated but not
    permitted (e.g. a workspace-scoped token reaching a workspace outside
    its scope). Distinct from ``AuthError`` (401, bad credentials) so callers
    can tell "this token can't touch this resource" apart from a transient
    failure and react accordingly."""

    user_side = True


class PlanLimitError(APIError):
    """Raised when an API operation fails due to plan limits (e.g., max components).

    ``resource`` names what hit the limit (``"product"`` or ``"component"``)
    so UI layers (e.g. the wizard's apply screen) can offer a targeted
    recovery path — reuse an existing product vs. reuse existing components.
    """

    def __init__(self, message: str, *, resource: str | None = None) -> None:
        super().__init__(message)
        self.resource = resource


class DuplicateArtifactError(APIError):
    """Raised when every upload failure was "this version already exists".

    An expected outcome, not a defect: re-running a workflow on the same
    commit, or two triggers racing on one push, both land here. The run
    still fails so the user knows nothing new was published, but it is
    filtered out of telemetry the same way the other user-side conditions
    are — see ``initialize_sentry``. It accounted for ~10% of all reported
    events before being classified.
    """

    user_side = True


class OIDCError(APIError):
    """Base exception for OIDC trusted-publishing failures.

    Attributes:
        user_side: whether this is something the user fixes -- a binding that
            was never created, a component id that is wrong, a workflow that
            does not grant ``id-token: write`` -- rather than a defect or an
            outage. Telemetry needs the distinction stated here because every
            caller *logs* these and exits: by the time Sentry sees the event
            there is no exception left to type-check, so listing ``OIDCError``
            in ``before_send``'s type filter never fired for any of them.
    """


class OIDCBindingMissingError(OIDCError):
    """Raised when the sbomify backend has no OIDC binding for the (component, repo) pair.

    The user must create an OIDC binding for the component in the sbomify UI before
    trusted publishing will work from this repository.
    """

    user_side = True


class OIDCExchangeError(OIDCError):
    """Raised when the OIDC -> sbomify token exchange fails for any other reason
    (invalid OIDC token, rate limit, backend unavailable, etc.).

    ``user_side`` is per-raise here because the cases genuinely differ: a 404
    on the component id or a workflow with no ``id-token: write`` is the
    caller's to fix, while a 5xx or a malformed response is the backend
    falling over and is worth knowing about -- the same line
    ``_USER_SIDE_HTTP_STATUSES`` draws for upload failures.
    """

    def __init__(self, message: str, *, user_side: bool = False):
        self.user_side = user_side
        super().__init__(message)


class FileProcessingError(SbomifyError):
    """Raised when file operations fail."""


class InputPathNotFoundError(FileProcessingError):
    """Raised when the path the *user* named does not exist.

    A distinct type only so telemetry can tell it apart. "You pointed
    LOCK_FILE at a file that is not there" is a user-side condition like the
    others ``initialize_sentry`` filters -- the run still fails and the user
    still gets the message naming every location searched, but it is not a
    defect in the action and does not belong in Sentry.

    Deliberately narrow: it covers the paths a user supplies, not every
    missing file. "No SBOM file found from previous step" stays a plain
    ``FileProcessingError``, because that one *is* a bug in the pipeline.
    """

    user_side = True


class CommandExecutionError(SbomifyError):
    """Raised when external command execution fails."""
