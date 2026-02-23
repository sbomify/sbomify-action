"""Custom exceptions for sbomify-action."""


class SbomifyError(Exception):
    """Base exception for all sbomify operations."""


class ConfigurationError(SbomifyError):
    """Raised when configuration validation fails."""


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

    def __init__(self, input_type: str, lock_file: str | None = None, message: str | None = None):
        self.input_type = input_type
        self.lock_file = lock_file
        super().__init__(message or f"No SBOM generation tools available for {input_type}")


class SBOMValidationError(SbomifyError):
    """Raised when SBOM validation fails."""


class APIError(SbomifyError):
    """Raised when API operations fail."""


class PlanLimitError(APIError):
    """Raised when an API operation fails due to plan limits (e.g., max components)."""


class FileProcessingError(SbomifyError):
    """Raised when file operations fail."""


class CommandExecutionError(SbomifyError):
    """Raised when external command execution fails."""
