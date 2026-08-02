"""Shared utilities for SBOM generation."""

import re
import subprocess
import threading
from pathlib import Path
from typing import Optional

from sbomify_action.exceptions import DockerImageNotFoundError, SBOMGenerationError
from sbomify_action.logging_config import logger
from sbomify_action.runtimes import ensure_runtime

# Track whether Java/Maven has been installed on-demand
_java_maven_installed = False
_java_maven_lock = threading.Lock()

# Track whether Go has been installed on-demand
_go_installed = False
_go_lock = threading.Lock()

# Lock file constants by ecosystem
PYTHON_LOCK_FILES = [
    "Pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
]

# Cargo.toml is the manifest fallback, mirroring pyproject.toml / package.json /
# go.mod in the other ecosystems. It matters for Rust in particular because
# `cargo new --lib` gitignores Cargo.lock by convention, so a library crate often
# has no lockfile committed at all -- without the manifest, such a repo looks like
# it contains no Rust to the wizard and to LOCK_FILE validation.
# Cargo.lock stays first and outranks it (see the wizard's _LOCKFILE_PRIORITY).
RUST_LOCK_FILES = ["Cargo.lock", "Cargo.toml"]

JAVASCRIPT_LOCK_FILES = [
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
]

RUBY_LOCK_FILES = ["Gemfile.lock"]

GO_LOCK_FILES = [
    "go.mod",
    "go.sum",
]

DART_LOCK_FILES = ["pubspec.lock"]
CPP_LOCK_FILES = ["conan.lock"]

JAVA_LOCK_FILES = [
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
]

PHP_LOCK_FILES = [
    "composer.json",
    "composer.lock",
]

DOTNET_LOCK_FILES = [
    "packages.lock.json",
]

SWIFT_LOCK_FILES = [
    "Package.swift",
    "Package.resolved",
]

ELIXIR_LOCK_FILES = ["mix.lock"]

SCALA_LOCK_FILES = ["build.sbt"]

TERRAFORM_LOCK_FILES = [".terraform.lock.hcl"]

# All supported lock files
ALL_LOCK_FILES = (
    PYTHON_LOCK_FILES
    + RUST_LOCK_FILES
    + JAVASCRIPT_LOCK_FILES
    + RUBY_LOCK_FILES
    + GO_LOCK_FILES
    + DART_LOCK_FILES
    + CPP_LOCK_FILES
    + JAVA_LOCK_FILES
    + PHP_LOCK_FILES
    + DOTNET_LOCK_FILES
    + SWIFT_LOCK_FILES
    + ELIXIR_LOCK_FILES
    + SCALA_LOCK_FILES
    + TERRAFORM_LOCK_FILES
)

# =============================================================================
# Tool-specific lock file support
# Each tool supports different ecosystems - this drives generator selection
# =============================================================================

# cyclonedx-py: Native Python generator - Python only
CYCLONEDX_PY_LOCK_FILES = PYTHON_LOCK_FILES

# cdxgen: Comprehensive multi-ecosystem support
# Excellent for Java (pom.xml, gradle), JavaScript, Python, Go, Rust, etc.
CDXGEN_LOCK_FILES = (
    PYTHON_LOCK_FILES
    + JAVASCRIPT_LOCK_FILES
    + JAVA_LOCK_FILES  # Best tool for Java/Gradle lock files
    # GO_LOCK_FILES is deliberately absent. cdxgen hits an internal purl error
    # on go.mod ("Invalid purl: name is a required field"): with
    # --fail-on-error it exits 1, and without it emits a document with 0
    # components. Syft reads the same go.mod/go.sum and returns 190. It has
    # never worked here -- the chain fell back to syft and the failure was
    # invisible. Routing to the tool that actually produces the better SBOM
    # is the whole point, so Go goes to syft directly.
    + RUST_LOCK_FILES
    + RUBY_LOCK_FILES
    + DART_LOCK_FILES
    + CPP_LOCK_FILES
    + PHP_LOCK_FILES
    + DOTNET_LOCK_FILES
    + SWIFT_LOCK_FILES
    + ELIXIR_LOCK_FILES
    + SCALA_LOCK_FILES
)

# Trivy: Good multi-ecosystem support
# Supports most common ecosystems but may have varying quality
TRIVY_LOCK_FILES = (
    PYTHON_LOCK_FILES
    + JAVASCRIPT_LOCK_FILES
    + GO_LOCK_FILES
    + RUST_LOCK_FILES
    + RUBY_LOCK_FILES
    + JAVA_LOCK_FILES
    + CPP_LOCK_FILES
    + PHP_LOCK_FILES
    + DOTNET_LOCK_FILES
)

# Syft: Good multi-ecosystem support
# Note: Java support is for compiled artifacts (jar/war/ear), not pom.xml/gradle
SYFT_LOCK_FILES = (
    PYTHON_LOCK_FILES
    + JAVASCRIPT_LOCK_FILES
    + GO_LOCK_FILES
    + RUST_LOCK_FILES
    + RUBY_LOCK_FILES
    + DART_LOCK_FILES
    + CPP_LOCK_FILES
    + PHP_LOCK_FILES
    + DOTNET_LOCK_FILES
    + SWIFT_LOCK_FILES
    + ELIXIR_LOCK_FILES
    + TERRAFORM_LOCK_FILES
)

# Default command timeout in seconds
DEFAULT_TIMEOUT = 1800  # 30 minutes (large Maven projects can take a while)

# Progress indicator interval in seconds
PROGRESS_INTERVAL = 60  # Log progress every minute


def log_command_error(command_name: str, stderr: str, stdout: str, level: str = "error") -> None:
    """
    Log command errors with a standardized format.

    Args:
        command_name: The name of the command that failed
        stderr: The stderr output from the command
        stdout: The stdout output from the command (some tools output errors here)
        level: Log level to use ("error", "warning", or "debug"). Default is
            "error". "debug" is used for failures inside a generator priority
            chain where a later generator is expected to succeed, so the
            failure is benign noise on the happy path.
    """
    # Prefer stderr, fall back to stdout (some tools like cdxgen output errors to stdout)
    output = stderr or stdout
    if output:
        message = f"[{command_name}] error: {output.strip()}"
        log_fn = {"debug": logger.debug, "warning": logger.warning}.get(level, logger.error)
        log_fn(message)


# Patterns that indicate a Docker image was not found in the registry
# These are common error messages from trivy, syft, cdxgen, and Docker itself
DOCKER_IMAGE_NOT_FOUND_PATTERNS = [
    r"MANIFEST_UNKNOWN",
    r"manifest unknown",
    r"manifest for .* not found",
    r"unable to find the specified image",
    r"No such image:",
    r"not found: manifest unknown",
    r"pull access denied",
    r"repository does not exist",
    r"name unknown: repository .* not found",
]


def detect_docker_image_not_found(stderr: str) -> bool:
    """
    Detect if an error message indicates a Docker image was not found.

    This function checks stderr output from SBOM generation tools (trivy, syft, cdxgen)
    for patterns that indicate the specified Docker image doesn't exist in any registry.

    Args:
        stderr: The stderr output from a failed command

    Returns:
        True if the error indicates the Docker image was not found, False otherwise

    Examples:
        >>> detect_docker_image_not_found("MANIFEST_UNKNOWN: manifest unknown")
        True
        >>> detect_docker_image_not_found("manifest for alpine:nonexistent not found")
        True
        >>> detect_docker_image_not_found("some other error")
        False
    """
    if not stderr:
        return False

    for pattern in DOCKER_IMAGE_NOT_FOUND_PATTERNS:
        if re.search(pattern, stderr, re.IGNORECASE):
            return True

    return False


# Patterns to identify key error lines in command output
# These patterns match anywhere in the line to handle prefixed output like:
# - "2024-01-28 10:00:00 ERROR: something failed" (timestamp prefix)
# - "[trivy] FATAL: scan failed" (tool prefix)
ERROR_LINE_PATTERNS = [
    r"\bFATAL\b",
    r"\bERROR\b",
    r"\berror:",
    r"\bError:",
    r"\bfailed:",
    r"\bunable to\b",
    r"\bcould not\b",
    r"\bcannot ",
]


def extract_error_summary(output: str | None, max_chars: int = 500) -> str:
    """
    Extract a concise error summary from command output.

    This function looks for lines containing error keywords (FATAL, ERROR, error:, etc.)
    and returns them as a summary. If no error lines are found, it returns a truncated
    version of the full output.

    Args:
        output: The stderr or stdout from a failed command
        max_chars: Maximum characters to include in the summary

    Returns:
        A string containing the most relevant error information, truncated to max_chars

    Examples:
        >>> extract_error_summary("INFO: Starting\\nFATAL: Something went wrong\\nINFO: Done")
        'FATAL: Something went wrong'
        >>> extract_error_summary("Some long output...", max_chars=10)
        'Some lo...'
    """
    if not output:
        return ""

    output = output.strip()

    # Try to find error-specific lines
    error_lines = []
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        for pattern in ERROR_LINE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                error_lines.append(line)
                break

    if error_lines:
        # Join error lines and truncate if needed
        summary = " | ".join(error_lines)
    else:
        # No specific error lines found, use the full output
        summary = output.replace("\n", " | ")

    # Truncate to max_chars
    if len(summary) > max_chars:
        summary = summary[: max_chars - 3] + "..."

    return summary


def run_command(
    cmd: list[str],
    command_name: str,
    timeout: int = DEFAULT_TIMEOUT,
    capture_output: bool = True,
    cwd: str | None = None,
    docker_image: str | None = None,
    log_errors: bool = True,
) -> subprocess.CompletedProcess[str]:
    """
    Run a command and handle common error cases.

    For long-running commands, logs progress every PROGRESS_INTERVAL seconds.

    Args:
        cmd: Command to run as a list
        command_name: Name of the command for error reporting
        timeout: Command timeout in seconds
        capture_output: Whether to capture stdout/stderr
        cwd: Working directory for the command (optional)
        docker_image: Docker image being scanned (optional, for better error messages)
        log_errors: When True (default), a failure (non-zero exit, timeout, or
            missing binary) logs at ERROR. Set
            False for a generator that runs inside the priority chain and is
            expected to fail gracefully when a higher-priority or fallback
            generator can still succeed (e.g. cdxgen on a Python lockfile,
            where cyclonedx-py/syft take over) — its failure is then logged
            at DEBUG so it doesn't spam ERROR on the happy path. The
            ``SBOMGenerationError`` is still raised either way; the
            orchestrator surfaces the real ERROR only if *every* generator
            in the chain fails.

    Returns:
        CompletedProcess result

    Raises:
        DockerImageNotFoundError: If the Docker image doesn't exist in the registry
        SBOMGenerationError: If command fails or times out for other reasons
    """
    import threading
    import time

    cwd_info = f" (cwd: {cwd})" if cwd else ""
    logger.info(f"Running command: {' '.join(cmd)}{cwd_info}")

    # Use Popen for progress tracking on long-running commands
    start_time = time.time()
    stop_progress = threading.Event()

    def log_progress() -> None:
        """Log progress periodically while command is running."""
        timeout_minutes = timeout // 60
        while not stop_progress.wait(PROGRESS_INTERVAL):
            elapsed = int(time.time() - start_time)
            minutes = elapsed // 60
            seconds = elapsed % 60
            logger.info(f"{command_name} still running... ({minutes}m {seconds}s elapsed, timeout: {timeout_minutes}m)")

    # Start progress thread
    progress_thread = threading.Thread(target=log_progress, daemon=True)
    progress_thread.start()

    try:
        # Safe by invariant: the executable (cmd[0]) is always an internal generator
        # constant ("syft", "cdxgen", "trivy", ...), never user-controlled. Untrusted
        # values (lockfile paths, image refs) reach only argv, and shell=False means
        # no shell parsing — so neither command nor shell injection is reachable.
        # nosemgrep: dangerous-subprocess-use-audit
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            check=True,
            text=True,
            shell=False,
            timeout=timeout,
            cwd=cwd,
        )
        return result
    except subprocess.CalledProcessError as e:
        stderr = e.stderr or ""
        stdout = e.stdout or ""

        # Check if this is a Docker image not found error (user configuration issue)
        # Log at WARNING level since this isn't a bug - user specified a non-existent image
        if docker_image and detect_docker_image_not_found(stderr):
            logger.warning(f"Docker image '{docker_image}' not found")
            log_command_error(command_name, stderr, stdout, level="warning")
            raise DockerImageNotFoundError(
                image=docker_image,
                message=(
                    f"Docker image '{docker_image}' not found. "
                    "Verify the image exists in the registry and the tag is correct."
                ),
                stderr=stderr,
                stdout=stdout,
                returncode=e.returncode,
            )

        # Other errors normally log at ERROR (potential bugs or system issues).
        # When the caller is a priority-chain generator that fails gracefully
        # (log_errors=False), drop to DEBUG so an expected fallback doesn't
        # spam red ERROR lines on the happy path — the SBOMGenerationError is
        # still raised, and the orchestrator logs ERROR only if all generators
        # fail.
        if log_errors:
            logger.error(f"{command_name} command failed with error: {e}")
            log_command_error(command_name, stderr, stdout)
        else:
            logger.debug(f"{command_name} command failed (trying next generator): {e}")
            log_command_error(command_name, stderr, stdout, level="debug")

        # Include error summary in the exception message for better diagnostics
        error_summary = extract_error_summary(stderr or stdout)
        message = f"{command_name} command failed with return code {e.returncode}"
        if error_summary:
            message += f": {error_summary}"

        raise SBOMGenerationError(
            message,
            stderr=stderr,
            stdout=stdout,
            returncode=e.returncode,
        )
    except subprocess.TimeoutExpired:
        elapsed = int(time.time() - start_time)
        # Honor log_errors here too: a cdxgen timeout on, say, a Python
        # lockfile is the same benign priority-chain fallback as a non-zero
        # exit — it shouldn't spam red ERROR when a later generator succeeds.
        timeout_msg = f"{command_name} command timed out after {elapsed}s (limit: {timeout}s)"
        logger.error(timeout_msg) if log_errors else logger.debug(timeout_msg)
        raise SBOMGenerationError(f"{command_name} command timed out")
    except FileNotFoundError:
        not_found_msg = f"{command_name} command not found"
        logger.error(not_found_msg) if log_errors else logger.debug(not_found_msg)
        raise SBOMGenerationError(f"{command_name} command not found - is it installed?")
    finally:
        # Stop the progress thread
        stop_progress.set()
        progress_thread.join(timeout=1)


def get_lock_file_ecosystem(lock_file_name: str) -> Optional[str]:
    """
    Get the ecosystem for a lock file.

    Args:
        lock_file_name: Name of the lock file

    Returns:
        Ecosystem name or None if not recognized
    """
    if lock_file_name in PYTHON_LOCK_FILES:
        return "python"
    elif lock_file_name in RUST_LOCK_FILES:
        return "rust"
    elif lock_file_name in JAVASCRIPT_LOCK_FILES:
        return "javascript"
    elif lock_file_name in RUBY_LOCK_FILES:
        return "ruby"
    elif lock_file_name in GO_LOCK_FILES:
        return "go"
    elif lock_file_name in DART_LOCK_FILES:
        return "dart"
    elif lock_file_name in CPP_LOCK_FILES:
        return "cpp"
    elif lock_file_name in JAVA_LOCK_FILES:
        return "java"
    elif lock_file_name in PHP_LOCK_FILES:
        return "php"
    elif lock_file_name in DOTNET_LOCK_FILES:
        return "dotnet"
    elif lock_file_name in SWIFT_LOCK_FILES:
        return "swift"
    elif lock_file_name in ELIXIR_LOCK_FILES:
        return "elixir"
    elif lock_file_name in SCALA_LOCK_FILES:
        return "scala"
    elif lock_file_name in TERRAFORM_LOCK_FILES:
        return "terraform"
    return None


# Lock files whose generator also needs the project manifest beside them.
#
# A lock file records resolved versions; the manifest names the project. Tools
# that build a root component from the manifest fail without it, and the
# failure is obscure:
#
#   Cargo.lock  without Cargo.toml    cargo metadata: manifest path ... does not exist
#   pubspec.lock without pubspec.yaml TypeError: Cannot read properties of
#                                     undefined (reading 'bom-ref')
#
# Both were being absorbed by the fallback chain, so the generator looked
# merely unlucky rather than mis-declared. Declining an input we cannot handle
# is a routing decision; claiming it and failing is a defect.
#
# Only pairs verified to matter are listed. Adding one on suspicion would
# silently narrow a generator's coverage.
LOCK_FILE_MANIFESTS = {
    "Cargo.lock": "Cargo.toml",
    "pubspec.lock": "pubspec.yaml",
}


def has_required_manifest(lock_file: str | None) -> bool:
    """Whether a lock file has the project manifest its generator needs."""
    if not lock_file:
        return True
    required = LOCK_FILE_MANIFESTS.get(Path(lock_file).name)
    if not required:
        return True
    return (Path(lock_file).parent / required).exists()


def is_supported_lock_file(lock_file_name: str) -> bool:
    """Check if a lock file is supported."""
    return lock_file_name in ALL_LOCK_FILES


def ensure_java_maven_installed() -> None:
    """Make a JDK and Maven available for Java/Scala dependency resolution.

    Previously this ran `apt-get install maven default-jdk-headless` during
    the run: whatever the Debian mirror happened to serve that day, requiring
    root, and recorded in no SBOM. Both are now pinned artifacts verified
    against the vendor's published digest and unpacked into an unprivileged
    prefix, so a release resolves Java projects with exactly the toolchain it
    was built against.
    """
    ensure_runtime("java")
    ensure_runtime("maven")


def ensure_go_installed() -> None:
    """Make the Go toolchain available for Go dependency resolution.

    Was `apt-get install golang`, with the same problems: unpinned, root-only
    and absent from every SBOM. Now a pinned tarball from go.dev, checked
    against their published SHA256.
    """
    ensure_runtime("go")
