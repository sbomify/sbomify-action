#!/usr/bin/env python3
"""Check if binary tools in the Dockerfile are up to date with their latest GitHub releases.

This script parses the Dockerfile to extract current tool versions, queries
the GitHub API for the latest releases, and reports which tools are outdated.

Usage:
    ./bin/check_tool_versions.py [--json] [--update] [--timeout SECONDS]

Options:
    --json              Output in JSON format for machine parsing
    --update            Update Dockerfile with latest versions
    --timeout SECONDS   Request timeout in seconds (default: 30)
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ToolInfo:
    """Information about a tool and its versions."""

    name: str
    env_var: str
    github_repo: str
    current_version: Optional[str] = None
    latest_version: Optional[str] = None
    error: Optional[str] = None

    @property
    def is_outdated(self) -> bool:
        """Check if the tool is outdated."""
        if not self.current_version or not self.latest_version:
            return False
        return self.current_version != self.latest_version

    @property
    def status(self) -> str:
        """Get the status string for display."""
        if self.error:
            return f"ERROR: {self.error}"
        if not self.current_version:
            return "NOT FOUND"
        if not self.latest_version:
            return "UNKNOWN"
        if self.is_outdated:
            return "OUTDATED"
        return "OK"


# Tools to check - maps ENV variable name to GitHub repo
TOOLS = [
    ToolInfo(name="syft", env_var="SYFT_VERSION", github_repo="anchore/syft"),
    ToolInfo(name="bomctl", env_var="BOMCTL_VERSION", github_repo="bomctl/bomctl"),
    ToolInfo(
        name="cargo-cyclonedx",
        env_var="CARGO_CYCLONEDX_VERSION",
        github_repo="CycloneDX/cyclonedx-rust-cargo",
    ),
    ToolInfo(name="crane", env_var="CRANE_VERSION", github_repo="google/go-containerregistry"),
    ToolInfo(name="cosign", env_var="COSIGN_VERSION", github_repo="sigstore/cosign"),
]


def find_project_root() -> Path:
    """Find the project root directory (where Dockerfile is located)."""
    # Start from script location and walk up
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "Dockerfile").exists():
            return current
        current = current.parent

    # Fallback to current working directory
    cwd = Path.cwd()
    if (cwd / "Dockerfile").exists():
        return cwd

    raise FileNotFoundError("Could not find project root (no Dockerfile found)")


def parse_dockerfile(dockerfile_path: Path) -> dict[str, str]:
    """Parse Dockerfile and extract ENV version variables.

    Args:
        dockerfile_path: Path to the Dockerfile

    Returns:
        Dictionary mapping ENV variable names to their values
    """
    versions = {}
    content = dockerfile_path.read_text()

    # Match ENV blocks like:
    # ENV BOMCTL_VERSION=0.4.3 \
    #     TRIVY_VERSION=0.67.2 \
    #     SYFT_VERSION=1.39.0
    # Also handles single-line: ENV FOO=bar
    env_pattern = re.compile(r"(\w+_VERSION)=([^\s\\]+)")

    for match in env_pattern.finditer(content):
        var_name = match.group(1)
        version = match.group(2)
        versions[var_name] = version

    # Also check ARG statements (cargo-cyclonedx uses ARG)
    arg_pattern = re.compile(r"ARG\s+(\w+_VERSION)=([^\s]+)")
    for match in arg_pattern.finditer(content):
        var_name = match.group(1)
        version = match.group(2)
        # Don't overwrite ENV values with ARG defaults
        if var_name not in versions:
            versions[var_name] = version

    return versions


DEFAULT_TIMEOUT = 30


def get_latest_github_release(repo: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[Optional[str], Optional[str]]:
    """Fetch the latest release version from GitHub API using curl.

    Args:
        repo: GitHub repository in "owner/repo" format
        timeout: Request timeout in seconds

    Returns:
        Tuple of (version, error_message). Version is None if error occurred.
    """
    url = f"https://api.github.com/repos/{repo}/releases/latest"

    try:
        result = subprocess.run(
            [
                "curl",
                "-s",
                "-f",
                "-L",  # Follow redirects
                "--max-time",
                str(timeout),
                "-H",
                "Accept: application/vnd.github.v3+json",
                "-H",
                "User-Agent: sbomify-version-checker",
                url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 5,  # Give curl a bit more time than its own timeout
        )

        if result.returncode != 0:
            # curl -f returns 22 for HTTP errors
            if result.returncode == 22:
                return None, "HTTP error (404 or other)"
            return None, f"curl failed with code {result.returncode}"

        data = json.loads(result.stdout)
        tag = data.get("tag_name", "")
        # Strip 'v' prefix if present (e.g., "v0.67.2" -> "0.67.2")
        version = tag.lstrip("v")
        # Handle cargo-cyclonedx which uses "cargo-cyclonedx-X.Y.Z" format
        if version.startswith("cargo-cyclonedx-"):
            version = version.replace("cargo-cyclonedx-", "")
        return version, None
    except subprocess.TimeoutExpired:
        return None, "Request timed out"
    except json.JSONDecodeError:
        return None, "Invalid JSON response"
    except FileNotFoundError:
        return None, "curl not found - please install curl"
    except Exception as e:
        return None, f"Error: {e}"


def check_all_tools(dockerfile_path: Path, timeout: int = DEFAULT_TIMEOUT) -> list[ToolInfo]:
    """Check all tools for updates.

    Args:
        dockerfile_path: Path to the Dockerfile
        timeout: Request timeout in seconds

    Returns:
        List of ToolInfo objects with version information
    """
    # Parse current versions from Dockerfile
    current_versions = parse_dockerfile(dockerfile_path)

    results = []

    for tool in TOOLS:
        # Create a copy to avoid mutating the original
        tool_info = ToolInfo(
            name=tool.name,
            env_var=tool.env_var,
            github_repo=tool.github_repo,
        )

        # Get current version from Dockerfile
        tool_info.current_version = current_versions.get(tool.env_var)

        # Get latest version from GitHub
        latest, error = get_latest_github_release(tool.github_repo, timeout=timeout)
        if error:
            tool_info.error = error
        else:
            tool_info.latest_version = latest

        results.append(tool_info)

    return results


def print_table(tools: list[ToolInfo]) -> None:
    """Print results as a formatted table.

    Args:
        tools: List of ToolInfo objects
    """
    # Check if terminal supports colors
    use_colors = sys.stdout.isatty()

    def colorize(text: str, color: str) -> str:
        if not use_colors:
            return text
        colors = {
            "green": "\033[32m",
            "red": "\033[31m",
            "yellow": "\033[33m",
            "reset": "\033[0m",
        }
        return f"{colors.get(color, '')}{text}{colors['reset']}"

    print("\nTool Version Audit")
    print("=" * 50)
    print()

    # Column headers
    headers = ["Tool", "Current", "Latest", "Status"]
    widths = [18, 14, 14, 20]

    header_line = "".join(h.ljust(w) for h, w in zip(headers, widths))
    print(header_line)
    print("-" * sum(widths))

    outdated_count = 0

    for tool in tools:
        current = tool.current_version or "N/A"
        latest = tool.latest_version or "N/A"
        status = tool.status

        # Colorize status
        if status == "OK":
            status_display = colorize(status, "green")
        elif status == "OUTDATED":
            status_display = colorize(status, "red")
            outdated_count += 1
        elif status.startswith("ERROR"):
            status_display = colorize(status, "yellow")
        else:
            status_display = status

        row = f"{tool.name.ljust(widths[0])}{current.ljust(widths[1])}{latest.ljust(widths[2])}{status_display}"
        print(row)

    print()

    error_count = sum(1 for t in tools if t.error)

    if error_count > 0:
        print(colorize(f"{error_count} tool(s) had errors fetching latest version.", "yellow"))

    if outdated_count > 0:
        msg = f"{outdated_count} tool(s) are outdated. Run with --update to update Dockerfile."
        print(colorize(msg, "yellow"))
    elif error_count == 0:
        print(colorize("All tools are up to date!", "green"))


def update_dockerfile(dockerfile_path: Path, tools: list[ToolInfo]) -> int:
    """Update the Dockerfile with latest versions.

    Args:
        dockerfile_path: Path to the Dockerfile
        tools: List of ToolInfo objects

    Returns:
        Number of tools updated
    """
    content = dockerfile_path.read_text()
    updated_count = 0

    for tool in tools:
        if tool.is_outdated:
            old_pattern = f"{tool.env_var}={tool.current_version}"
            new_pattern = f"{tool.env_var}={tool.latest_version}"
            if old_pattern in content:
                content = content.replace(old_pattern, new_pattern)
                print(f"  Updated {tool.name}: {tool.current_version} -> {tool.latest_version}")
                updated_count += 1

    if updated_count > 0:
        dockerfile_path.write_text(content)

    return updated_count


def print_json(tools: list[ToolInfo]) -> None:
    """Print results as JSON.

    Args:
        tools: List of ToolInfo objects
    """
    output = {
        "tools": [
            {
                "name": t.name,
                "env_var": t.env_var,
                "github_repo": t.github_repo,
                "current_version": t.current_version,
                "latest_version": t.latest_version,
                "is_outdated": t.is_outdated,
                "status": t.status,
                "error": t.error,
            }
            for t in tools
        ],
        "summary": {
            "total": len(tools),
            "outdated": sum(1 for t in tools if t.is_outdated),
            "errors": sum(1 for t in tools if t.error),
        },
    }
    print(json.dumps(output, indent=2))


def main() -> int:
    """Main entry point.

    Returns:
        Exit code (0 if all up to date, 1 if outdated, 2 if errors)
    """
    parser = argparse.ArgumentParser(description="Check if binary tools in Dockerfile are up to date")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Update Dockerfile with latest versions",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    args = parser.parse_args()

    try:
        project_root = find_project_root()
        dockerfile_path = project_root / "Dockerfile"
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    tools = check_all_tools(dockerfile_path, timeout=args.timeout)

    if args.json:
        print_json(tools)
    else:
        print_table(tools)

    # Determine exit code
    has_errors = any(t.error for t in tools)
    has_outdated = any(t.is_outdated for t in tools)

    # Update Dockerfile if requested
    if args.update and has_outdated:
        print()
        print("Updating Dockerfile...")
        updated = update_dockerfile(dockerfile_path, tools)
        if updated > 0:
            print(f"\nUpdated {updated} tool(s) in Dockerfile.")

    if has_errors:
        return 2
    if has_outdated and not args.update:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
