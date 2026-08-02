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

from sbomify_action import tool_manifest
from sbomify_action.tool_manifest import STAGE_RUNTIME, load_tools


@dataclass
class ToolInfo:
    """Information about a tool and its versions."""

    name: str
    env_var: str
    github_repo: str
    stage: str = "image"
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


def _tools_from_manifest() -> list[ToolInfo]:
    """Every pinned tool that has an upstream we can query.

    Derived from tools.toml rather than restated here. The previous hardcoded
    list is exactly how cosign and crane fell out of monitoring when they
    moved from the Dockerfile to on-demand fetching: nothing failed, they just
    silently stopped being checked, and both went stale.
    """
    return [
        ToolInfo(
            name=name,
            env_var=tool.dockerfile_arg or "",
            github_repo=tool.github_repo,
            stage=tool.stage,
            current_version=tool.version,
        )
        for name, tool in sorted(load_tools().items())
        if tool.github_repo
    ]


TOOLS = _tools_from_manifest()


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
    # ENV SYFT_VERSION=1.39.0 \
    #     TRIVY_VERSION=0.67.2
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
        # Release tags carry project-specific prefixes: "v1.50.0" (syft),
        # "cargo-cyclonedx-0.5.9", "bun-v1.3.14". Strip everything up to the
        # first digit so the comparison is against a bare version -- otherwise
        # a tool is reported permanently outdated because the prefix never
        # matches the pinned value.
        match = re.search(r"\d.*$", tag)
        version = match.group(0) if match else tag
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
    results = []

    for tool in TOOLS:
        # Create a copy to avoid mutating the original
        tool_info = ToolInfo(
            name=tool.name,
            env_var=tool.env_var,
            github_repo=tool.github_repo,
            stage=tool.stage,
            current_version=tool.current_version,
        )

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
        msg = f"{outdated_count} tool(s) are outdated. Run with --update to bump the pins in tools.toml."
        print(colorize(msg, "yellow"))
    elif error_count == 0:
        print(colorize("All tools are up to date!", "green"))


def update_pins(dockerfile_path: Path, tools: list[ToolInfo]) -> int:
    """Bump pinned versions in tools.toml, and the matching Dockerfile ARGs.

    Runtime tools are deliberately skipped. Their pin is a version *and* a
    SHA256, and bumping the version alone would leave every user's download
    failing its checksum -- a far worse outcome than being a release behind.
    Those need the digest updating by hand from the vendor's checksum file.

    Args:
        dockerfile_path: Path to the Dockerfile
        tools: List of ToolInfo objects

    Returns:
        Number of tools updated
    """
    manifest_path = Path(tool_manifest.__file__).with_name("tools.toml")
    manifest = manifest_path.read_text()
    dockerfile = dockerfile_path.read_text()
    updated_count = 0
    skipped: list[ToolInfo] = []

    for tool in tools:
        if not tool.is_outdated:
            continue
        if tool.stage == STAGE_RUNTIME:
            skipped.append(tool)
            continue

        old_pin = f'version = "{tool.current_version}"'
        new_pin = f'version = "{tool.latest_version}"'
        # Scope the replacement to this tool's own table.
        head = f"[tool.{tool.name}]"
        if head in manifest and old_pin in manifest[manifest.index(head) :]:
            start = manifest.index(head)
            manifest = manifest[:start] + manifest[start:].replace(old_pin, new_pin, 1)
        else:
            print(f"  Could not find pin for {tool.name} in tools.toml")
            continue

        if tool.env_var:
            dockerfile = dockerfile.replace(
                f"{tool.env_var}={tool.current_version}", f"{tool.env_var}={tool.latest_version}"
            )
        print(f"  Updated {tool.name}: {tool.current_version} -> {tool.latest_version}")
        updated_count += 1

    if updated_count > 0:
        manifest_path.write_text(manifest)
        dockerfile_path.write_text(dockerfile)

    for tool in skipped:
        print(
            f"  SKIPPED {tool.name}: {tool.current_version} -> {tool.latest_version} "
            f"(runtime tool -- update the sha256 for both architectures in tools.toml too, "
            f"or every fetch will fail its checksum)"
        )

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
        updated = update_pins(dockerfile_path, tools)
        if updated > 0:
            print(f"\nUpdated {updated} tool(s) in Dockerfile.")

    if has_errors:
        return 2
    if has_outdated and not args.update:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
