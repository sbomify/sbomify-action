"""Log formatters for the CI runtime platforms.

Each formatter renders the same structural events -- groups, step headers,
annotations, final banners -- in the dialect its platform understands.

These are imported by ``sbomify_action.console``, so nothing here may import
that module (or ``logging_config``, which imports it) at module scope. The Rich
console is fetched lazily inside method bodies instead.
"""

import os
import uuid
from typing import Any


def _rich_console() -> Any:
    """Return the shared Rich console.

    Deferred so this module stays importable from ``console`` itself.
    """
    from sbomify_action.console import console

    return console


def _escape(text: str) -> str:
    """Escape workflow-command data the way the GitHub runner unescapes it."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


class PlainFormatter:
    """Rich-styled output for local terminals and CI systems without annotations.

    Grouping is a no-op: platforms that cannot collapse output simply print
    everything inline.
    """

    name: str = "plain"
    force_terminal: bool | None = None
    show_log_time: bool = True
    annotates_warnings: bool = False

    def job_summary(self, markdown: str) -> None:
        """No-op -- this platform has no summary page."""

    def set_output(self, name: str, value: str) -> None:
        """No-op -- this platform has no step outputs."""

    def group_start(self, title: str) -> None:
        """No-op -- this platform has no collapsible sections."""

    def group_end(self) -> None:
        """No-op -- this platform has no collapsible sections."""

    def step_header(self, title: str) -> None:
        """Print a horizontal rule introducing the step."""
        console = _rich_console()
        console.print()
        console.rule(f"[bold blue]{title}[/bold blue]", style="blue")

    def step_footer(self) -> None:
        """Separate this step from the next with a blank line."""
        _rich_console().print()

    def warning(self, message: str, title: str | None = None) -> None:
        """Print a styled warning line."""
        console = _rich_console()
        if title:
            console.print(f"[warning]Warning ({title}):[/warning] {message}")
        else:
            console.print(f"[warning]Warning:[/warning] {message}")

    def error(self, message: str, title: str | None = None) -> None:
        """Print a styled error line."""
        console = _rich_console()
        if title:
            console.print(f"[error]Error ({title}):[/error] {message}")
        else:
            console.print(f"[error]Error:[/error] {message}")

    def notice(self, message: str, title: str | None = None) -> None:
        """Print a styled notice line."""
        console = _rich_console()
        if title:
            console.print(f"[info]Notice ({title}):[/info] {message}")
        else:
            console.print(f"[info]Notice:[/info] {message}")

    def final_success(self) -> None:
        """Print the success banner."""
        console = _rich_console()
        console.rule("[bold green]SUCCESS[/bold green]", style="green")
        console.print("[bold green]All steps completed successfully![/bold green]", justify="center")

    def final_failure(self, message: str) -> None:
        """Print the failure banner."""
        console = _rich_console()
        console.rule("[bold red]FAILED[/bold red]", style="red")
        console.print(f"[bold red]{message}[/bold red]", justify="center")


class GitHubActionsFormatter:
    """GitHub Actions workflow commands.

    Emits ``::group::`` / ``::warning::`` / ``::error::`` / ``::notice::`` so
    output collapses in the job log and annotations reach the job summary.
    """

    name: str = "github-actions"
    # GHA supports ANSI colour but Rich cannot detect it through the runner's pipe.
    force_terminal: bool | None = True
    # The runner already timestamps every line.
    show_log_time: bool = False
    annotates_warnings: bool = True

    def job_summary(self, markdown: str) -> None:
        """Append to the job summary file (container actions are handed one too)."""
        if path := os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(path, "a", encoding="utf-8") as f:
                f.write(markdown)

    def set_output(self, name: str, value: str) -> None:
        """Append a step output.

        Always in the heredoc form, under a delimiter the value cannot know,
        so a newline in a value (an SBOM id is whatever the server returned)
        cannot close it early and forge another output.
        """
        if path := os.environ.get("GITHUB_OUTPUT"):
            delimiter = f"ghadelimiter_{uuid.uuid4()}"
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")

    def group_start(self, title: str) -> None:
        """Open a collapsible job-log group."""
        print(f"::group::{title}")

    def group_end(self) -> None:
        """Close the current job-log group."""
        print("::endgroup::")

    def step_header(self, title: str) -> None:
        """Open a group and echo the step title inside it."""
        self.group_start(title)
        _rich_console().print(f"[bold blue]{title}[/bold blue]")

    def step_footer(self) -> None:
        """Close the step's group."""
        self.group_end()

    def _annotate(self, kind: str, message: str, title: str | None) -> None:
        """Print one annotation, escaped as the runner unescapes it.

        Annotations carry logged text, which can span lines: unescaped, a
        newline would end the annotation and leave the rest as a raw log line
        the runner might read as a command of its own.
        """
        if title:
            title = _escape(title).replace(":", "%3A").replace(",", "%2C")
            print(f"::{kind} title={title}::{_escape(message)}")
        else:
            print(f"::{kind}::{_escape(message)}")

    def warning(self, message: str, title: str | None = None) -> None:
        """Emit a warning annotation."""
        self._annotate("warning", message, title)

    def error(self, message: str, title: str | None = None) -> None:
        """Emit an error annotation."""
        self._annotate("error", message, title)

    def notice(self, message: str, title: str | None = None) -> None:
        """Emit a notice annotation."""
        self._annotate("notice", message, title)

    def final_success(self) -> None:
        """Print a one-line success message (rules waste space in a job log)."""
        _rich_console().print("[bold green]✓ SUCCESS![/bold green] All steps completed successfully.")

    def final_failure(self, message: str) -> None:
        """No-op -- the ``::error::`` annotation already carries the message."""
