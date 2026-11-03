"""Log formatters for the CI runtime platforms.

Each formatter renders the same structural events -- groups, step headers,
annotations, final banners -- in the dialect its platform understands.

These are imported by ``sbomify_action.console``, so nothing here may import
that module (or ``logging_config``, which imports it) at module scope. The Rich
console is fetched lazily inside method bodies instead.
"""

from typing import Any


def _rich_console() -> Any:
    """Return the shared Rich console.

    Deferred so this module stays importable from ``console`` itself.
    """
    from sbomify_action.console import console

    return console


class PlainFormatter:
    """Rich-styled output for local terminals and CI systems without annotations.

    Grouping is a no-op: platforms that cannot collapse output simply print
    everything inline.
    """

    name: str = "plain"
    force_terminal: bool | None = None
    show_log_time: bool = True

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

    def warning(self, message: str, title: str | None = None) -> None:
        """Emit a warning annotation."""
        if title:
            print(f"::warning title={title}::{message}")
        else:
            print(f"::warning::{message}")

    def error(self, message: str, title: str | None = None) -> None:
        """Emit an error annotation."""
        if title:
            print(f"::error title={title}::{message}")
        else:
            print(f"::error::{message}")

    def notice(self, message: str, title: str | None = None) -> None:
        """Emit a notice annotation."""
        if title:
            print(f"::notice title={title}::{message}")
        else:
            print(f"::notice::{message}")

    def final_success(self) -> None:
        """Print a one-line success message (rules waste space in a job log)."""
        _rich_console().print("[bold green]✓ SUCCESS![/bold green] All steps completed successfully.")

    def final_failure(self, message: str) -> None:
        """No-op -- the ``::error::`` annotation already carries the message."""
