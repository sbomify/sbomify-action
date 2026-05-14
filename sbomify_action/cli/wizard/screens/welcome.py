"""Welcome screen — banner, repo summary, start button."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen


class WelcomeScreen(WizardScreen):
    """Phase 0 — intro and repo summary."""

    step_index = 1
    step_title = "Welcome"
    step_subtitle = "Get this repo set up for SBOM generation in a few minutes."

    BINDINGS = [
        Binding("enter", "start", "Continue", show=True),
        Binding("escape", "app.quit_with_cancel", "Cancel", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="wizard-panel-emphasis"):
            # Banner uses a Rich `Text` (not markup) because the ASCII art
            # contains backslashes — `\[/]` would be parsed as a literal "[/]".
            yield Static(self._banner(), classes="banner")
            yield Static(self._intro())
            yield Static("")
            yield Static(self._repo_summary(), classes="wizard-muted")
        with Horizontal(classes="button-row"):
            yield Button("Start  ▸", id="start", variant="primary")
            yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#start", Button).focus()

    def action_start(self) -> None:
        self._advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            self._advance()
        elif event.button.id == "cancel":
            self.wizard.action_quit_with_cancel()

    def _advance(self) -> None:
        from sbomify_action.cli.wizard.screens.discover import DiscoverScreen

        self.wizard.push_screen(DiscoverScreen())

    def _banner(self) -> Text:
        # Marketing-palette gradient (logo SVG stops): blue → magenta → peach.
        # Built as a `Text` rather than markup so backslashes in the ASCII art
        # don't get interpreted as escape sequences (`\[` would render `[/]`
        # literally at end-of-line).
        lines = [
            ("         __                    _ ____         ___        __  _           ", "#4059D0"),
            ("   _____/ /_  ____  ____ ___  (_) __/_  __   /   | _____/ /_(_)___  ____ ", "#7C5BC8"),
            ("  / ___/ __ \\/ __ \\/ __ `__ \\/ / /_/ / / /  / /| |/ ___/ __/ / __ \\/ __ \\", "#A85AC0"),
            (" (__  ) /_/ / /_/ / / / / / / / __/ /_/ /  / ___ / /__/ /_/ / /_/ / / / /", "#CC58BB"),
            ("/____/_.___/\\____/_/ /_/ /_/_/_/  \\__, /  /_/  |_\\___/\\__/_/\\____/_/ /_/ ", "#E0879D"),
            ("                                 /____/                                  ", "#F4B57F"),
        ]
        banner = Text()
        for i, (text, color) in enumerate(lines):
            if i > 0:
                banner.append("\n")
            banner.append(text, style=f"bold {color}")
        return banner

    def _intro(self) -> str:
        return (
            "[bold #FFFFFF]Generate Software Bills of Materials for this repo in CI.[/]\n"
            "[#CBCCCE]We'll find your lockfiles, create matching components on sbomify, "
            "and emit GitHub Actions workflows that keep them in sync on every push.[/]"
        )

    def _repo_summary(self) -> str:
        facts = self.wizard.state.facts
        rows: list[str] = []
        rows.append(f"  [#8A7DFF]Repo[/]      {facts.repo_root}")
        if facts.is_git:
            rows.append(f"  [#8A7DFF]Remote[/]    {facts.remote_url or '[dim]no remote configured[/]'}")
            rows.append(
                f"  [#8A7DFF]Branch[/]    {facts.current_branch or '[dim]detached[/]'}  ·  default → {facts.default_branch}"
            )
            if facts.has_release_tags:
                rows.append("  [#F4B57F]✓[/] git tags detected — will suggest tag-based releases")
        else:
            rows.append("  [#F4B57F]![/] not a git repository — discovery and PR creation will be limited")
        return "\n".join(rows)
