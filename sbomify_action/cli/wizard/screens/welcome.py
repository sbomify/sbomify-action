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
        has_existing = bool(self.wizard.state.existing_workflows)
        start_label = "Add / set up  ▸" if has_existing else "Start  ▸"
        with Horizontal(classes="button-row"):
            yield Button(start_label, id="start", variant="primary")
            if has_existing:
                yield Button("Edit existing  ▸", id="edit")
            yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#start", Button).focus()

    def action_start(self) -> None:
        self._advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            self._advance()
        elif event.button.id == "edit":
            self._advance_to_edit()
        elif event.button.id == "cancel":
            self.wizard.action_quit_with_cancel()

    def _advance(self) -> None:
        self.wizard.flow_mode = "onboard"
        from sbomify_action.cli.wizard.screens.discover import DiscoverScreen

        self.wizard.push_screen(DiscoverScreen())

    def _advance_to_edit(self) -> None:
        # The edit flow skips lockfile discovery — we already know which
        # workflows exist and what they point at. Go straight to auth so we
        # can resolve component IDs against the user's workspace.
        self.wizard.flow_mode = "edit"
        from sbomify_action.cli.wizard.screens.authenticate import AuthenticateScreen

        self.wizard.push_screen(AuthenticateScreen())

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
        existing = self.wizard.state.existing_workflows
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
        if existing:
            matched, lockfiles, orphans = self.wizard.state.coverage()
            if lockfiles == 0:
                rows.append(
                    f"  [#F4B57F]·[/] found [#FFFFFF]{len(existing)}[/] existing sbomify workflow(s) "
                    "but no lockfiles were discovered to match against"
                )
            elif matched == lockfiles:
                rows.append(
                    f"  [#4ADE80]✓[/] found jobs for [#FFFFFF]{matched}/{lockfiles}[/] lockfile(s) — "
                    "every component will be pre-filled in the configure step"
                )
            elif matched > 0:
                rows.append(
                    f"  [#4ADE80]✓[/] found jobs for [#FFFFFF]{matched}/{lockfiles}[/] lockfile(s) — "
                    "matched components will be pre-filled, the rest set up fresh"
                )
            else:
                rows.append(
                    f"  [#F4B57F]·[/] found [#FFFFFF]{len(existing)}[/] existing workflow(s), "
                    "but none match the discovered lockfiles"
                )
            if orphans:
                rows.append(
                    f"      [#5E5E5E]({orphans} orphan workflow(s) — point at lockfiles that no longer exist)[/]"
                )
        return "\n".join(rows)
