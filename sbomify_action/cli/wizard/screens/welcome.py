"""Welcome screen — banner, repo summary, start button."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen


class WelcomeScreen(WizardScreen):
    """Phase 1 — intro + repo summary."""

    step_index = 1
    step_title = "Welcome"
    step_subtitle = "Get this repo set up for SBOM generation in a few minutes."

    BINDINGS = [
        Binding("enter", "start", "Continue", show=True),
        Binding("escape", "app.quit_with_cancel", "Cancel", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="wizard-panel-emphasis"):
            yield Static("[b]sbomify wizard[/b]", classes="wizard-title")
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

    def _intro(self) -> str:
        return (
            "This wizard scans your repository for lockfiles, registers the "
            "matching components in sbomify, and writes a GitHub Actions workflow "
            "that publishes an SBOM on every push.\n\n"
            "[b]What we'll do:[/b]\n"
            "  1. Pick which lockfiles to track\n"
            "  2. Authenticate against sbomify\n"
            "  3. Pick a product\n"
            "  4. Name each component & choose a release strategy\n"
            "  5. Review the plan\n"
            "  6. Apply — create components & write the workflow file"
        )

    def _repo_summary(self) -> str:
        facts = self.wizard.state.facts
        lockfile_count = len(self.wizard.state.discovered)
        lines = [
            f"Repository: [b]{facts.suggested_repo_name}[/b]",
            f"Branch: {facts.current_branch or facts.default_branch}",
            f"Lockfiles found: {lockfile_count}",
        ]
        if self.wizard.state.workflow_exists:
            lines.append(
                "[#F4B57F]A wizard-managed sboms.yml already exists — it will be backed up before overwrite.[/]"
            )
        if facts.has_release_tags:
            lines.append("Release tags detected (v*) — tag-based release strategy will be suggested.")
        return "\n".join(lines)
