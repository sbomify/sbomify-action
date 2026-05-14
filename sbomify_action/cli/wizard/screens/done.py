"""Done screen — summary, next steps, exit."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen


class DoneScreen(WizardScreen):
    """Phase 7 — summary + next steps + exit."""

    step_index = 6
    step_title = "Done"

    BINDINGS = [
        Binding("enter", "finish", "Exit", show=True, priority=True),
        Binding("escape", "finish", "Exit", show=True),
    ]

    def __init__(self, *, dry_run: bool) -> None:
        super().__init__()
        self._dry_run = dry_run
        self.step_subtitle = "Dry-run complete — no changes made." if dry_run else "Your repo is wired up to sbomify."

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="wizard-panel-emphasis"):
            yield Static(self._headline(), classes="wizard-title")
            yield Static("")
            yield Static(self._body(), markup=True)
        with Horizontal(classes="button-row"):
            yield Button("Exit", id="exit", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#exit", Button).focus()

    def _headline(self) -> str:
        if self._dry_run:
            return "[b #F4B57F]Dry-run complete[/]"
        n = len(self.wizard.state.plan.create_components)
        return f"[b #4ADE80]All set.[/]  [#FFFFFF]{n} component(s) configured.[/]"

    def _body(self) -> str:
        if self._dry_run:
            return (
                "[#CBCCCE]Re-run without [#FFFFFF]--dry-run[/] to apply the plan.\n"
                "Nothing was sent to sbomify and no files were written.[/]"
            )
        api = self.wizard.opts.api_base_url
        return (
            "[#CBCCCE]Next steps[/]\n"
            "  [#8A7DFF]1.[/]  Add your sbomify token as a repo secret:\n"
            "      [#FFFFFF]gh secret set SBOMIFY_TOKEN[/]\n\n"
            "  [#8A7DFF]2.[/]  Commit the new workflow files:\n"
            "      [#FFFFFF]git add .github/workflows/sbomify-*.yml[/]\n"
            "      [#FFFFFF]git commit -m 'Add sbomify SBOM generation'[/]\n\n"
            "  [#8A7DFF]3.[/]  Push to your default branch (or push a v* tag for tag-strategy\n"
            "      components) to trigger your first SBOM upload.\n\n"
            f"  [#8A7DFF]·[/]  View your components: [#F4B57F]{api}[/]"
        )

    def action_finish(self) -> None:
        self.app.exit(0)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "exit":
            self.app.exit(0)
