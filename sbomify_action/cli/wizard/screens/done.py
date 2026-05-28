"""Done screen — summary of what apply did + OIDC binding instructions."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen


class DoneScreen(WizardScreen):
    """Phase 6c — summary + next steps."""

    step_index = 7
    step_title = "Done"
    step_subtitle = "All set. Here's what you'll want to do next."

    BINDINGS = [
        Binding("enter", "finish", "Finish", show=True, priority=True),
    ]

    def compose_body(self) -> ComposeResult:
        applied = Vertical(classes="wizard-panel-emphasis")
        applied.border_title = "✓  Applied"
        applied.border_subtitle = "From zero to SBOM hero"
        with applied:
            yield Static(self._applied_summary(), classes="wizard-muted")

        if self.wizard.state.plan.credential_mode == "oidc":
            oidc = Vertical(classes="wizard-panel")
            oidc.border_title = "⚠  One more step — set up OIDC trusted publishing"
            with oidc:
                yield Static(self._oidc_instructions(), classes="wizard-muted")
        else:
            tok = Vertical(classes="wizard-panel")
            tok.border_title = "⚠  Add the SBOMIFY_TOKEN secret"
            with tok:
                yield Static(self._token_instructions(), classes="wizard-muted")

        with Horizontal(classes="button-row"):
            yield Button("Finish", id="finish", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#finish", Button).focus()

    def action_finish(self) -> None:
        self.wizard.exit(0)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "finish":
            self.wizard.exit(0)

    def _applied_summary(self) -> str:
        state = self.wizard.state
        lines: list[str] = []
        if state.created_product_id:
            lines.append(f"[#86EFAC]✓[/]  [#CBCCCE]Product[/]    {state.created_product_id}")
        if state.component_ids:
            lines.append("[#86EFAC]✓[/]  [#CBCCCE]Components[/]")
            for rel, cid in state.component_ids.items():
                lines.append(f"     [#5E5E5E]│[/]  {rel}  [#5E5E5E]→[/]  [b]{cid}[/]")
        for path in state.written_files:
            lines.append(f"[#86EFAC]✓[/]  [#CBCCCE]Wrote[/]      {path}")
        if not lines:
            lines.append("[#5E5E5E]◌  (nothing applied)[/]")
        return "\n".join(lines)

    def _oidc_instructions(self) -> str:
        state = self.wizard.state
        api_base = self.wizard.opts.api_base_url
        slug = state.facts.owner_repo_slug or "<owner>/<repo>"
        lines = [
            "Trusted publishing needs an OIDC binding per component in the sbomify UI.",
            "",
            f"  Repository: [b]{slug}[/]",
            "",
            "For each component:",
        ]
        for rel, cid in state.component_ids.items():
            lines.append(f"  · {rel}  →  {api_base}/components/{cid}/settings")
        lines.extend(
            [
                "",
                "Open each link → [b]Trusted Publishing → Add binding[/] → paste the repository slug.",
                "After that, pushing to the default branch will mint a short-lived token via OIDC and publish your first SBOM.",
            ]
        )
        return "\n".join(lines)

    def _token_instructions(self) -> str:
        return (
            "Add a repository secret named [b]SBOMIFY_TOKEN[/] with a sbomify API token "
            "(Repository → Settings → Secrets and variables → Actions → New repository secret).\n"
            "After that, pushing to the default branch will publish your first SBOM."
        )
