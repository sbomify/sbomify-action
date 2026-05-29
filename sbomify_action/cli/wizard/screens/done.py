"""Done screen — summary of what apply did + OIDC binding instructions."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen


class DoneScreen(WizardScreen):
    """Phase 6c — summary + next steps."""

    step_index = 8
    step_title = "Done"
    step_subtitle = "All set. Here's what you'll want to do next."

    BINDINGS = [
        Binding("enter", "finish", "Finish", show=True, priority=True),
        # Done is terminal — there's nothing useful to go 'back' to,
        # since apply already committed the plan. Treat Escape as a
        # synonym for Finish so it exits the wizard instead of
        # popping back to the Apply screen (which would just re-show
        # the success log from the run that already happened).
        Binding("escape", "finish", "Finish", show=True, priority=True),
        # One-keystroke 'copy first OIDC settings URL to clipboard' so
        # users don't have to drag-select a multi-line URL inside the
        # TUI. Only useful when there's at least one URL to copy; the
        # action no-ops cleanly when there isn't.
        Binding("c", "copy_first_url", "Copy URL", show=True),
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

    def action_copy_first_url(self) -> None:
        """Copy the OIDC settings URL for the first applied component."""
        state = self.wizard.state
        if not state.component_ids:
            self.notify(
                "No components were applied — nothing to copy.",
                severity="warning",
            )
            return
        api_base = self.wizard.opts.api_base_url
        first_cid = next(iter(state.component_ids.values()))
        url = f"{api_base}/components/{first_cid}/settings"
        self.app.copy_to_clipboard(url)
        self.notify(f"Copied {url} to clipboard.", severity="information")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "finish":
            self.wizard.exit(0)

    def _applied_summary(self) -> str:
        state = self.wizard.state
        lines: list[str] = []
        if state.created_product_id:
            lines.append(f"[#86EFAC]✓[/]  [#CBCCCE]Product[/]    {state.created_product_id}")
        if state.component_ids:
            # Reused components don't deserve the same green-checkmark
            # weight as newly-created ones — re-running the wizard
            # against an already-onboarded workspace should feel quiet,
            # not like every line is an "event". apply.apply_plan
            # populates state.reused_component_ids with both pre-picked
            # IDs and DUPLICATE_NAME-recovered IDs, so we don't need to
            # re-derive the set here.
            lines.append("[#86EFAC]✓[/]  [#CBCCCE]Components[/]")
            for rel, cid in state.component_ids.items():
                if cid in state.reused_component_ids:
                    glyph = "[#5E5E5E]·[/]"  # muted dot — reused, nothing changed
                    label = "[#5E5E5E]reused[/]"
                    cid_style = f"[#5E5E5E]{cid}[/]"
                else:
                    glyph = "[#86EFAC]+[/]"  # green plus — newly created
                    label = "[#86EFAC]created[/]"
                    cid_style = f"[b]{cid}[/]"
                lines.append(f"     {glyph}  {rel}  [#5E5E5E]→[/]  {cid_style}  {label}")
        if state.attach_error:
            # Components were created but attach failed — surface this
            # prominently so the user knows their workflow file points at
            # components that aren't actually linked to the product.
            lines.append(
                "[#F87171]✗[/]  [#CBCCCE]Attach[/]     [#F87171]failed — components are not linked to the product[/]"
            )
            lines.append(f"     [#5E5E5E]reason: {state.attach_error}[/]")
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
