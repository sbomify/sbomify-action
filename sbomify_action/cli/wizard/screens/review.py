"""Review screen — show the staged plan + confirm before apply."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Static

from sbomify_action.cli.wizard.existing import workflow_path
from sbomify_action.cli.wizard.screens._base import WizardScreen


class ReviewScreen(WizardScreen):
    """Phase 6 — show what apply will do, then confirm."""

    step_index = 6
    step_title = "Review"
    step_subtitle = "Apply nothing yet. Confirm the plan below to commit."

    BINDINGS = [
        Binding("enter", "apply", "Apply ▸", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        summary = Vertical(classes="wizard-panel")
        summary.border_title = "◆  Plan summary"
        summary.border_subtitle = "what apply will do"
        with summary:
            yield Static(self._summary(), classes="wizard-muted")

        components = Vertical(classes="wizard-panel")
        components.border_title = "◆  Components"
        components.border_subtitle = f"{len(self.wizard.state.plan.create_components)} planned"
        with components:
            yield DataTable(id="components-table", cursor_type="none", zebra_stripes=True)

        files = Vertical(classes="wizard-panel")
        files.border_title = "◆  Files to write"
        with files:
            yield Static(self._files_summary(), classes="wizard-muted")

        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Apply  ▸", id="apply", variant="primary")

    def on_mount(self) -> None:
        table = self.query_one("#components-table", DataTable)
        table.add_columns("Lockfile", "Ecosystem", "Component name")
        for c in self.wizard.state.plan.create_components:
            table.add_row(str(c.lockfile.rel_path), c.lockfile.ecosystem, c.name)
        self.query_one("#apply", Button).focus()

    def action_apply(self) -> None:
        self._advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()

    def _advance(self) -> None:
        from sbomify_action.cli.wizard.screens.apply import ApplyScreen

        self.wizard.push_screen(ApplyScreen())

    def _summary(self) -> str:
        plan = self.wizard.state.plan
        workspace = self.wizard.state.workspace
        product_label = "(no product)"
        if plan.create_product:
            product_label = f"new: {plan.create_product}"
        elif plan.use_product_id and workspace:
            match = next((p for p in workspace.products if str(p.get("id")) == plan.use_product_id), None)
            if match:
                product_label = f"existing: {match.get('name')} ({plan.use_product_id})"
            else:
                product_label = f"existing: {plan.use_product_id}"
        return (
            f"Product: {product_label}\n"
            f"Release strategy: {plan.release_strategy}\n"
            f"Credentials: {plan.credential_mode}\n"
            f"Augmentation: {plan.augmentation}"
        )

    def _files_summary(self) -> str:
        target = workflow_path(self.wizard.state.facts.repo_root)
        if self.wizard.state.workflow_exists:
            return f"{target}  [#F4B57F]→ overwrite (backup as {target.name}.bak)[/]"
        return f"{target}  [#86EFAC]→ create[/]"
