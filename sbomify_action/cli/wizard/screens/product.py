"""Product screen — pick an existing product or create a new one."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.widgets import NEW_SENTINEL, PickOrCreate
from sbomify_action.logging_config import logger


class ProductScreen(WizardScreen):
    """Phase 4 — pick or create the product these components attach to."""

    step_index = 4
    step_title = "Pick a product"
    step_subtitle = "Components attach to a product. Pick an existing one or create a new one."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True, priority=True),
    ]

    def compose_body(self) -> ComposeResult:
        products = self.wizard.state.workspace.products if self.wizard.state.workspace else []
        panel = Vertical(classes="wizard-panel")
        panel.border_title = "◆  Pick a product"
        panel.border_subtitle = f"{len(products)} existing"
        with panel:
            yield Static(
                "Use [b]↑/↓[/] to highlight a product (or leave on "
                "[b]Create new[/]), then [b]Tab[/] to edit the new-product "
                "name. [b]Enter[/] when done.",
                classes="wizard-muted",
            )
            yield PickOrCreate(
                existing=[(str(p.get("name") or p.get("id") or "(unnamed)"), str(p.get("id"))) for p in products],
                create_label="[#86EFAC]➕  Create a new product[/]",
                placeholder="New product name (used only when 'Create new' is highlighted)",
                # Pre-select the first existing product when the
                # workspace has any. Re-running the wizard against an
                # already-onboarded workspace shouldn't nudge the user
                # toward creating a duplicate.
                pre_select_id=str(products[0].get("id")) if products else None,
                id="product-picker",
            )
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next  ▸", id="next", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#product-picker", PickOrCreate).focus_list()

    def action_submit(self) -> None:
        self._advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()

    def _advance(self) -> None:
        picker = self.query_one("#product-picker", PickOrCreate)
        picked_id = picker.picked_id
        if picked_id is None:
            self.app.bell()
            return
        if picked_id == NEW_SENTINEL:
            new_name = picker.new_value
            if not new_name:
                self.app.bell()
                return
            self.wizard.state.plan.create_product = new_name
            self.wizard.state.plan.use_product_id = None
            logger.debug("Product screen: will create new product %r", new_name)
        else:
            self.wizard.state.plan.use_product_id = picked_id
            self.wizard.state.plan.create_product = None
            logger.debug("Product screen: will use existing product id=%s", picked_id)

        from sbomify_action.cli.wizard.screens.components import ComponentsScreen

        self.wizard.push_screen(ComponentsScreen())
