"""Product screen — pick an existing product or create a new one."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, OptionList, Static
from textual.widgets.option_list import Option

from sbomify_action.cli.wizard.screens._base import WizardScreen


class ProductScreen(WizardScreen):
    """Phase 4 — pick or create the product these components attach to."""

    step_index = 4
    step_title = "Pick a product"
    step_subtitle = "Components attach to a product. Pick an existing one or create a new one."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="wizard-panel"):
            yield Static("[b]Products[/]", classes="wizard-title")
            yield Static(self._help_text(), classes="wizard-muted")
            yield OptionList(id="product-list")
            yield Static("Or create a new one:", classes="wizard-muted")
            yield Input(placeholder="New product name (leave blank to use selection)", id="new-product")
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next  ▸", id="next", variant="primary")

    def on_mount(self) -> None:
        listing = self.query_one("#product-list", OptionList)
        products = self.wizard.state.workspace.products if self.wizard.state.workspace else []
        for product in products:
            label = str(product.get("name") or product.get("id") or "(unnamed)")
            listing.add_option(Option(label, id=str(product.get("id"))))
        if products:
            listing.focus()
        else:
            self.query_one("#new-product", Input).focus()

    def action_submit(self) -> None:
        self._advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()

    def _advance(self) -> None:
        new_name = self.query_one("#new-product", Input).value.strip()
        if new_name:
            self.wizard.state.plan.create_product = new_name
            self.wizard.state.plan.use_product_id = None
        else:
            listing = self.query_one("#product-list", OptionList)
            if listing.highlighted is None:
                self.app.bell()
                return
            option = listing.get_option_at_index(listing.highlighted)
            self.wizard.state.plan.use_product_id = option.id
            self.wizard.state.plan.create_product = None
        from sbomify_action.cli.wizard.screens.configure import ConfigureScreen

        self.wizard.push_screen(ConfigureScreen())

    def _help_text(self) -> str:
        count = len(self.wizard.state.workspace.products) if self.wizard.state.workspace else 0
        return f"{count} existing product(s). Use [b]↑/↓[/] to navigate, [b]Enter[/] to pick."
