"""Product screen — pick an existing product or create a new one."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, OptionList, Static
from textual.widgets.option_list import Option

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.logging_config import logger


class ProductScreen(WizardScreen):
    """Phase 4 — pick or create the product these components attach to."""

    step_index = 4
    step_title = "Pick a product"
    step_subtitle = "Components attach to a product. Pick an existing one or create a new one."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        # Priority so the new-product Input doesn't swallow Escape.
        Binding("escape", "app.pop_screen", "Back", show=True, priority=True),
    ]

    def compose_body(self) -> ComposeResult:
        product_count = len(self.wizard.state.workspace.products) if self.wizard.state.workspace else 0
        panel = Vertical(classes="wizard-panel")
        panel.border_title = "◆  Pick a product"
        panel.border_subtitle = f"{product_count} existing"
        with panel:
            yield Static(self._help_text(), classes="wizard-muted")
            yield OptionList(id="product-list")
            yield Static("[#5E5E5E]Or create a new one:[/]", classes="wizard-muted")
            yield Input(placeholder="New product name (leave blank to use selection)", id="new-product")
            yield Static("", id="product-status", markup=True)
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
            # Pre-highlight the first row so the user can press Enter
            # immediately without an arrow keypress. Without this, the
            # OptionList focuses with no cursor, _advance() sees
            # highlighted=None, hits app.bell(), and the screen looks
            # frozen.
            listing.highlighted = 0
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
        status = self.query_one("#product-status", Static)
        if new_name:
            self.wizard.state.plan.create_product = new_name
            self.wizard.state.plan.use_product_id = None
            logger.debug("Product screen: will create new product %r", new_name)
        else:
            listing = self.query_one("#product-list", OptionList)
            if listing.highlighted is None:
                # Defensive — on_mount pre-highlights the first row when
                # any products exist, so we should only reach this with
                # an empty product list AND an empty new-product input.
                status.update(
                    "[#F87171]Pick a product from the list, or type a new product name below.[/]"
                )
                self.app.bell()
                return
            option = listing.get_option_at_index(listing.highlighted)
            if option.id is None:
                status.update("[#F87171]Selected product has no id; please pick another.[/]")
                self.app.bell()
                return
            self.wizard.state.plan.use_product_id = option.id
            self.wizard.state.plan.create_product = None
            logger.debug("Product screen: will use existing product id=%s", option.id)
        from sbomify_action.cli.wizard.screens.configure import ConfigureScreen

        self.wizard.push_screen(ConfigureScreen())

    def _help_text(self) -> str:
        count = len(self.wizard.state.workspace.products) if self.wizard.state.workspace else 0
        return f"{count} existing product(s). Use [b]↑/↓[/] to navigate, [b]Enter[/] to pick."
