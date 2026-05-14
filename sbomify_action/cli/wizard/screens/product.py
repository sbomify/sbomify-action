"""Product picker — choose an existing product or create a new one.

Existing products are rendered as a filterable, scrollable `OptionList`
(not a `RadioSet`) because workspaces routinely contain dozens or hundreds
of products. A filter `Input` above the list narrows results live as the
user types; pressing `↓` moves focus into the list for arrow navigation
and `Enter` commits the highlighted entry.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, OptionList, RadioButton, RadioSet, Static
from textual.widgets.option_list import Option

from sbomify_action.cli.wizard.screens._base import WizardScreen


class ProductScreen(WizardScreen):
    """Phase 3 — pick or create a Product."""

    step_index = 4
    step_title = "Product"
    step_subtitle = "Components on sbomify are grouped under a Product. Pick one or create a new one."

    BINDINGS = [
        Binding("enter", "confirm", "Continue", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._products: list[dict[str, Any]] = []
        # The list-driven default pick — used to pre-select a row that
        # matches the repo name, or fall back to the first product.
        self._default_product_id: str | None = None

    def compose_body(self) -> ComposeResult:
        self._products = list(self.wizard.state.workspace.products if self.wizard.state.workspace else [])
        suggested = (self.wizard.state.facts.suggested_repo_name or "").lower()
        match = next(
            (p for p in self._products if str(p.get("name") or "").lower() == suggested),
            self._products[0] if self._products else None,
        )
        self._default_product_id = str(match["id"]) if match else None

        with Vertical(classes="wizard-panel"):
            yield Static("[b #8A7DFF]Product[/]", classes="wizard-title")
            yield Static(
                f"[#CBCCCE]You have [#F4B57F]{len(self._products)}[/] product(s) on sbomify.[/]",
                classes="wizard-muted",
            )
            with RadioSet(id="mode"):
                yield RadioButton(
                    "Use an existing product",
                    value=bool(self._products),
                    id="mode-existing",
                    disabled=not self._products,
                )
                yield RadioButton("Create a new product", value=not self._products, id="mode-create")

            with Vertical(id="existing-pane"):
                yield Label("Filter:")
                yield Input(placeholder="Type to filter products…", id="product-filter")
                yield OptionList(id="product-list", classes="wizard-options")
                yield Static("", id="product-empty", classes="wizard-muted")

            with Vertical(id="create-pane"):
                yield Label("Name for the new product:")
                yield Input(
                    value=self.wizard.state.facts.suggested_repo_name or "",
                    placeholder="e.g. acme-platform",
                    id="new-product-name",
                )
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Continue  ▸", id="continue", variant="primary")

    def on_mount(self) -> None:
        self._sync_panes()
        self._populate_list("")
        # Focus the filter input first so users can immediately narrow long lists.
        if self._products:
            self.query_one("#product-filter", Input).focus()
        else:
            self.query_one("#new-product-name", Input).focus()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if event.radio_set.id == "mode":
            self._sync_panes()

    def _sync_panes(self) -> None:
        mode_create = self.query_one("#mode-create", RadioButton).value
        self.query_one("#existing-pane", Vertical).display = not mode_create
        self.query_one("#create-pane", Vertical).display = mode_create

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "product-filter":
            self._populate_list(event.value.strip().lower())

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "product-filter":
            # Enter in the filter input → move focus to the list so the
            # user can navigate with arrows.
            self.query_one("#product-list", OptionList).focus()
        elif event.input.id == "new-product-name":
            self._commit()

    def _populate_list(self, query: str) -> None:
        option_list = self.query_one("#product-list", OptionList)
        option_list.clear_options()
        empty = self.query_one("#product-empty", Static)

        matches = [p for p in self._products if not query or query in str(p.get("name") or "").lower()]

        if not matches:
            empty.update("[#F87171]No products match that filter.[/]")
            return
        empty.update("")

        # Re-pick a sensible default after filtering: prefer the repo-name
        # match if it's still in the result set, else the first row.
        default_id = self._default_product_id
        default_idx = 0
        for i, prod in enumerate(matches):
            label = self._format_option(prod)
            option_list.add_option(Option(label, id=str(prod["id"])))
            if default_id and str(prod["id"]) == default_id:
                default_idx = i
        option_list.highlighted = default_idx

    @staticmethod
    def _format_option(prod: dict[str, Any]) -> str:
        name = str(prod.get("name") or "(unnamed)")
        pid = str(prod.get("id") or "")
        return f"[b]{name}[/]  [#5E5E5E]·[/] [#CBCCCE]{pid}[/]"

    def action_confirm(self) -> None:
        self._commit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "continue":
            self._commit()

    def _commit(self) -> None:
        plan = self.wizard.state.plan
        mode_create = self.query_one("#mode-create", RadioButton).value
        if mode_create:
            name = self.query_one("#new-product-name", Input).value.strip()
            if not name:
                self.app.bell()
                return
            plan.create_product = name
            plan.use_product_id = None
        else:
            option_list = self.query_one("#product-list", OptionList)
            highlighted_idx = option_list.highlighted
            if highlighted_idx is None or option_list.option_count == 0:
                self.app.bell()
                return
            option = option_list.get_option_at_index(highlighted_idx)
            if option.id is None:
                self.app.bell()
                return
            plan.create_product = None
            plan.use_product_id = option.id

        from sbomify_action.cli.wizard.screens.configure import ConfigureScreen

        self.wizard.push_screen(ConfigureScreen())
