"""Product picker — choose an existing product or create a new one."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, RadioButton, RadioSet, Static

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

    def compose_body(self) -> ComposeResult:
        products = self.wizard.state.workspace.products if self.wizard.state.workspace else []
        with Vertical(classes="wizard-panel"):
            yield Static("[b #8A7DFF]Product[/]", classes="wizard-title")
            yield Static(
                f"[#CBCCCE]You have [#F4B57F]{len(products)}[/] product(s) on sbomify.[/]",
                classes="wizard-muted",
            )
            with RadioSet(id="mode"):
                yield RadioButton(
                    "Use an existing product",
                    value=bool(products),
                    id="mode-existing",
                    disabled=not products,
                )
                yield RadioButton("Create a new product", value=not products, id="mode-create")

            yield Static("", classes="wizard-muted")  # spacer

            with Vertical(id="existing-pane"):
                yield Label("Pick a product:")
                with RadioSet(id="product-picker"):
                    suggested = (self.wizard.state.facts.suggested_repo_name or "").lower()
                    # Pre-select either the repo-name match or, failing that,
                    # the first product so `pressed_button` is never None when
                    # the user hits Enter.
                    name_match_idx = next(
                        (i for i, p in enumerate(products) if str(p.get("name") or "").lower() == suggested),
                        0 if products else -1,
                    )
                    for i, prod in enumerate(products):
                        name = str(prod.get("name") or "(unnamed)")
                        product_id = str(prod.get("id"))
                        yield RadioButton(
                            name,
                            value=i == name_match_idx,
                            id=f"prod-{product_id}",
                            name=product_id,
                        )

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
        self.query_one("#mode", RadioSet).focus()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if event.radio_set.id == "mode":
            self._sync_panes()

    def _sync_panes(self) -> None:
        mode_create = self.query_one("#mode-create", RadioButton).value
        self.query_one("#existing-pane", Vertical).display = not mode_create
        self.query_one("#create-pane", Vertical).display = mode_create

    def action_confirm(self) -> None:
        self._commit()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "new-product-name":
            self._commit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "continue":
            self._commit()

    def _commit(self) -> None:
        mode_create = self.query_one("#mode-create", RadioButton).value
        plan = self.wizard.state.plan
        if mode_create:
            name = self.query_one("#new-product-name", Input).value.strip()
            if not name:
                self.app.bell()
                return
            plan.create_product = name
            plan.use_product_id = None
        else:
            picker = self.query_one("#product-picker", RadioSet)
            selected = picker.pressed_button
            if selected is None or selected.name is None:
                self.app.bell()
                return
            plan.create_product = None
            plan.use_product_id = selected.name
        from sbomify_action.cli.wizard.screens.configure import ConfigureScreen

        self.wizard.push_screen(ConfigureScreen())
