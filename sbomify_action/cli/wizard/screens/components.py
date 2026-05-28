"""Components screen — pick or create a sbomify component per lockfile.

Lives between Product (where the user picked the workspace product) and
Configure (where the user picks file-wide settings). Per-lockfile, the
user gets two choices:

  * Reuse an existing component from their workspace, OR
  * Create a new one with a name they can override (default derived
    from the repo + ecosystem).

Whichever they choose lands on the matching ``PlannedComponent`` —
``existing_id`` set when they reused, ``name`` carrying the new-or-
reused label either way. ``apply.apply_plan`` reads ``existing_id``
to decide whether to call the create API or just attach the existing
component to the product.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, Select, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import PlannedComponent
from sbomify_action.logging_config import logger


class ComponentsScreen(WizardScreen):
    """Phase 5 — pick or create a component per selected lockfile."""

    step_index = 5
    step_title = "Components"
    step_subtitle = "Reuse an existing sbomify component or create a new one for each lockfile."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        # priority so the per-lockfile name Inputs don't swallow Escape.
        Binding("escape", "app.pop_screen", "Back", show=True, priority=True),
    ]

    def compose_body(self) -> ComposeResult:
        existing = self.wizard.state.workspace.components if self.wizard.state.workspace else []
        panel = Vertical(classes="wizard-panel")
        panel.border_title = "◆  Components"
        panel.border_subtitle = (
            f"{len(self.wizard.state.selected)} lockfile(s) · {len(existing)} existing"
        )
        with panel:
            yield Static(
                "One component per lockfile. Reuse an existing one or create a "
                "new one — the suggested name is derived from the repo + ecosystem.",
                classes="wizard-muted",
            )
            for idx, lockfile in enumerate(self.wizard.state.selected):
                yield Label(
                    f"[#CBCCCE]{lockfile.rel_path}[/]  [#5E5E5E]({lockfile.ecosystem})[/]"
                )
                if existing:
                    options: list[tuple[str, str]] = [
                        ("➕  Create a new component", "__new__"),
                    ]
                    options.extend(
                        (str(c.get("name") or c.get("id") or "(unnamed)"), str(c.get("id")))
                        for c in existing
                    )
                    yield Select(
                        options,
                        value="__new__",
                        allow_blank=False,
                        id=f"component-{idx}",
                    )
                yield Input(
                    value=lockfile.suggested_name,
                    placeholder=(
                        "New component name (ignored if you picked an existing one above)"
                    ),
                    id=f"name-{idx}",
                )
        yield Static("", id="components-status", markup=True)
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next  ▸", id="next", variant="primary")

    def on_mount(self) -> None:
        if not self.wizard.state.selected:
            return
        existing = self.wizard.state.workspace.components if self.wizard.state.workspace else []
        if existing:
            self.query_one("#component-0", Select).focus()
        else:
            self.query_one("#name-0", Input).focus()

    def action_submit(self) -> None:
        self._advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()

    def _advance(self) -> None:
        plan = self.wizard.state.plan
        existing = self.wizard.state.workspace.components if self.wizard.state.workspace else []
        plan.create_components = []
        for idx, lockfile in enumerate(self.wizard.state.selected):
            if existing:
                select_value = str(self.query_one(f"#component-{idx}", Select).value)
            else:
                select_value = "__new__"

            if select_value == "__new__":
                name = self.query_one(f"#name-{idx}", Input).value.strip() or lockfile.suggested_name
                plan.create_components.append(PlannedComponent(lockfile=lockfile, name=name))
                logger.debug("Components: will create %r for %s", name, lockfile.rel_path)
            else:
                comp = next(c for c in existing if str(c.get("id")) == select_value)
                name = str(comp.get("name") or comp.get("id") or "(unnamed)")
                plan.create_components.append(
                    PlannedComponent(lockfile=lockfile, name=name, existing_id=select_value)
                )
                logger.debug(
                    "Components: will reuse %s (id=%s) for %s",
                    name,
                    select_value,
                    lockfile.rel_path,
                )

        from sbomify_action.cli.wizard.screens.configure import ConfigureScreen

        self.wizard.push_screen(ConfigureScreen())
