"""Components screen — pick or create a sbomify component per lockfile.

Lives between Product and Configure. For each selected lockfile the
user gets a ``PickOrCreate`` widget — same interaction the Product
screen uses, repeated once per lockfile — so they can either reuse an
existing component or create a new one. Names that match an existing
component exactly default to that component (re-running the wizard
against an already-onboarded workspace doesn't push toward duplicate
creates).
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Label, Rule, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import PlannedComponent
from sbomify_action.cli.wizard.widgets import NEW_SENTINEL, PickOrCreate
from sbomify_action.logging_config import logger


class ComponentsScreen(WizardScreen):
    """Phase 5 — pick or create a component per selected lockfile."""

    step_index = 5
    step_title = "Components"
    step_subtitle = "Reuse an existing sbomify component or create a new one for each lockfile."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True, priority=True),
    ]

    def compose_body(self) -> ComposeResult:
        existing = self.wizard.state.workspace.components if self.wizard.state.workspace else []
        existing_pairs = [
            (str(c.get("name") or c.get("id") or "(unnamed)"), str(c.get("id")))
            for c in existing
            if c.get("id")
        ]
        existing_by_name = {label: item_id for label, item_id in existing_pairs}

        panel = Vertical(classes="wizard-panel")
        panel.border_title = "◆  Components"
        panel.border_subtitle = (
            f"{len(self.wizard.state.selected)} lockfile(s) · {len(existing_pairs)} existing"
        )
        with panel:
            yield Static(
                "One component per lockfile. Use [b]↑/↓[/] to highlight an "
                "existing component (or leave on [b]Create new[/]), then "
                "[b]Tab[/] to edit the new-component name. [b]Enter[/] / "
                "[b]Next[/] when done.",
                classes="wizard-muted",
            )
            for idx, lockfile in enumerate(self.wizard.state.selected):
                if idx > 0:
                    yield Rule()
                yield Label(
                    f"[#CBCCCE]{lockfile.rel_path}[/]  [#5E5E5E]({lockfile.ecosystem})[/]"
                )
                yield PickOrCreate(
                    existing=existing_pairs,
                    create_label="[#86EFAC]➕  Create a new component[/]",
                    placeholder=(
                        "New component name (used only when 'Create new' is highlighted)"
                    ),
                    default_new_value=lockfile.suggested_name,
                    # Auto-match by name: if a component called exactly
                    # ``suggested_name`` already exists, default to that
                    # one rather than the "Create new" sentinel.
                    pre_select_id=existing_by_name.get(lockfile.suggested_name),
                    id=f"component-{idx}",
                )
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next  ▸", id="next", variant="primary")

    def on_mount(self) -> None:
        if not self.wizard.state.selected:
            return
        try:
            self.query_one("#component-0", PickOrCreate).focus_list()
        except Exception:  # noqa: BLE001
            pass

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
            picker = self.query_one(f"#component-{idx}", PickOrCreate)
            picked_id = picker.picked_id
            if picked_id is None or picked_id == NEW_SENTINEL:
                name = picker.new_value or lockfile.suggested_name
                plan.create_components.append(PlannedComponent(lockfile=lockfile, name=name))
                logger.debug("Components: will create %r for %s", name, lockfile.rel_path)
            else:
                comp = next(c for c in existing if str(c.get("id")) == picked_id)
                name = str(comp.get("name") or comp.get("id") or "(unnamed)")
                plan.create_components.append(
                    PlannedComponent(lockfile=lockfile, name=name, existing_id=picked_id)
                )
                logger.debug(
                    "Components: will reuse %s (id=%s) for %s",
                    name,
                    picked_id,
                    lockfile.rel_path,
                )

        from sbomify_action.cli.wizard.screens.configure import ConfigureScreen

        self.wizard.push_screen(ConfigureScreen())
