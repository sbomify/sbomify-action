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

UI shape: per lockfile, we render an inline ``OptionList`` showing
"Create new" as the first row followed by every existing component
in the workspace. The list is pre-highlighted on the new-component
row, and we cap its height so a workspace with hundreds of
components stays scrollable instead of dwarfing the screen. Below
the list sits an ``Input`` for the new component name — only read
when the user leaves the highlight on the "Create new" row.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, OptionList, Rule, Static
from textual.widgets.option_list import Option

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import PlannedComponent
from sbomify_action.logging_config import logger

# Sentinel id used for the "Create new component" row at the top of
# each OptionList. Anything else is the actual component's id.
_NEW = "__new__"


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
                opts: list[Option] = [
                    Option("[#86EFAC]➕  Create a new component[/]", id=_NEW),
                ]
                opts.extend(
                    Option(
                        str(c.get("name") or c.get("id") or "(unnamed)"),
                        id=str(c.get("id")),
                    )
                    for c in existing
                )
                yield OptionList(*opts, id=f"component-{idx}")
                yield Input(
                    value=lockfile.suggested_name,
                    placeholder="New component name (used only when 'Create new' is highlighted)",
                    id=f"name-{idx}",
                )
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next  ▸", id="next", variant="primary")

    def on_mount(self) -> None:
        # Pre-highlight the "Create new" row on every OptionList so a
        # user who just hits Enter ends up creating components with the
        # auto-suggested names. Same fix as ProductScreen.
        for idx in range(len(self.wizard.state.selected)):
            try:
                listing = self.query_one(f"#component-{idx}", OptionList)
            except Exception:
                continue
            listing.highlighted = 0
            # The name Input is visible by default in compose_body, so
            # nothing to do for the pre-highlighted "Create new" row.
        if self.wizard.state.selected:
            try:
                self.query_one("#component-0", OptionList).focus()
            except Exception:
                pass

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        """Show the new-component name Input only when 'Create new' is highlighted.

        Existing-component rows hide their matching Input so it can't
        be mistaken for an editable label for the selected component
        (the existing component's real name is shown in the row above).
        This also keeps the screen shorter when picking existing
        components for several lockfiles in a row.
        """
        list_id = event.option_list.id or ""
        if not list_id.startswith("component-"):
            return
        try:
            idx = int(list_id.split("-", 1)[1])
        except ValueError:
            return
        try:
            input_widget = self.query_one(f"#name-{idx}", Input)
        except Exception:
            return
        option_id = event.option.id
        input_widget.display = option_id == _NEW

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
            listing = self.query_one(f"#component-{idx}", OptionList)
            highlighted = listing.highlighted
            picked_id: str | None
            if highlighted is None:
                picked_id = _NEW
            else:
                option = listing.get_option_at_index(highlighted)
                picked_id = option.id

            if picked_id is None or picked_id == _NEW:
                name = (
                    self.query_one(f"#name-{idx}", Input).value.strip()
                    or lockfile.suggested_name
                )
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
