"""Configure screen — collect per-component name + augmentation + release strategy.

The wizard steps through `state.selected` one component at a time on a
single screen, rebuilding the body for each step. This keeps the screen
stack shallow and lets us show "Component 2 of 5" in the subtitle so
users know where they are.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, RadioButton, RadioSet, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import (
    AugmentationStrategy,
    PlannedComponent,
    ReleaseStrategy,
)


class ConfigureScreen(WizardScreen):
    """Phase 4 — name + augmentation + release strategy, per component."""

    step_index = 5
    step_title = "Configure components"
    step_subtitle = "Name each component, decide on metadata, pick a release strategy."

    BINDINGS = [
        Binding("enter", "next", "Next ▸", show=True, priority=True),
        Binding("escape", "go_back", "Back", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._index = 0
        self._planned: list[PlannedComponent] = []

    def compose_body(self) -> ComposeResult:
        with Vertical(id="component-form", classes="wizard-panel"):
            yield Static("", id="component-title", markup=True, classes="wizard-title")
            yield Static("", id="component-hint", markup=True, classes="wizard-muted")
            yield Label("Component name:")
            yield Input(placeholder="my-service", id="name")
            yield Static("")
            yield Label("Metadata / contacts:")
            with RadioSet(id="augmentation"):
                profiles = self.wizard.state.workspace.contact_profiles if self.wizard.state.workspace else []
                yield RadioButton(
                    f"Use a contact profile saved on sbomify  ({len(profiles)} available)",
                    id="aug-profile",
                    value=bool(profiles),
                    disabled=not profiles,
                )
                yield RadioButton(
                    "Skip — leave metadata blank for now",
                    id="aug-skip",
                    value=not profiles,
                )
            with Vertical(id="profile-pane"):
                yield Label("Pick a profile:")
                with RadioSet(id="profile-picker"):
                    yield from self._profile_options()
            yield Static("")
            yield Label("Release tracking:")
            with RadioSet(id="release"):
                has_tags = self.wizard.state.facts.has_release_tags
                yield RadioButton("Latest only  (every push = version)", id="rel-latest", value=not has_tags)
                yield RadioButton(
                    f"Git tags  (v*-tagged commits){' — recommended' if has_tags else ''}", id="rel-tag", value=has_tags
                )
                yield RadioButton("Manual  (workflow_dispatch)", id="rel-manual")
                yield RadioButton("Don't track releases", id="rel-none")
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next ▸", id="next", variant="primary")

    def _profile_options(self) -> list[RadioButton]:
        profiles = self.wizard.state.workspace.contact_profiles if self.wizard.state.workspace else []
        buttons: list[RadioButton] = []
        for i, profile in enumerate(profiles):
            name = str(profile.get("name") or profile.get("id") or "(unnamed)")
            pid = str(profile.get("id") or "")
            buttons.append(RadioButton(name, value=i == 0, id=f"profile-{pid}", name=pid))
        return buttons

    def on_mount(self) -> None:
        self._load_current()

    def _load_current(self) -> None:
        selected = self.wizard.state.selected
        total = len(selected)
        if self._index >= total:
            self._finalise()
            return
        lf = selected[self._index]
        existing_names = {
            c.get("name") for c in (self.wizard.state.workspace.components if self.wizard.state.workspace else [])
        }
        suggested = lf.suggested_name
        # Suffix to avoid collisions with existing components
        if suggested in existing_names:
            base = suggested
            n = 2
            while f"{base}-{n}" in existing_names:
                n += 1
            suggested = f"{base}-{n}"

        self.query_one("#component-title", Static).update(
            f"[b #8A7DFF]Component {self._index + 1} of {total}[/]  [#CBCCCE]·[/]  {lf.rel_path}"
        )
        self.query_one("#component-hint", Static).update(
            f"[#CBCCCE]Ecosystem: [#F4B57F]{lf.ecosystem}[/]   Suggested name derived from the lockfile path.[/]"
        )
        name_input = self.query_one("#name", Input)
        name_input.value = suggested
        name_input.focus()
        self._sync_profile_pane()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if event.radio_set.id == "augmentation":
            self._sync_profile_pane()

    def _sync_profile_pane(self) -> None:
        use_profile = self.query_one("#aug-profile", RadioButton).value
        pane = self.query_one("#profile-pane", Vertical)
        pane.display = use_profile

    def action_next(self) -> None:
        self._commit_current()

    def action_go_back(self) -> None:
        if self._index == 0:
            self.app.pop_screen()
            return
        # Step backward within the same screen.
        self._index -= 1
        # Pre-populate the form with whatever the user picked previously,
        # if available. The simplest implementation is to drop the previous
        # entry and let them redo it.
        if self._planned:
            self._planned.pop()
        self._load_current()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.action_go_back()
        elif event.button.id == "next":
            self._commit_current()

    def _commit_current(self) -> None:
        name = self.query_one("#name", Input).value.strip()
        if not name:
            self.app.bell()
            return

        aug: AugmentationStrategy = "skip"
        profile_id: str | None = None
        if self.query_one("#aug-profile", RadioButton).value:
            aug = "profile"
            picker = self.query_one("#profile-picker", RadioSet)
            pressed = picker.pressed_button
            if pressed is None or pressed.name is None:
                self.app.bell()
                return
            profile_id = pressed.name

        release: ReleaseStrategy = "latest"
        for radio_id, value in (
            ("rel-latest", "latest"),
            ("rel-tag", "tag"),
            ("rel-manual", "manual"),
            ("rel-none", "none"),
        ):
            if self.query_one(f"#{radio_id}", RadioButton).value:
                release = value  # type: ignore[assignment]
                break

        lockfile = self.wizard.state.selected[self._index]
        self._planned.append(
            PlannedComponent(
                lockfile=lockfile,
                name=name,
                augmentation=aug,
                profile_id=profile_id,
                release_strategy=release,
            )
        )
        self._index += 1
        if self._index >= len(self.wizard.state.selected):
            self._finalise()
        else:
            self._load_current()

    def _finalise(self) -> None:
        plan = self.wizard.state.plan
        plan.create_components = list(self._planned)
        plan.create_initial_release = any(c.release_strategy == "tag" for c in self._planned)
        from sbomify_action.cli.wizard.screens.review import ReviewScreen

        self.wizard.push_screen(ReviewScreen())


# Helper alias for type-checker friendliness; not exported.
_Profile = dict[str, Any]
