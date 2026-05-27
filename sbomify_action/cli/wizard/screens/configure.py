"""Configure screen — file-wide settings + per-component names.

The single-matrix-file scope means we ask for the release strategy,
credential mode, and augmentation flag once per workflow, then walk
through each selected lockfile to confirm or override the suggested
component name.
"""

from __future__ import annotations

from typing import cast

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, RadioButton, RadioSet, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import (
    AugmentationStrategy,
    CredentialMode,
    PlannedComponent,
    ReleaseStrategy,
)


class ConfigureScreen(WizardScreen):
    """Phase 5 — file-wide settings + component names."""

    step_index = 5
    step_title = "Configure"
    step_subtitle = "Pick the workflow's release strategy, credentials, and name each component."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        has_tags = self.wizard.state.facts.has_release_tags
        with Vertical(classes="wizard-panel"):
            yield Static("[b]Release strategy[/]", classes="wizard-title")
            with RadioSet(id="release"):
                yield RadioButton(
                    "Trunk (every push to the default branch)",
                    id="rel-trunk",
                    value=not has_tags,
                )
                yield RadioButton(
                    f"Tag (v* git tags){' — recommended' if has_tags else ''}",
                    id="rel-tag",
                    value=has_tags,
                )
                yield RadioButton("Manual (workflow_dispatch only)", id="rel-manual")
        with Vertical(classes="wizard-panel"):
            yield Static("[b]Credentials[/]", classes="wizard-title")
            with RadioSet(id="credential"):
                yield RadioButton(
                    "OIDC trusted publishing — no token secret needed (recommended)",
                    id="cred-oidc",
                    value=True,
                )
                yield RadioButton(
                    "Token (uses SBOMIFY_TOKEN secret)",
                    id="cred-token",
                )
        with Vertical(classes="wizard-panel"):
            yield Static("[b]Augmentation[/]", classes="wizard-title")
            with RadioSet(id="augmentation"):
                yield RadioButton(
                    "Skip — leave metadata blank for now",
                    id="aug-skip",
                    value=True,
                )
                yield RadioButton(
                    "Use a contact profile (set AUGMENT=true)",
                    id="aug-profile",
                )
        with Vertical(classes="wizard-panel"):
            yield Static("[b]Component names[/]", classes="wizard-title")
            yield Static(
                "Each lockfile maps to one sbomify component. Defaults are derived from the repo + ecosystem.",
                classes="wizard-muted",
            )
            for idx, lockfile in enumerate(self.wizard.state.selected):
                yield Label(f"{lockfile.rel_path} ({lockfile.ecosystem})")
                yield Input(value=lockfile.suggested_name, id=f"name-{idx}")
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next  ▸", id="next", variant="primary")

    def on_mount(self) -> None:
        if self.wizard.state.selected:
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
        plan.release_strategy = self._selected_release_strategy()
        plan.credential_mode = self._selected_credential_mode()
        plan.augmentation = self._selected_augmentation()
        plan.create_components = []
        for idx, lockfile in enumerate(self.wizard.state.selected):
            name = self.query_one(f"#name-{idx}", Input).value.strip() or lockfile.suggested_name
            plan.create_components.append(PlannedComponent(lockfile=lockfile, name=name))

        from sbomify_action.cli.wizard.screens.review import ReviewScreen

        self.wizard.push_screen(ReviewScreen())

    def _selected_release_strategy(self) -> ReleaseStrategy:
        pressed = self.query_one("#release", RadioSet).pressed_button
        if pressed is None:
            return "trunk"
        return cast(ReleaseStrategy, pressed.id.split("-", 1)[1] if pressed.id else "trunk")

    def _selected_credential_mode(self) -> CredentialMode:
        pressed = self.query_one("#credential", RadioSet).pressed_button
        if pressed is None:
            return "oidc"
        return cast(CredentialMode, pressed.id.split("-", 1)[1] if pressed.id else "oidc")

    def _selected_augmentation(self) -> AugmentationStrategy:
        pressed = self.query_one("#augmentation", RadioSet).pressed_button
        if pressed is None:
            return "skip"
        return cast(AugmentationStrategy, pressed.id.split("-", 1)[1] if pressed.id else "skip")
