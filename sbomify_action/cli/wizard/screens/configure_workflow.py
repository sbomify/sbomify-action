"""Configure (workflow shape) — release strategy + credentials.

The first of the two Configure screens. Answers the "when and how
does this workflow run?" half of the configuration. Pairs with
``ConfigureSbomScreen`` which handles the "what does each SBOM
contain (and where does its metadata come from)?" half.

Metadata-source controls — enrichment + augmentation / contact
profile binding — live on the SBOM-content screen since they shape
what lands in the SBOM, not when the workflow fires.
"""

from __future__ import annotations

from typing import cast

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, RadioSet

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import (
    CredentialMode,
    ReleaseStrategy,
)
from sbomify_action.cli.wizard.widgets import StatefulRadioButton as RadioButton


class ConfigureWorkflowScreen(WizardScreen):
    """Phase 6 — workflow shape: release strategy + credentials."""

    step_index = 6
    step_title = "Configure (workflow)"
    step_subtitle = "When the workflow fires and how it authenticates."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True, priority=True),
    ]

    def compose_body(self) -> ComposeResult:
        has_tags = self.wizard.state.facts.has_release_tags

        release = Vertical(classes="wizard-panel")
        release.border_title = "◆  Release strategy"
        release.border_subtitle = "when the workflow fires"
        with release:
            with RadioSet(id="release"):
                yield RadioButton(
                    "Trunk — every push to the default branch",
                    id="rel-trunk",
                    value=not has_tags,
                )
                yield RadioButton(
                    "Tag — version tags (v1.2.3 or 2026.7.1)" + ("  [#86EFAC]✓ recommended[/]" if has_tags else ""),
                    id="rel-tag",
                    value=has_tags,
                )
                yield RadioButton("Manual — workflow_dispatch only", id="rel-manual")

        cred = Vertical(classes="wizard-panel")
        cred.border_title = "◆  Credentials"
        cred.border_subtitle = "how the workflow authenticates"
        with cred:
            with RadioSet(id="credential"):
                yield RadioButton(
                    "OIDC trusted publishing — no token secret  [#86EFAC]✓ recommended[/]",
                    id="cred-oidc",
                    value=True,
                )
                yield RadioButton("Token — uses SBOMIFY_TOKEN secret", id="cred-token")

    def compose_actions(self) -> ComposeResult:
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next  ▸", id="next", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#release", RadioSet).focus()

    def action_submit(self) -> None:
        self.route_enter(self._advance)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()

    def _advance(self) -> None:
        plan = self.wizard.state.plan
        plan.release_strategy = self._selected_release_strategy()
        plan.credential_mode = self._selected_credential_mode()

        from sbomify_action.cli.wizard.screens.configure_sbom import ConfigureSbomScreen

        self.wizard.push_screen(ConfigureSbomScreen())

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
