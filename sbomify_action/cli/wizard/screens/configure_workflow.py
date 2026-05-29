"""Configure (workflow shape) — release strategy, credentials, augmentation.

The first of the two Configure screens. Answers the "when and how
does this workflow run?" half of the configuration. Pairs with
``ConfigureSbomScreen`` which handles the "what does each SBOM
contain?" half.
"""

from __future__ import annotations

from typing import cast

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, OptionList, RadioButton, RadioSet, Static
from textual.widgets.option_list import Option

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import (
    AugmentationStrategy,
    CredentialMode,
    ReleaseStrategy,
)


class ConfigureWorkflowScreen(WizardScreen):
    """Phase 6 — workflow shape: release strategy / credentials / augmentation."""

    step_index = 6
    step_title = "Configure (workflow)"
    step_subtitle = "When the workflow fires, how it authenticates, and how it sources metadata."

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
                    "Tag — v* git tags" + ("  [#86EFAC]✓ recommended[/]" if has_tags else ""),
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

        # Augmentation: skip vs bind a contact profile to every component.
        # When there are no contact profiles in the workspace, the profile
        # option is disabled — there's nothing for the wizard to bind, and
        # AUGMENT=true with no bound profile silently no-ops at workflow
        # run time. The picker beneath only matters when the user picks
        # the profile radio.
        profiles = self.wizard.state.workspace.contact_profiles if self.wizard.state.workspace else []
        self._profiles = [
            (str(p.get("name") or p.get("id") or "(unnamed)"), str(p.get("id"))) for p in profiles if p.get("id")
        ]
        aug = Vertical(classes="wizard-panel")
        aug.border_title = "◆  Augmentation"
        aug.border_subtitle = "supplier / contacts metadata"
        with aug:
            with RadioSet(id="augmentation"):
                yield RadioButton("Skip — leave metadata blank for now", id="aug-skip", value=True)
                if self._profiles:
                    yield RadioButton(
                        "Use a contact profile  (AUGMENT=true, bound to every component)",
                        id="aug-profile",
                    )
                else:
                    # No profiles available — render the option but make it
                    # clear why it isn't selectable.
                    rb = RadioButton(
                        "[#5E5E5E]Use a contact profile — none configured in this workspace[/]",
                        id="aug-profile",
                    )
                    rb.disabled = True
                    yield rb
            # Inline picker — hidden until the profile radio is selected so
            # the screen doesn't promise something the user can't act on.
            picker = OptionList(
                *[Option(label, id=pid) for label, pid in self._profiles],
                id="profile-picker",
            )
            picker.display = False
            yield picker
            help_text = Static(
                "[#5E5E5E]Pick which profile binds to every applied component. "
                "AUGMENT=true at workflow run time reads contact_profile_id off "
                "the component on the backend.[/]",
                id="profile-help",
                markup=True,
            )
            help_text.display = False
            yield help_text

        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next  ▸", id="next", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#release", RadioSet).focus()

    def action_submit(self) -> None:
        self.route_enter(self._advance)

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Show / hide the profile picker as the augmentation radio toggles.

        The picker would otherwise be visible and focusable even when the
        user has 'Skip' highlighted — promising an action the wizard
        won't actually take. Toggling visibility keeps the screen honest
        about what the current selection does.
        """
        if event.radio_set.id != "augmentation":
            return
        is_profile = event.pressed.id == "aug-profile" and bool(self._profiles)
        picker = self.query_one("#profile-picker", OptionList)
        help_text = self.query_one("#profile-help", Static)
        picker.display = is_profile
        help_text.display = is_profile
        if is_profile:
            # Default-pick the first profile so 'Next' on a fresh toggle
            # doesn't require an extra arrow-key + Enter combo.
            if picker.highlighted is None:
                picker.highlighted = 0
            picker.focus()

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
        # contact_profile_id is only meaningful when we're actually
        # binding a profile; clear it on every advance so a user who
        # toggles Profile -> Skip doesn't leave a stale id on the plan.
        if plan.augmentation == "profile":
            plan.contact_profile_id = self._selected_profile_id()
            if plan.contact_profile_id is None:
                # The radio said 'profile' but the picker had no selection.
                # Fall back to skip rather than emit AUGMENT=true with no
                # binding — silent no-op at workflow time would be worse.
                plan.augmentation = "skip"
        else:
            plan.contact_profile_id = None

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

    def _selected_augmentation(self) -> AugmentationStrategy:
        pressed = self.query_one("#augmentation", RadioSet).pressed_button
        if pressed is None:
            return "skip"
        return cast(AugmentationStrategy, pressed.id.split("-", 1)[1] if pressed.id else "skip")

    def _selected_profile_id(self) -> str | None:
        """Read the picker's highlighted profile id, or None when nothing
        is highlighted (eg the user toggled to 'profile' but never moved
        focus into the picker)."""
        picker = self.query_one("#profile-picker", OptionList)
        if picker.highlighted is None:
            return None
        option = picker.get_option_at_index(picker.highlighted)
        return option.id
