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
    SbomFormat,
)


class ConfigureScreen(WizardScreen):
    """Phase 5 — file-wide settings + component names."""

    step_index = 5
    step_title = "Configure"
    step_subtitle = "Pick the workflow's release strategy, credentials, and name each component."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        # Priority so the per-component name Inputs don't swallow Escape.
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

        aug = Vertical(classes="wizard-panel")
        aug.border_title = "◆  Augmentation"
        aug.border_subtitle = "supplier / contacts metadata"
        with aug:
            with RadioSet(id="augmentation"):
                yield RadioButton("Skip — leave metadata blank for now", id="aug-skip", value=True)
                yield RadioButton("Use a contact profile  (AUGMENT=true)", id="aug-profile")

        fmt = Vertical(classes="wizard-panel")
        fmt.border_title = "◆  SBOM formats"
        fmt.border_subtitle = "one matrix row per format"
        with fmt:
            with RadioSet(id="formats"):
                yield RadioButton(
                    "CycloneDX  [#86EFAC]✓ recommended[/]",
                    id="fmt-cdx",
                    value=True,
                )
                yield RadioButton("SPDX", id="fmt-spdx")
                yield RadioButton("Both CycloneDX and SPDX", id="fmt-both")

        attest = Vertical(classes="wizard-panel")
        attest.border_title = "◆  Build provenance"
        attest.border_subtitle = "signed attestations via sigstore"
        with attest:
            yield Static(
                "[#86EFAC]✓  Supported[/]\n"
                "    • Public repos on any GitHub plan  (public-good Sigstore)\n"
                "    • Private/internal repos on [b]GitHub Enterprise Cloud[/]  (private Sigstore)\n"
                "[#F87171]✗  Not supported[/]\n"
                "    • Private/internal repos on Free, Pro, or Team — the workflow will fail\n"
                "    • Any repo on GitHub Enterprise Server\n"
                "[#5E5E5E]The same note is emitted as a comment in the generated workflow.[/]",
                classes="wizard-muted",
            )
            with RadioSet(id="attestation"):
                yield RadioButton("Skip provenance attestation", id="attest-no", value=True)
                yield RadioButton(
                    "Sign SBOMs with attest-build-provenance  [#86EFAC]✓ recommended for releases[/]",
                    id="attest-yes",
                )

        names = Vertical(classes="wizard-panel")
        names.border_title = "◆  Component names"
        names.border_subtitle = f"{len(self.wizard.state.selected)} component(s)"
        with names:
            yield Static(
                "Each lockfile maps to one sbomify component. Defaults are derived from the repo + ecosystem.",
                classes="wizard-muted",
            )
            for idx, lockfile in enumerate(self.wizard.state.selected):
                yield Label(f"[#CBCCCE]{lockfile.rel_path}[/]  [#5E5E5E]({lockfile.ecosystem})[/]")
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
        plan.sbom_formats = self._selected_formats()
        plan.attestation = self._selected_attestation()
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

    def _selected_formats(self) -> list[SbomFormat]:
        pressed = self.query_one("#formats", RadioSet).pressed_button
        if pressed is None or pressed.id == "fmt-cdx":
            return ["cyclonedx"]
        if pressed.id == "fmt-spdx":
            return ["spdx"]
        return ["cyclonedx", "spdx"]

    def _selected_attestation(self) -> bool:
        pressed = self.query_one("#attestation", RadioSet).pressed_button
        return pressed is not None and pressed.id == "attest-yes"
