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
from textual.widgets import Button, RadioButton, RadioSet, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import (
    AugmentationStrategy,
    CredentialMode,
    ReleaseStrategy,
    SbomFormat,
)


class ConfigureScreen(WizardScreen):
    """Phase 6 — file-wide settings (release / credentials / formats / etc).

    Per-component names + existing-component selection have moved to
    ``ComponentsScreen`` (Phase 5). This screen handles everything
    that's shared across the whole emitted workflow.
    """

    step_index = 6
    step_title = "Configure"
    step_subtitle = "Pick the workflow's release strategy, credentials, formats, and provenance settings."

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

        enrich = Vertical(classes="wizard-panel")
        enrich.border_title = "◆  Enrichment"
        enrich.border_subtitle = "external metadata (licenses, descriptions, …)"
        with enrich:
            with RadioSet(id="enrich"):
                yield RadioButton(
                    "Enrich packages from PyPI / deps.dev / Repology  [#86EFAC]✓ recommended[/]",
                    id="enrich-yes",
                    value=True,
                )
                yield RadioButton("Skip enrichment — lockfile data only", id="enrich-no")

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

        # Attestation default tracks repo visibility: public/unknown
        # repos default to "yes attest" (the recommended path actually
        # works), private repos default to "skip" because attestation
        # will fail on Free/Pro/Team without GHEC.
        attest_default_yes = self.wizard.state.facts.visibility != "private"
        attest = Vertical(classes="wizard-panel")
        attest.border_title = "◆  Build provenance"
        attest.border_subtitle = "signed attestations via sigstore"
        with attest:
            yield Static(self._attestation_note(), classes="wizard-muted")
            with RadioSet(id="attestation"):
                yield RadioButton(
                    "Sign SBOMs with attest-build-provenance  [#86EFAC]✓ recommended for releases[/]",
                    id="attest-yes",
                    value=attest_default_yes,
                )
                yield RadioButton(
                    "Skip provenance attestation",
                    id="attest-no",
                    value=not attest_default_yes,
                )

        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next  ▸", id="next", variant="primary")

    def _attestation_note(self) -> str:
        """Render the attestation panel note, gated by detected repo visibility.

        - Public repo → one-line "✓ supported" so the user isn't scared
          off by an irrelevant warning.
        - Private repo → the full GHEC requirement note (the workflow
          will fail on Free/Pro/Team private repos).
        - Unknown (non-github remote, no network, rate-limited) → the
          same conservative warning, because we can't rule out the
          unsupported case.
        """
        visibility = self.wizard.state.facts.visibility
        if visibility == "public":
            return (
                "[#86EFAC]✓  Public repository[/] — attestation is supported on any GitHub plan, "
                "signed via the public-good Sigstore instance.\n"
                "[#5E5E5E]The same note is emitted as a comment in the generated workflow.[/]"
            )
        warning_tone = "[#F4B57F]⚠  Private repository[/]" if visibility == "private" else "[#5E5E5E]◌  Visibility unknown[/]"
        return (
            f"{warning_tone} — attestation has plan-tier requirements:\n"
            "[#86EFAC]✓  Supported[/]\n"
            "    • Public repos on any GitHub plan  (public-good Sigstore)\n"
            "    • Private/internal repos on [b]GitHub Enterprise Cloud[/]  (private Sigstore)\n"
            "[#F87171]✗  Not supported[/]\n"
            "    • Private/internal repos on Free, Pro, or Team — the workflow will fail\n"
            "    • Any repo on GitHub Enterprise Server\n"
            "[#5E5E5E]The same note is emitted as a comment in the generated workflow.[/]"
        )

    def on_mount(self) -> None:
        # Focus the first radio group so the user can start picking immediately.
        self.query_one("#release", RadioSet).focus()

    def action_submit(self) -> None:
        self._advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()

    def _advance(self) -> None:
        # Per-component name + existing-component selection were collected
        # by ComponentsScreen and are already on plan.create_components.
        # All we set here is the file-wide configuration.
        plan = self.wizard.state.plan
        plan.release_strategy = self._selected_release_strategy()
        plan.credential_mode = self._selected_credential_mode()
        plan.augmentation = self._selected_augmentation()
        plan.enrich = self._selected_enrich()
        plan.sbom_formats = self._selected_formats()
        plan.attestation = self._selected_attestation()

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

    def _selected_enrich(self) -> bool:
        pressed = self.query_one("#enrich", RadioSet).pressed_button
        # No pressed button (shouldn't happen — we pre-select enrich-yes)
        # falls back to the recommended default rather than silently
        # disabling enrichment.
        if pressed is None:
            return True
        return pressed.id == "enrich-yes"

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
