"""Configure (SBOM content) — enrichment, formats, build provenance.

The second of the two Configure screens. Answers the "what does each
SBOM contain?" half of the configuration. Pairs with
``ConfigureWorkflowScreen`` which handles the "when/how does the
workflow run?" half.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, RadioButton, RadioSet, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import SbomFormat


class ConfigureSbomScreen(WizardScreen):
    """Phase 7 — SBOM content: enrichment / formats / build provenance."""

    step_index = 7
    step_title = "Configure (SBOM)"
    step_subtitle = "What goes into each SBOM and whether to sign the build."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True, priority=True),
    ]

    def compose_body(self) -> ComposeResult:
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

        # Public/unknown repos default to "attest"; private repos
        # default to "skip" because attestation needs GHEC on private.
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
        """Visibility-gated note above the attestation radio set."""
        visibility = self.wizard.state.facts.visibility
        if visibility == "public":
            return (
                "[#86EFAC]✓  Public repository[/] — attestation is supported on any GitHub plan, "
                "signed via the public-good Sigstore instance.\n"
                "[#5E5E5E]The same note is emitted as a comment in the generated workflow.[/]"
            )
        warning_tone = (
            "[#F4B57F]⚠  Private repository[/]"
            if visibility == "private"
            else "[#5E5E5E]◌  Visibility unknown[/]"
        )
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
        self.query_one("#enrich", RadioSet).focus()

    def action_submit(self) -> None:
        self._advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()

    def _advance(self) -> None:
        plan = self.wizard.state.plan
        plan.enrich = self._selected_enrich()
        plan.sbom_formats = self._selected_formats()
        plan.attestation = self._selected_attestation()

        from sbomify_action.cli.wizard.screens.review import ReviewScreen

        self.wizard.push_screen(ReviewScreen())

    def _selected_enrich(self) -> bool:
        pressed = self.query_one("#enrich", RadioSet).pressed_button
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
