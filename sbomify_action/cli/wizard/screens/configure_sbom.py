"""Configure (SBOM content) — enrichment, augmentation, formats, build provenance.

The second of the two Configure screens. Answers the "what does each
SBOM contain (and where does its metadata come from)?" half of the
configuration. Pairs with ``ConfigureWorkflowScreen`` which handles
the "when/how does the workflow run?" half.

Enrichment and augmentation are grouped together because they're both
metadata-source choices — enrichment pulls package data from external
registries (PyPI, deps.dev, Repology), augmentation pulls organisational
metadata (supplier / contacts) from a sbomify contact profile.
"""

from __future__ import annotations

from typing import cast

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, OptionList, RadioButton, RadioSet, Static
from textual.widgets.option_list import Option

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import AugmentationStrategy, SbomFormat


class ConfigureSbomScreen(WizardScreen):
    """Phase 7 — SBOM content: enrichment / augmentation / formats / provenance."""

    step_index = 7
    step_title = "Configure (SBOM)"
    step_subtitle = "What goes into each SBOM, where its metadata comes from, and whether to sign the build."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True, priority=True),
    ]

    def compose_body(self) -> ComposeResult:
        enrich = Vertical(classes="wizard-panel")
        enrich.border_title = "◆  Enrichment"
        enrich.border_subtitle = "external package metadata (licenses, identifiers, lifecycle)"
        with enrich:
            yield Static(
                "[#5E5E5E]Lockfiles list package names + versions but rarely carry licenses, "
                "PURLs/CPEs, or EOL dates — leaving SBOMs that fail vulnerability matching, "
                "license compliance, and [b]NTIA minimum elements[/]. Enrichment fills these "
                "from package registries (PyPI, crates.io, deps.dev, Repology, LicenseDB) "
                "so the SBOMs the workflow produces meet the bar regulators ask for.[/]",
                classes="wizard-muted",
            )
            with RadioSet(id="enrich"):
                yield RadioButton(
                    "Enrich packages from external registries  [#86EFAC]✓ recommended[/]",
                    id="enrich-yes",
                    value=True,
                )
                yield RadioButton("Skip enrichment — lockfile data only", id="enrich-no")

        # Augmentation: skip vs bind a contact profile to every component.
        # When the workspace has no contact profiles the profile option
        # is disabled — there's nothing for the wizard to bind, and
        # AUGMENT=true with no bound profile silently no-ops at workflow
        # run time. The picker beneath only matters when the user picks
        # the profile radio.
        profiles = self.wizard.state.workspace.contact_profiles if self.wizard.state.workspace else []
        self._profiles = [
            (str(p.get("name") or p.get("id") or "(unnamed)"), str(p.get("id"))) for p in profiles if p.get("id")
        ]
        aug = Vertical(classes="wizard-panel")
        aug.border_title = "◆  Augmentation"
        aug.border_subtitle = "organisational metadata (supplier, contacts) from sbomify"
        with aug:
            with RadioSet(id="augmentation"):
                yield RadioButton("Skip — leave metadata blank for now", id="aug-skip", value=True)
                if self._profiles:
                    yield RadioButton(
                        "Use a contact profile  (AUGMENT=true, bound to every component)",
                        id="aug-profile",
                    )
                else:
                    rb = RadioButton(
                        "[#5E5E5E]Use a contact profile — none configured in this workspace[/]",
                        id="aug-profile",
                    )
                    rb.disabled = True
                    yield rb
            picker = OptionList(
                *[Option(label, id=pid) for label, pid in self._profiles],
                id="profile-picker",
            )
            picker.display = False
            yield picker
            help_text = Static(
                "[#5E5E5E]The selected profile contributes supplier and author metadata to "
                "every SBOM this workflow generates — both are minimum elements under "
                "[b]NTIA[/], [b]CISA[/], and the [b]EU Cyber Resilience Act[/], so SBOMs without "
                "them fail compliance checks. Same profile applies to every component; re-run "
                "the wizard to change it.[/]",
                id="profile-help",
                markup=True,
            )
            help_text.display = False
            yield help_text
            # Shown only when the workspace has zero profiles — points
            # the user at the sbomify UI path where they can create
            # one. Without it the disabled radio leaves them with no
            # obvious next step.
            if not self._profiles:
                yield Static(
                    "[#5E5E5E]◌  Create a contact profile in the sbomify UI under "
                    "[b]Settings → Contacts[/], then re-run the wizard to bind it.[/]",
                    id="profile-empty-hint",
                    markup=True,
                )

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
            "[#F4B57F]⚠  Private repository[/]" if visibility == "private" else "[#5E5E5E]◌  Visibility unknown[/]"
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
        plan.enrich = self._selected_enrich()
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
        plan.sbom_formats = self._selected_formats()
        plan.attestation = self._selected_attestation()

        from sbomify_action.cli.wizard.screens.review import ReviewScreen

        self.wizard.push_screen(ReviewScreen())

    def _selected_enrich(self) -> bool:
        pressed = self.query_one("#enrich", RadioSet).pressed_button
        if pressed is None:
            return True
        return pressed.id == "enrich-yes"

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
