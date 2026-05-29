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
from textual.css.query import NoMatches
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

    def __init__(self) -> None:
        super().__init__()
        # True after _advance has pushed ConfigureSbomifyJsonScreen at
        # least once. on_screen_resume reads this to detect cancel-
        # without-save and flip the augmentation radio back to Skip,
        # breaking the Enter→Escape→Enter loop documented in the
        # earlier code review.
        self._json_form_visited = False

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
        # The picker always shows existing workspace profiles plus a
        # "+ Create new" sentinel at the top — selecting the sentinel
        # pushes CreateProfileScreen which POSTs to the API and returns
        # with the new profile auto-selected. This lets a user with
        # zero profiles bootstrap one from inside the wizard.
        profiles = self.wizard.state.workspace.contact_profiles if self.wizard.state.workspace else []
        self._profiles = [
            (str(p.get("name") or p.get("id") or "(unnamed)"), str(p.get("id"))) for p in profiles if p.get("id")
        ]
        aug = Vertical(classes="wizard-panel")
        aug.border_title = "◆  Augmentation"
        aug.border_subtitle = "organisational metadata (supplier, contacts, authors)"
        with aug:
            yield Static(
                "[#5E5E5E]Lockfiles never carry organisational metadata — who the supplier is, "
                "who authored the SBOM, how to contact security. Both [b]Supplier Name[/] and "
                "[b]Author of SBOM Data[/] are minimum elements under [b]NTIA[/], [b]CISA[/], "
                "and the [b]EU Cyber Resilience Act[/], so SBOMs without them fail compliance "
                "checks. A sbomify contact profile fills these in for every SBOM the workflow "
                "produces.[/]",
                classes="wizard-muted",
            )
            with RadioSet(id="augmentation"):
                yield RadioButton("Skip — leave metadata blank for now", id="aug-skip", value=True)
                yield RadioButton(
                    "Use a contact profile (saved to sbomify)  [#86EFAC]✓ recommended[/]",
                    id="aug-profile",
                )
                yield RadioButton(
                    "Write a sbomify.json file (saved to the repo)",
                    id="aug-json_config",
                )
            picker = OptionList(
                *self._picker_options(),
                id="profile-picker",
            )
            picker.display = False
            yield picker
            help_text = Static(
                "[#5E5E5E]Same profile binds to every component; re-run the wizard to change it. "
                "Pick [b]+ Create new[/] to add one without leaving the wizard.[/]",
                id="profile-help",
                markup=True,
            )
            help_text.display = False
            yield help_text
            # Status / "Edit fields…" affordance shown only when the
            # user has selected the json_config radio. Tells them
            # whether the form has been filled out yet.
            json_status = Static(
                "",
                id="json-config-status",
                markup=True,
            )
            json_status.display = False
            yield json_status

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

    # Sentinel id used by the "+ Create a new profile" row at the top
    # of the picker. Anything else is a real workspace profile id.
    _CREATE_PROFILE_SENTINEL = "__create_new__"

    def _picker_options(self) -> list[Option]:
        """Build the OptionList rows: + Create new + every workspace profile."""
        options: list[Option] = [
            Option(
                "[#86EFAC]+ Create a new profile[/]",
                id=self._CREATE_PROFILE_SENTINEL,
            )
        ]
        options.extend(Option(label, id=pid) for label, pid in self._profiles)
        return options

    def on_mount(self) -> None:
        self.query_one("#enrich", RadioSet).focus()

    def on_screen_resume(self) -> None:
        """Called when the screen becomes active again after a sub-screen
        pops. If CreateProfileScreen succeeded, the workspace snapshot
        gained a new profile — rebuild the picker so it appears, and
        auto-select it via the id CreateProfileScreen stashed on the
        plan. If ConfigureSbomifyJsonScreen was pushed and the user
        cancelled (no data on the plan), flip the augmentation back
        to Skip so the user isn't trapped in a re-push loop.
        """
        workspace = self.wizard.state.workspace
        if workspace is None:
            return
        # Re-derive the picker contents from the current snapshot.
        self._profiles = [
            (str(p.get("name") or p.get("id") or "(unnamed)"), str(p.get("id")))
            for p in workspace.contact_profiles
            if p.get("id")
        ]
        try:
            picker = self.query_one("#profile-picker", OptionList)
            aug = self.query_one("#augmentation", RadioSet)
        except NoMatches:
            return
        # Snapshot the previous selection so we can preserve it across
        # the clear+add rebuild when there's no fresh auto-select
        # target. Without this, a cancelled CreateProfileScreen leaves
        # picker.highlighted=None and the next Enter silently downgrades
        # augmentation to "skip".
        previous_highlighted_id: str | None = None
        if picker.highlighted is not None:
            try:
                previous_highlighted_id = picker.get_option_at_index(picker.highlighted).id
            except Exception:  # noqa: BLE001
                previous_highlighted_id = None
        picker.clear_options()
        picker.add_options(self._picker_options())
        target_id = self.wizard.state.plan.contact_profile_id
        if target_id:
            # Auto-select the freshly-created profile if CreateProfile
            # stashed its id; flip the augmentation radio so the user
            # sees the success directly.
            for idx, opt in enumerate(self._picker_options()):
                if opt.id == target_id:
                    picker.highlighted = idx
                    break
            self._set_radio_value(aug, target_id="aug-profile")
            picker.display = True
            self.query_one("#profile-help", Static).display = True
        elif previous_highlighted_id is not None:
            # No fresh target → restore the previous selection so the
            # user's prior pick isn't silently wiped by the rebuild.
            for idx, opt in enumerate(self._picker_options()):
                if opt.id == previous_highlighted_id:
                    picker.highlighted = idx
                    break

        # Handle the sbomify.json form return: detect cancel-without-
        # save and flip back to Skip so the user isn't trapped in a
        # form-push loop on subsequent Enter presses.
        pressed = aug.pressed_button
        if (
            self._json_form_visited
            and pressed is not None
            and pressed.id == "aug-json_config"
            and self.wizard.state.plan.sbomify_json_data is None
        ):
            self._json_form_visited = False
            self._set_radio_value(aug, target_id="aug-skip")
            self.notify(
                "Cancelled — augmentation reverted to Skip. Pick the radio again to retry.",
                title="sbomify.json",
                severity="information",
            )
        elif pressed is not None and pressed.id == "aug-json_config":
            self.query_one("#json-config-status", Static).display = True
            self._refresh_json_status()
            if self.wizard.state.plan.sbomify_json_data is not None:
                # Save succeeded → consume the visited flag so a later
                # cancel-cycle isn't misread as the FIRST cancellation.
                self._json_form_visited = False

    @staticmethod
    def _set_radio_value(rs: RadioSet, *, target_id: str) -> None:
        """Force exactly one radio in ``rs`` to be selected by id.

        Iterates RadioButton children and assigns ``value`` — Textual
        fires RadioSet.Changed synchronously per assignment, and the
        intermediate states may briefly leave event.pressed None.
        on_radio_set_changed guards for that case.
        """
        for rb in rs.query(RadioButton):
            rb.value = rb.id == target_id

    def action_submit(self) -> None:
        self.route_enter(self._advance)

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        """Reveal the inputs that match the chosen augmentation strategy.

        Each strategy has its own follow-up: the profile picker for
        ``aug-profile``, a status row pointing at the sbomify.json
        config screen for ``aug-json_config``. Hiding the unused
        controls keeps the screen honest about what the current
        selection does — a visible picker under a ``Skip`` selection
        would be a UI lie.
        """
        # Programmatic mutations (on_screen_resume forcing the radio
        # state to match plan.contact_profile_id) iterate the buttons
        # and assign ``rb.value = …`` for each. Textual fires
        # RadioSet.Changed synchronously per assignment, and the
        # intermediate states can briefly leave event.pressed = None.
        # Guard so a transient None during programmatic toggling
        # doesn't crash the screen.
        if event.radio_set.id != "augmentation" or event.pressed is None:
            return
        is_profile = event.pressed.id == "aug-profile"
        is_json = event.pressed.id == "aug-json_config"
        picker = self.query_one("#profile-picker", OptionList)
        help_text = self.query_one("#profile-help", Static)
        json_status = self.query_one("#json-config-status", Static)
        picker.display = is_profile
        help_text.display = is_profile
        json_status.display = is_json
        if is_profile:
            # Default highlight to the first REAL profile when one
            # exists, so a quick Tab-to-Next-Enter advances with the
            # most-likely intended selection instead of jumping into
            # CreateProfileScreen. Sentinel is reserved for a
            # deliberate up-arrow choice. When the workspace has zero
            # profiles, index 0 IS the sentinel — landing on it is
            # both correct and unavoidable.
            if picker.highlighted is None:
                picker.highlighted = 1 if self._profiles else 0
            picker.focus()
        if is_json:
            self._refresh_json_status()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()

    def _picker_sentinel_highlighted(self) -> bool:
        """True when the profile picker is highlighting the ``+ Create new``
        sentinel — used so ``_advance`` can route to CreateProfileScreen
        instead of falling back to Skip.

        Listening for ``OptionList.OptionSelected`` would be cleaner, but
        the screen's ``priority=True`` Enter binding consumes the
        keystroke before Textual can fire the OptionSelected event, so
        the selection signal never reaches us through the normal channel.
        """
        try:
            picker = self.query_one("#profile-picker", OptionList)
        except Exception:  # noqa: BLE001
            return False
        if picker.highlighted is None:
            return False
        option = picker.get_option_at_index(picker.highlighted)
        return option.id == self._CREATE_PROFILE_SENTINEL

    def _advance(self) -> None:
        plan = self.wizard.state.plan
        plan.enrich = self._selected_enrich()
        plan.augmentation = self._selected_augmentation()
        plan.sbom_formats = self._selected_formats()
        plan.attestation = self._selected_attestation()

        # contact_profile_id / sbomify_json_data are only meaningful
        # when we're actually using that strategy; clear stale state
        # on every advance so toggling between Skip / Profile /
        # JsonConfig doesn't leak data from a previous selection.
        if plan.augmentation == "profile":
            # User wants to create a new profile? Push the create
            # screen instead of advancing — on success it pops back
            # here with the new profile auto-selected (see
            # on_screen_resume) and the user hits Next again to go
            # to Review.
            if self._picker_sentinel_highlighted():
                from sbomify_action.cli.wizard.screens.create_profile import CreateProfileScreen

                self.wizard.push_screen(CreateProfileScreen())
                return
            plan.contact_profile_id = self._selected_profile_id()
            plan.sbomify_json_data = None
            if plan.contact_profile_id is None:
                # The radio said 'profile' but the picker had no
                # selection. Fall back to skip rather than emit
                # AUGMENT=true with no binding — silent no-op at
                # workflow time would be worse.
                plan.augmentation = "skip"
        elif plan.augmentation == "json_config":
            plan.contact_profile_id = None
            if plan.sbomify_json_data is None:
                # User picked the sbomify.json radio but hasn't filled
                # in the form yet. Push the configure screen here
                # instead of falling back to Skip — the form is the
                # point of the radio. The form pops back to this
                # screen on save; we re-advance via the saved data.
                # ``_json_form_visited`` records that we pushed the
                # form at least once — on_screen_resume reads it to
                # detect a user cancellation (Escape from the form
                # without saving) and silently flips the radio back
                # to Skip, breaking the Enter→Escape→Enter loop.
                self._json_form_visited = True
                from sbomify_action.cli.wizard.screens.configure_sbomify_json import (
                    ConfigureSbomifyJsonScreen,
                )

                self.wizard.push_screen(ConfigureSbomifyJsonScreen())
                return
        else:
            plan.contact_profile_id = None
            plan.sbomify_json_data = None

        from sbomify_action.cli.wizard.screens.review import ReviewScreen

        self.wizard.push_screen(ReviewScreen())

    def _selected_enrich(self) -> bool:
        pressed = self.query_one("#enrich", RadioSet).pressed_button
        if pressed is None:
            return True
        return pressed.id == "enrich-yes"

    def _selected_augmentation(self) -> AugmentationStrategy:
        pressed = self.query_one("#augmentation", RadioSet).pressed_button
        if pressed is None or not pressed.id:
            return "skip"
        # Radio ids are ``aug-<strategy>`` — strategy may contain an
        # underscore (``json_config``), so split on the first dash only.
        return cast(AugmentationStrategy, pressed.id.split("-", 1)[1])

    def _refresh_json_status(self) -> None:
        """Render the inline status under the json_config radio.

        Tells the user whether the sbomify.json fields have been
        captured yet, and how to get to the form.
        """
        status = self.query_one("#json-config-status", Static)
        data = self.wizard.state.plan.sbomify_json_data
        if data:
            supplier = data.get("supplier") if isinstance(data, dict) else None
            sup_name = supplier.get("name") if isinstance(supplier, dict) and supplier.get("name") else "(unnamed)"
            status.update(
                f"[#86EFAC]✓  Configured.[/] Supplier: [b]{sup_name}[/]. "
                "[#5E5E5E]Press [b]Next[/] to review, or pick the radio again to edit.[/]"
            )
        else:
            status.update(
                "[#5E5E5E]◌  Not configured yet — press [b]Next[/] to open the "
                "sbomify.json form. Fields will be written to "
                "[b]<repo>/sbomify.json[/] when apply runs.[/]"
            )

    def _selected_profile_id(self) -> str | None:
        """Read the picker's highlighted profile id, or None when nothing
        is highlighted (eg the user toggled to 'profile' but never moved
        focus into the picker) — also None when the highlight sits on
        the '+ Create new' sentinel, which isn't a real profile."""
        picker = self.query_one("#profile-picker", OptionList)
        if picker.highlighted is None:
            return None
        option = picker.get_option_at_index(picker.highlighted)
        if option.id == self._CREATE_PROFILE_SENTINEL:
            return None
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
