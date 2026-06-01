"""Configure the on-disk ``sbomify.json`` augmentation source.

Pushed from ConfigureSbomScreen when the user picks "Write a
sbomify.json file" as their augmentation strategy. Mirrors the
old ``init`` command's field set: supplier + manufacturer + authors
+ security contact + lifecycle dates, all CycloneDX-aligned.

On submit, the collected fields are stashed on ``state.plan.
sbomify_json_data``. apply.py writes them to
``<repo_root>/sbomify.json`` (alongside the emitted workflow), and
the action's existing ``json_config`` provider picks the file up at
workflow run time when AUGMENT=true.

This screen exists because some teams can't (or don't want to) use
sbomify-hosted contact profiles — their compliance program requires
metadata to live in-repo with the source, version-controlled
alongside the code it describes.
"""

from __future__ import annotations

import json

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Button, Input, RadioButton, RadioSet, Static

from sbomify_action.cli.wizard.io import WIZARD_JSON_SENTINEL_KEY
from sbomify_action.cli.wizard.screens._base import WizardScreen

# Constructor calls use the wizard's state-aware glyph subclass; the
# base RadioButton import stays for ``rs.query(RadioButton)`` below.
from sbomify_action.cli.wizard.widgets import StatefulRadioButton

# CycloneDX-defined lifecycle phases. The action's existing
# ``_augmentation/metadata.py`` accepts these values verbatim.
_LIFECYCLE_PHASES: list[tuple[str, str]] = [
    ("planning", "Planning"),
    ("development", "Development"),
    ("build", "Build  [#86EFAC]✓ recommended[/]"),
    ("testing", "Testing"),
    ("distribution", "Distribution"),
    ("maintenance", "Maintenance"),
    ("end-of-life", "End of life"),
]


class ConfigureSbomifyJsonScreen(WizardScreen):
    """Collect the fields written to ``sbomify.json``."""

    step_index = 7
    step_title = "Configure (sbomify.json)"
    step_subtitle = "Organisational metadata written to the repo, version-controlled alongside the code."

    BINDINGS = [
        Binding("enter", "submit", "Save ▸", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True, priority=True),
    ]

    def compose_body(self) -> ComposeResult:
        intro = Vertical(classes="wizard-panel")
        intro.border_title = "◆  sbomify.json fields"
        intro.border_subtitle = "saved to the repository root"
        with intro:
            yield Static(
                "[#5E5E5E]Fields marked [#F4B57F]required[/] satisfy NTIA / CISA / EU CRA "
                "minimum elements. The rest are optional — most are CRA-recommended and can be "
                "added later by editing [b]sbomify.json[/] directly.[/]",
                classes="wizard-muted",
            )

        sup = Vertical(classes="wizard-panel")
        sup.border_title = "◇  Supplier"
        sup.border_subtitle = "the entity that distributes the software (NTIA Supplier Name)"
        with sup:
            yield Static(
                "[#F4B57F]Name required[/] — email + website strongly recommended.",
                classes="wizard-muted",
            )
            yield Input(placeholder="Supplier name (e.g. Acme Inc.)", id="sup-name")
            yield Input(placeholder="Supplier email (e.g. hello@acme.com)", id="sup-email")
            yield Input(placeholder="Supplier website (e.g. https://acme.com)", id="sup-url")

        man = Vertical(classes="wizard-panel")
        man.border_title = "◇  Manufacturer"
        man.border_subtitle = "the entity that created the software (optional, may differ from supplier)"
        with man:
            yield Static(
                "[#5E5E5E]Optional — leave blank when supplier and manufacturer are the same.[/]",
                classes="wizard-muted",
            )
            yield Input(placeholder="Manufacturer name (optional)", id="man-name")
            yield Input(placeholder="Manufacturer email (optional)", id="man-email")
            yield Input(placeholder="Manufacturer website (optional)", id="man-url")

        author = Vertical(classes="wizard-panel")
        author.border_title = "◇  Author of SBOM data"
        author.border_subtitle = "NTIA minimum element"
        with author:
            yield Static(
                "[#5E5E5E]Optional but [b]recommended[/] — satisfies NTIA's "
                "[b]Author of SBOM Data[/] minimum element.[/]",
                classes="wizard-muted",
            )
            yield Input(placeholder="Author name (optional)", id="author-name")
            yield Input(placeholder="Author email (optional)", id="author-email")

        sec = Vertical(classes="wizard-panel")
        sec.border_title = "◇  Security contact"
        sec.border_subtitle = "vulnerability reporting (CRA requirement)"
        with sec:
            yield Static(
                "[#5E5E5E]URL, [b]mailto:[/], or [b]tel:[/] — eg "
                "[#8A7DFF u]https://example.com/.well-known/security.txt[/]. CRA-recommended.[/]",
                classes="wizard-muted",
            )
            yield Input(
                placeholder="Security contact URI (optional)",
                id="security-contact",
            )

        lifecycle = Vertical(classes="wizard-panel")
        lifecycle.border_title = "◇  Lifecycle phase"
        lifecycle.border_subtitle = "CycloneDX 1.5+ field, CISA framing"
        with lifecycle:
            yield Static(
                "[#5E5E5E]Where this software sits in its lifecycle today. Most repos that "
                "produce shipped artifacts pick [b]Build[/]; libraries in active development "
                "pick [b]Development[/].[/]",
                classes="wizard-muted",
            )
            with RadioSet(id="lifecycle"):
                for phase, label in _LIFECYCLE_PHASES:
                    yield StatefulRadioButton(label, id=f"phase-{phase}", value=phase == "build")

        dates = Vertical(classes="wizard-panel")
        dates.border_title = "◇  Lifecycle dates"
        dates.border_subtitle = "ISO-8601 (YYYY-MM-DD), all optional"
        with dates:
            yield Static(
                "[#5E5E5E]Required for some EU CRA submissions and helpful for any consumer "
                "needing EOL / EOS planning.[/]",
                classes="wizard-muted",
            )
            yield Input(placeholder="Release date (YYYY-MM-DD)", id="release-date")
            yield Input(placeholder="Support period end (YYYY-MM-DD)", id="support-end")
            yield Input(placeholder="End of life (YYYY-MM-DD)", id="end-of-life")

        yield Static("", id="sbomify-json-status", markup=True)

        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Save  ▸", id="save", variant="primary")

    def on_mount(self) -> None:
        # Pre-populate from previously-saved plan data so the user can come
        # back and edit. If the plan has nothing yet but the repo already
        # ships a sbomify.json, seed the form from that on-disk file so the
        # user edits their existing metadata instead of re-typing it.
        prior = self.wizard.state.plan.sbomify_json_data
        if not prior and self.wizard.state.facts.has_sbomify_json:
            prior = self._load_from_disk()
        if prior:
            self._populate_from(prior)
        self.query_one("#sup-name", Input).focus()

    def action_submit(self) -> None:
        # Enter is handled here only — the priority=True binding on
        # this screen consumes Enter before any focused Input can fire
        # Input.Submitted, so an on_input_submitted handler would be
        # unreachable dead code.
        self.route_enter(self._save)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "save":
            self._save()

    def _save(self) -> None:
        sup_name = self.query_one("#sup-name", Input).value.strip()
        if not sup_name:
            self._set_status("[#F87171]Supplier name is required (it's an NTIA minimum element).[/]")
            return

        data: dict[str, object] = {}

        # Supplier — name required, email + url optional but recommended.
        supplier: dict[str, object] = {"name": sup_name}
        sup_email = self.query_one("#sup-email", Input).value.strip()
        sup_url = self.query_one("#sup-url", Input).value.strip()
        if sup_url:
            supplier["url"] = [sup_url]
        if sup_email:
            supplier["contacts"] = [{"name": sup_name, "email": sup_email}]
        data["supplier"] = supplier

        # Manufacturer — fully optional.
        man_name = self.query_one("#man-name", Input).value.strip()
        if man_name:
            manufacturer: dict[str, object] = {"name": man_name}
            man_email = self.query_one("#man-email", Input).value.strip()
            man_url = self.query_one("#man-url", Input).value.strip()
            if man_url:
                manufacturer["url"] = [man_url]
            if man_email:
                manufacturer["contacts"] = [{"name": man_name, "email": man_email}]
            data["manufacturer"] = manufacturer

        # Author — needs both name AND email to be useful in CycloneDX.
        author_name = self.query_one("#author-name", Input).value.strip()
        author_email = self.query_one("#author-email", Input).value.strip()
        if author_name and author_email:
            data["authors"] = [{"name": author_name, "email": author_email}]

        # Security contact — single URI string per the action's schema.
        security = self.query_one("#security-contact", Input).value.strip()
        if security:
            data["security_contact"] = security

        # Lifecycle phase.
        lifecycle = self._selected_lifecycle()
        if lifecycle:
            data["lifecycle_phase"] = lifecycle

        # Lifecycle dates — left as raw strings; the action's schema
        # validates ISO-8601 at run time and surfaces a clear error if
        # the user typed something wrong.
        for input_id, key in (
            ("release-date", "release_date"),
            ("support-end", "support_period_end"),
            ("end-of-life", "end_of_life"),
        ):
            value = self.query_one(f"#{input_id}", Input).value.strip()
            if value:
                data[key] = value

        self.wizard.state.plan.sbomify_json_data = data
        self.app.pop_screen()

    def _selected_lifecycle(self) -> str | None:
        pressed = self.query_one("#lifecycle", RadioSet).pressed_button
        if pressed is None or not pressed.id:
            return None
        return pressed.id.split("-", 1)[1]

    def _set_status(self, markup: str) -> None:
        self.query_one("#sbomify-json-status", Static).update(markup)

    def _populate_from(self, data: dict[str, object]) -> None:
        """Re-fill inputs from a previously-saved sbomify_json_data dict.

        Lets the user navigate back, tweak a field, and continue — same
        ergonomics as the rest of the wizard (Configure Workflow + SBOM
        also preserve their state via the Plan dataclass).
        """
        supplier = data.get("supplier") if isinstance(data.get("supplier"), dict) else None
        if isinstance(supplier, dict):
            name = supplier.get("name")
            if isinstance(name, str):
                self.query_one("#sup-name", Input).value = name
            urls = supplier.get("url")
            if isinstance(urls, list) and urls and isinstance(urls[0], str):
                self.query_one("#sup-url", Input).value = urls[0]
            contacts = supplier.get("contacts")
            if isinstance(contacts, list) and contacts and isinstance(contacts[0], dict):
                email = contacts[0].get("email")
                if isinstance(email, str):
                    self.query_one("#sup-email", Input).value = email

        manufacturer = data.get("manufacturer")
        if isinstance(manufacturer, dict):
            name = manufacturer.get("name")
            if isinstance(name, str):
                self.query_one("#man-name", Input).value = name
            urls = manufacturer.get("url")
            if isinstance(urls, list) and urls and isinstance(urls[0], str):
                self.query_one("#man-url", Input).value = urls[0]
            contacts = manufacturer.get("contacts")
            if isinstance(contacts, list) and contacts and isinstance(contacts[0], dict):
                email = contacts[0].get("email")
                if isinstance(email, str):
                    self.query_one("#man-email", Input).value = email

        authors = data.get("authors")
        if isinstance(authors, list) and authors and isinstance(authors[0], dict):
            name = authors[0].get("name")
            email = authors[0].get("email")
            if isinstance(name, str):
                self.query_one("#author-name", Input).value = name
            if isinstance(email, str):
                self.query_one("#author-email", Input).value = email

        sec = data.get("security_contact")
        if isinstance(sec, str):
            self.query_one("#security-contact", Input).value = sec

        phase = data.get("lifecycle_phase")
        if isinstance(phase, str):
            # NoMatches is the only legitimate failure here (DOM not
            # mounted, id renamed) — narrow to it so a real bug in the
            # radio iteration surfaces in tests instead of leaving the
            # screen quietly displaying the wrong lifecycle.
            try:
                rs = self.query_one("#lifecycle", RadioSet)
            except NoMatches:
                return
            for rb in rs.query(RadioButton):
                rb.value = rb.id == f"phase-{phase}"

        for input_id, key in (
            ("release-date", "release_date"),
            ("support-end", "support_period_end"),
            ("end-of-life", "end_of_life"),
        ):
            value = data.get(key)
            if isinstance(value, str):
                self.query_one(f"#{input_id}", Input).value = value

    def _load_from_disk(self) -> dict[str, object] | None:
        """Read an existing repo-root ``sbomify.json`` to seed the form.

        Returns the parsed JSON object with the wizard sentinel key removed
        (it's bookkeeping the form shouldn't surface), or ``None`` if the
        file is absent, unreadable, malformed, or not a JSON object. Purely
        a convenience — any failure just leaves the form blank, and unknown
        keys the form doesn't render (eg ``licenses``) are ignored here but
        preserved on disk because apply leaves a non-wizard file untouched.
        """
        json_path = self.wizard.state.facts.repo_root / "sbomify.json"
        try:
            with json_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        return {k: v for k, v in data.items() if k != WIZARD_JSON_SENTINEL_KEY}
