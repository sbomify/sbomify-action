"""Create a sbomify contact profile from inside the wizard.

Pushed from the Augmentation panel on Configure (SBOM) when the
workspace has zero profiles (or the user explicitly wants to add a
new one). Collects the minimal-but-CycloneDX-aligned fields that
sbomify's ``ContactProfileCreateSchema`` requires:

  - Profile name (free-text label, internal)
  - Organisation entity (supplier + manufacturer) with name + email +
    optional phone / address / website
  - At least one security contact on the entity — both the backend
    schema and CRA compliance require it
  - Optional author (NTIA "Author of SBOM Data" minimum element)

On submit, POSTs to ``/api/v1/workspaces/{team_key}/contact-profiles``;
on success, the new profile is appended to
``state.workspace.contact_profiles`` and the screen pops back to
ConfigureSbom, which auto-selects the freshly-created profile.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Input, Static
from textual.worker import Worker, WorkerState

from sbomify_action.cli.wizard.screens._paged import PagedFormScreen
from sbomify_action.exceptions import APIError
from sbomify_action.logging_config import logger


class CreateProfileScreen(PagedFormScreen):
    """Modal-style screen for creating a new contact profile via the API.

    Doesn't claim its own step in the crumb track — it's a sub-flow off
    Configure (SBOM). The user lands back on ConfigureSbom afterwards
    with the new profile selected.

    The field set doesn't fit an 80×24 terminal, so it's split into two
    fit-to-viewport pages (see ``PagedFormScreen``): identity +
    organisation, then security contact + author.
    """

    step_index = 7
    step_title = "Create contact profile"
    step_subtitle = (
        "Supplier name + author + security contact — the metadata NTIA, CISA, "
        "and the EU CRA list as minimum SBOM elements."
    )

    PAGE_TITLES = ["Identity & organisation", "Security & author"]

    def compose_page(self, index: int) -> ComposeResult:
        if index == 0:
            yield from self._compose_org_page()
        else:
            yield from self._compose_contacts_page()

    def _compose_org_page(self) -> ComposeResult:
        intro = Vertical(classes="wizard-panel")
        intro.border_title = "◆  New contact profile"
        intro.border_subtitle = "saved to your sbomify workspace"
        with intro:
            yield Static(
                "[#5E5E5E]Fields marked [#F4B57F]required[/] are needed for the API call AND "
                "for NTIA / CISA / EU CRA compliance. Everything else is optional and can be "
                "edited later in the sbomify UI.[/]",
                classes="wizard-help",
            )

        # Profile identity — internal label used to pick this profile
        # from the picker on subsequent runs.
        ident = Vertical(classes="wizard-panel")
        ident.border_title = "◇  Profile name"
        ident.border_subtitle = "internal label, free-text"
        with ident:
            yield Static("[#F4B57F]required[/]", classes="wizard-help")
            yield Input(
                placeholder="e.g. 'Acme default' or 'Production releases'",
                id="profile-name",
            )

        # Organisation entity — fills the Supplier Name minimum element.
        org = Vertical(classes="wizard-panel")
        org.border_title = "◇  Organisation"
        org.border_subtitle = "supplier + manufacturer (CycloneDX entity)"
        with org:
            yield Static(
                "[#F4B57F]Name and email required[/] — feed the SBOM's [b]supplier[/] and [b]manufacturer[/] fields.",
                classes="wizard-help",
            )
            yield Input(placeholder="Organisation name (e.g. Acme Inc.)", id="org-name")
            yield Input(placeholder="Organisation email (e.g. hello@acme.com)", id="org-email")
            yield Input(placeholder="Phone (optional)", id="org-phone")
            yield Input(placeholder="Address (optional)", id="org-address")
            yield Input(
                placeholder="Website URL (optional, e.g. https://acme.com)",
                id="org-website",
            )

    def _compose_contacts_page(self) -> ComposeResult:
        # Security contact — the backend rejects entities without at
        # least one contact, and the EU CRA requires a security contact.
        sec = Vertical(classes="wizard-panel")
        sec.border_title = "◇  Security contact"
        sec.border_subtitle = "vulnerability reporting (CRA requirement)"
        with sec:
            yield Static(
                "[#F4B57F]Name and email required[/] — listed as the "
                "[b]security contact[/] on every SBOM this workflow generates.",
                classes="wizard-help",
            )
            yield Input(placeholder="Security contact name", id="sec-name")
            yield Input(placeholder="Security contact email", id="sec-email")

        # Author — NTIA "Author of SBOM Data" minimum element. Optional
        # at the API level but compliance-relevant.
        author = Vertical(classes="wizard-panel")
        author.border_title = "◇  Author of SBOM data"
        author.border_subtitle = "NTIA minimum element"
        with author:
            yield Static(
                "[#5E5E5E]Optional but [b]recommended[/] — the SBOM author goes into the "
                "CycloneDX [b]authors[/] field and satisfies NTIA's [b]Author of SBOM Data[/] "
                "minimum element. Skip if a tool (eg sbomify-action itself) will be credited "
                "as the author instead.[/]",
                classes="wizard-help",
            )
            yield Input(placeholder="Author name (optional)", id="author-name")
            yield Input(placeholder="Author email (optional)", id="author-email")

    def on_mount(self) -> None:
        self.query_one("#profile-name", Input).focus()

    def save(self) -> None:
        """Validate, build the payload, and POST it on a worker thread."""
        if self.wizard.state.workspace is None or not self.wizard.state.workspace.team_key:
            self._set_status("[#F87171]No workspace key available — can't create a profile.[/]")
            return

        name = self.query_one("#profile-name", Input).value.strip()
        org_name = self.query_one("#org-name", Input).value.strip()
        org_email = self.query_one("#org-email", Input).value.strip()
        sec_name = self.query_one("#sec-name", Input).value.strip()
        sec_email = self.query_one("#sec-email", Input).value.strip()

        # Profile name + organisation live on page 1, the security contact
        # on page 2. Jump to whichever page owns the first missing field so
        # the error lands next to the empty input.
        missing: list[str] = []
        if not name:
            missing.append("profile name")
        if not org_name:
            missing.append("organisation name")
        if not org_email:
            missing.append("organisation email")
        if not sec_name:
            missing.append("security contact name")
        if not sec_email:
            missing.append("security contact email")
        if missing:
            page_for_missing = 0 if (not name or not org_name or not org_email) else 1
            self._goto_page(page_for_missing)
            self._set_status(f"[#F87171]Missing required field(s): {', '.join(missing)}.[/]")
            return

        org_phone = self.query_one("#org-phone", Input).value.strip()
        org_address = self.query_one("#org-address", Input).value.strip()
        org_website = self.query_one("#org-website", Input).value.strip()
        author_name = self.query_one("#author-name", Input).value.strip()
        author_email = self.query_one("#author-email", Input).value.strip()

        entity: dict[str, object] = {
            "name": org_name,
            "email": org_email,
            "is_supplier": True,
            "is_manufacturer": True,
            "contacts": [
                {
                    "name": sec_name,
                    "email": sec_email,
                    "is_security_contact": True,
                }
            ],
        }
        if org_phone:
            entity["phone"] = org_phone
        if org_address:
            entity["address"] = org_address
        if org_website:
            entity["website_urls"] = [org_website]

        payload: dict[str, object] = {
            "name": name,
            "entities": [entity],
        }
        if author_name and author_email:
            payload["authors"] = [{"name": author_name, "email": author_email}]

        self._set_status("[#CBCCCE]Creating profile…[/]")
        self.next_button.disabled = True
        self.run_worker(
            lambda: self._create_worker(payload),
            name="create-profile",
            thread=True,
            exclusive=True,
        )

    def _create_worker(self, payload: dict[str, object]) -> dict[str, object] | str:
        """POST the payload off-thread; return profile dict on success or
        error message string on failure."""
        api = self.wizard.state.require_api()
        workspace = self.wizard.state.workspace
        assert workspace is not None and workspace.team_key is not None
        try:
            created = api.create_contact_profile(workspace.team_key, payload)
        except APIError as e:
            logger.warning("Create-profile failed: %s", e)
            return str(e)
        return created

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != "create-profile":
            return
        if event.state == WorkerState.SUCCESS:
            result = event.worker.result
            # _create_worker's contract is `dict | str`: a dict is the
            # API success payload, a str is the APIError message. A
            # successful POST whose body doesn't parse (or which the
            # API client could not coerce into a dict-with-id) lands
            # in the dict branch with no id — surface it as an API
            # anomaly rather than rendering the empty dict as the
            # error message, which is both confusing and re-prompts
            # the user to submit a duplicate.
            if isinstance(result, str):
                self._set_status(f"[#F87171]✗  {result}[/]")
                self.next_button.disabled = False
                return
            if isinstance(result, dict) and result.get("id"):
                # Append to the workspace snapshot so ConfigureSbom's
                # compose_body picks up the new profile on re-render.
                workspace = self.wizard.state.workspace
                if workspace is not None:
                    workspace.contact_profiles.append(result)
                # Stash the id so ConfigureSbom can pre-select it.
                self.wizard.state.plan.contact_profile_id = str(result.get("id"))
                self.app.pop_screen()
                return
            # Successful 2xx but unexpected body shape — the profile
            # may or may not exist on the backend. Surface enough
            # context for the user to check the sbomify UI before
            # re-trying.
            self._set_status(
                "[#F87171]✗  Profile may have been created but the API response was "
                "unexpected. Check the sbomify UI under Settings → Contacts before "
                "re-submitting to avoid creating a duplicate.[/]"
            )
            self.next_button.disabled = False
        elif event.state == WorkerState.ERROR:
            self._set_status(f"[#F87171]✗  Unexpected error: {event.worker.error}[/]")
            self.next_button.disabled = False
