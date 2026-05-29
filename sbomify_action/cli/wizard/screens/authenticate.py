"""Authenticate screen — token entry + parallel workspace prefetch."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, Input, LoadingIndicator, Static
from textual.worker import Worker, WorkerState

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import WorkspaceSnapshot
from sbomify_action.exceptions import APIError, AuthError
from sbomify_action.sbomify_api import SbomifyApiClient


class AuthenticateScreen(WizardScreen):
    """Phase 3 — validate token + prefetch products/components/profiles."""

    step_index = 3
    step_title = "Authenticate"
    step_subtitle = "Validate your sbomify API token and load your workspace."

    BINDINGS = [
        Binding("enter", "submit", "Submit", show=True, priority=True),
        # priority=True ensures Escape pops the screen even when an Input
        # has focus — without it the password Input swallows the keypress
        # and the user can't get back to Discover from here.
        Binding("escape", "app.pop_screen", "Back", show=True, priority=True),
    ]

    def compose_body(self) -> ComposeResult:
        panel = Vertical(classes="wizard-panel")
        panel.border_title = "◆  API token"
        panel.border_subtitle = self.wizard.opts.api_base_url
        with panel:
            yield Static(self._token_help(), classes="wizard-muted")
            yield Input(
                placeholder="eyJ…  (JWT-shaped sbomify API token)",
                password=True,
                id="token",
            )
            yield Static("", id="auth-status", markup=True)
            yield Container(id="auth-progress")
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Authenticate  ▸", id="submit", variant="primary")

    def on_mount(self) -> None:
        existing = self.wizard.opts.token
        input_box = self.query_one("#token", Input)
        if existing:
            input_box.value = existing
            self._start_auth(existing)
        else:
            input_box.focus()

    def action_submit(self) -> None:
        self.route_enter(lambda: self._start_auth(self.query_one("#token", Input).value.strip()))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "token":
            self._start_auth(event.value.strip())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "submit":
            self._start_auth(self.query_one("#token", Input).value.strip())

    def _start_auth(self, token: str) -> None:
        if not token:
            self._set_status("[#F87171]Token is required.[/]")
            self.query_one("#token", Input).focus()
            return
        self._set_status("")
        progress = self.query_one("#auth-progress", Container)
        progress.remove_children()
        progress.mount(LoadingIndicator())
        self.query_one("#submit", Button).disabled = True
        self.query_one("#token", Input).disabled = True
        self._run_auth(token)

    def _run_auth(self, token: str) -> None:
        self.run_worker(
            lambda: self._auth_worker(token),
            name="authenticate",
            thread=True,
            exclusive=True,
            description="Talking to sbomify…",
        )

    def _auth_worker(self, token: str) -> tuple[SbomifyApiClient | None, WorkspaceSnapshot | None, str | None]:
        """Background work: validate token + prefetch workspace.

        Each prefetch task constructs its own ``SbomifyApiClient`` —
        ``requests.Session`` is not thread-safe and we run three calls
        in parallel.
        """
        base_url = self.wizard.opts.api_base_url
        client = SbomifyApiClient(base_url, token)
        try:
            client.whoami()
        except AuthError as e:
            return None, None, f"Token rejected: {e}"
        except APIError as e:
            return None, None, f"Could not reach sbomify: {e}"

        # Fetch the team list up front (small, single round-trip). We
        # need the team key to scope the contact-profiles endpoint —
        # ``/api/v1/teams/{team_key}/contact-profiles`` is the only way
        # to enumerate them. Tokens are typically scoped to one team
        # but the API returns a list; we use the first non-empty entry
        # and store the key on state so apply.py can reuse it.
        try:
            teams = SbomifyApiClient(base_url, token).list_teams()
        except APIError as e:
            return None, None, f"Could not list workspaces: {e}"
        team_key: str | None = None
        for team in teams:
            key = team.get("key")
            if isinstance(key, str) and key:
                team_key = key
                break

        def _list_products() -> list[dict[str, object]]:
            return SbomifyApiClient(base_url, token).list_products()

        def _list_components() -> list[dict[str, object]]:
            return SbomifyApiClient(base_url, token).list_components()

        def _list_profiles() -> list[dict[str, object]]:
            if team_key is None:
                # No team key → can't query profiles. Surface as empty
                # rather than as an error so the rest of the workspace
                # prefetch still completes.
                return []
            return SbomifyApiClient(base_url, token).list_contact_profiles(team_key)

        try:
            with ThreadPoolExecutor(max_workers=3) as pool:
                # Submit all three first so they run concurrently — chaining
                # ``submit(...).result()`` would block on each future before
                # the next is submitted, serialising the calls and defeating
                # the entire reason for the pool.
                products_future = pool.submit(_list_products)
                components_future = pool.submit(_list_components)
                profiles_future = pool.submit(_list_profiles)
                products = products_future.result()
                components = components_future.result()
                profiles = profiles_future.result()
        except APIError as e:
            return None, None, f"Workspace fetch failed: {e}"

        workspace = WorkspaceSnapshot(
            products=products,
            components=components,
            contact_profiles=profiles,
            team_key=team_key,
        )
        return client, workspace, None

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != "authenticate":
            return
        if event.state == WorkerState.SUCCESS:
            result = event.worker.result
            if result is None:
                self._on_auth_error("Authentication worker returned no result")
                return
            client, workspace, error = result
            if error:
                self._on_auth_error(error)
            else:
                assert client is not None and workspace is not None
                self._on_auth_success(client, workspace)
        elif event.state == WorkerState.ERROR:
            self._on_auth_error(f"Unexpected error: {event.worker.error}")

    def _on_auth_success(self, client: SbomifyApiClient, workspace: WorkspaceSnapshot) -> None:
        self.wizard.state.api = client
        self.wizard.state.workspace = workspace
        # Surface what the prefetch actually loaded so the user knows
        # what's coming on the next two screens — otherwise Product /
        # Components arrive with no context for "how many existing
        # things will I see?".
        self._set_status(
            f"[#86EFAC]✓  Authenticated.[/]  Loaded "
            f"[b]{len(workspace.products)}[/] product(s), "
            f"[b]{len(workspace.components)}[/] component(s), "
            f"[b]{len(workspace.contact_profiles)}[/] contact profile(s)."
        )
        from sbomify_action.cli.wizard.screens.product import ProductScreen

        self.wizard.push_screen(ProductScreen())

    def _on_auth_error(self, message: str) -> None:
        self.query_one("#auth-progress", Container).remove_children()
        self.query_one("#submit", Button).disabled = False
        self.query_one("#token", Input).disabled = False
        self.query_one("#token", Input).focus()
        self._set_status(f"[#F87171]{message}[/]")

    def _set_status(self, markup: str) -> None:
        self.query_one("#auth-status", Static).update(markup)

    def _token_help(self) -> str:
        return (
            "Paste your sbomify API token from "
            f"{self.wizard.opts.api_base_url}/account/api-tokens.\n"
            "Tip: set [b]SBOMIFY_TOKEN[/] in your shell env and the wizard skips this prompt next time."
        )
