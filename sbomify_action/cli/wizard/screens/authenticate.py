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
from sbomify_action.logging_config import logger
from sbomify_action.sbomify_api import SbomifyApiClient


def _pick_default_workspace_key(workspaces: list[dict[str, object]]) -> str | None:
    """Return the ``key`` of the workspace the wizard should bind to.

    ``GET /api/v1/workspaces/`` returns every workspace the underlying
    *user* belongs to, regardless of the token's scope (the backend does
    not filter that endpoint by token-bound team today). But
    ``list_products`` / ``list_components`` ARE scoped — to the token's
    bound team for scoped tokens, or the authenticating user's *default*
    workspace for PATs. Mirror that scoping by reading the
    ``is_default_team`` flag on the current user's membership entry —
    the same signal the backend uses for the component listing. When no
    entry is marked default (or the response omits the membership block),
    fall back to the first usable key.
    """
    fallback: str | None = None
    for ws in workspaces:
        key = ws.get("key")
        if not isinstance(key, str) or not key:
            continue
        if fallback is None:
            fallback = key
        members = ws.get("members")
        if not isinstance(members, list):
            continue
        for member in members:
            if not isinstance(member, dict):
                continue
            if member.get("is_me") and member.get("is_default_team"):
                return key
    return fallback


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

        # Resolve the workspace key up front. The contact-profiles
        # endpoint is nested under ``/api/v1/workspaces/{team_key}/``
        # and there's no "current workspace" alias — we have to know
        # the key explicitly. ``list_workspaces`` returns every workspace
        # the underlying USER belongs to, regardless of token scope (the
        # backend doesn't filter that endpoint by token-bound team), so a
        # multi-workspace user gets multiple entries even with a token
        # scoped to one team.
        #
        # We MUST pick the workspace where list_products / list_components
        # are actually scoped — those endpoints have no team_key parameter
        # and resolve via the token's bound team (scoped) or the user's
        # default workspace (PAT). Picking the wrong workspace silently
        # binds profiles to components that live elsewhere — the exact
        # failure mode apply.py's profile-binding step exists to avoid.
        #
        # Strategy: prefer the workspace whose membership entry has
        # ``is_default_team=True`` for the current user (the same
        # signal the backend uses to scope component listings). Fall
        # back to the first usable entry, and surface a warning when
        # the token spans multiple workspaces so the user notices.
        try:
            workspaces = SbomifyApiClient(base_url, token).list_workspaces()
        except APIError as e:
            logger.warning("Could not list workspaces: %s", e)
            workspaces = []
        team_key = _pick_default_workspace_key(workspaces)
        if len(workspaces) > 1:
            picked_name = next(
                (
                    str(ws.get("name") or ws.get("key"))
                    for ws in workspaces
                    if isinstance(ws.get("key"), str) and ws.get("key") == team_key
                ),
                "(unknown)",
            )
            logger.warning(
                "You belong to %d workspaces; the wizard will use %r (key=%s) — your "
                "default workspace. If you intended to onboard a different "
                "workspace, change the default in the sbomify UI and re-run.",
                len(workspaces),
                picked_name,
                team_key,
            )

        def _list_products() -> list[dict[str, object]]:
            return SbomifyApiClient(base_url, token).list_products()

        def _list_components() -> list[dict[str, object]]:
            return SbomifyApiClient(base_url, token).list_components()

        def _list_profiles() -> list[dict[str, object]]:
            if team_key is None:
                return []
            try:
                return SbomifyApiClient(base_url, token).list_contact_profiles(team_key)
            except APIError as e:
                # Non-fatal — Augmentation just appears empty in that case.
                logger.warning("Could not list contact profiles: %s", e)
                return []

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
