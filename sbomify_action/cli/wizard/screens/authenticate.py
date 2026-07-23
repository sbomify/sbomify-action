"""Authenticate screen — token entry + parallel workspace prefetch."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, Input, LoadingIndicator, Static
from textual.worker import Worker, WorkerState

from sbomify_action.cli.wizard.screens._base import WizardScreen, strip_status_codes
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
    the same signal the backend uses for the component listing.

    Caveat: for a *scoped* token bound to a non-default workspace, the
    membership block on the token's bound workspace still reads
    ``is_default_team=False`` (the flag tracks the user's default, not
    the token's scope), so this picker can return the wrong key. There's
    no programmatic disambiguation today — the picked workspace is
    surfaced in the auth-success status line so the user can spot a
    mismatch (eg. by seeing a workspace name they didn't expect) and
    re-run with the right token. When the token spans exactly one
    workspace (the common case for both unscoped PAT-with-one-team and
    scoped tokens correctly filtered backend-side), there's no
    ambiguity — return that key without consulting the flag.
    """
    usable_keys = [str(ws.get("key")) for ws in workspaces if isinstance(ws.get("key"), str) and ws.get("key")]
    if len(usable_keys) == 1:
        return usable_keys[0]
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


def _resolve_profile_workspace(
    base_url: str,
    token: str,
    workspaces: list[dict[str, object]],
    picked_key: str | None,
) -> tuple[str | None, list[dict[str, object]]]:
    """Return ``(team_key, contact_profiles)`` for the workspace the token can read.

    ``GET /api/v1/workspaces/`` is NOT filtered by token scope, so
    ``_pick_default_workspace_key`` can pick a workspace a scoped token has
    no access to. When that happens the contact-profile listing 403s — and
    silently treating that as "no profiles" is worse than it looks: the
    wizard then shows an empty picker for a workspace that has profiles,
    and a profile created from the wizard lands in the WRONG workspace
    (the products/components endpoints resolve via the token's bound team,
    not the picked key). Verified against production: a token scoped to
    workspace A lists A's profiles fine and gets 403 for every other key.

    So: try the picked key first; on failure, probe the remaining
    workspaces in parallel and bind to the first one whose listing
    succeeds (for a scoped token exactly one can). Returns
    ``(None, [])`` when no workspace is readable.
    """
    candidates = [str(ws.get("key")) for ws in workspaces if isinstance(ws.get("key"), str) and ws.get("key")]
    if picked_key is not None and picked_key in candidates:
        candidates.remove(picked_key)
        candidates.insert(0, picked_key)
    if not candidates:
        return None, []

    def _probe(key: str) -> tuple[str, list[dict[str, object]] | None]:
        try:
            return key, SbomifyApiClient(base_url, token).list_contact_profiles(key)
        except APIError as e:
            logger.debug("Contact-profile probe failed for workspace %s: %s", key, e)
            return key, None

    # Try the picked workspace alone first — the common case (unscoped
    # token, or a scoped token whose workspace IS the picked one) needs
    # exactly one request.
    first_key, first_profiles = _probe(candidates[0])
    if first_profiles is not None:
        return first_key, first_profiles

    rest = candidates[1:]
    if not rest:
        logger.warning("Could not list contact profiles for workspace %s", first_key)
        return None, []
    with ThreadPoolExecutor(max_workers=min(8, len(rest))) as pool:
        results = list(pool.map(_probe, rest))
    for key, profiles in results:
        if profiles is not None:
            logger.info(
                "Token cannot read workspace %s; binding contact profiles to workspace %s instead "
                "(the token appears to be scoped to it).",
                first_key,
                key,
            )
            return key, profiles
    logger.warning("Could not list contact profiles for any workspace the user belongs to")
    return None, []


def _workspace_display_name(workspaces: list[dict[str, object]], key: str | None) -> str | None:
    """Return the human name (or key) of the workspace with ``key``.

    Used in the auth-success status line so the user sees which workspace
    the wizard picked — a scoped token bound to a non-default workspace can
    surface a misdirection here (cf. ``_pick_default_workspace_key`` caveat).
    """
    if not key:
        return None
    for ws in workspaces:
        if isinstance(ws.get("key"), str) and ws.get("key") == key:
            name = ws.get("name")
            if isinstance(name, str) and name:
                return name
            return key
    return key


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
        # Enter is routed through here only — the priority=True binding on
        # this screen consumes Enter before any focused Input can fire
        # Input.Submitted, so an on_input_submitted handler would be
        # unreachable dead code. action_submit reads the token value
        # directly and kicks off _start_auth, covering both "Enter on
        # the Input" and "Enter on the Authenticate button" paths.
        self.route_enter(lambda: self._start_auth(self.query_one("#token", Input).value.strip()))

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

        def _list_products() -> list[dict[str, object]]:
            return SbomifyApiClient(base_url, token).list_products()

        def _list_components() -> list[dict[str, object]]:
            return SbomifyApiClient(base_url, token).list_components()

        def _list_profiles() -> tuple[str | None, list[dict[str, object]]]:
            return _resolve_profile_workspace(base_url, token, workspaces, team_key)

        try:
            with ThreadPoolExecutor(max_workers=3) as pool:
                # Submit all three first so they run concurrently — chaining
                # ``submit(...).result()`` would block on each future before
                # the next is submitted, serializing the calls and defeating
                # the entire reason for the pool.
                products_future = pool.submit(_list_products)
                components_future = pool.submit(_list_components)
                profiles_future = pool.submit(_list_profiles)
                products = products_future.result()
                components = components_future.result()
                team_key, profiles = profiles_future.result()
        except APIError as e:
            return None, None, f"Workspace fetch failed: {e}"

        if len(workspaces) > 1:
            bound_name = _workspace_display_name(workspaces, team_key) or "(unknown)"
            logger.warning(
                "You belong to %d workspaces; the wizard is bound to %r (key=%s). If you "
                "intended to onboard a different workspace, use a token scoped to that "
                "workspace (or change your default workspace in the sbomify UI) and re-run.",
                len(workspaces),
                bound_name,
                team_key,
            )

        workspace = WorkspaceSnapshot(
            products=products,
            components=components,
            contact_profiles=profiles,
            team_key=team_key,
        )
        # Stash the picked workspace's display name on the snapshot — the
        # main thread reads it for the auth-success status line so the user
        # can spot a misdirection (the picker is is_default_team-based,
        # which is wrong for scoped tokens bound to a non-default workspace).
        workspace.display_name = _workspace_display_name(workspaces, team_key)
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
        # Lead with the workspace name when known — the picker is
        # is_default_team-based and can choose the wrong workspace for
        # scoped tokens; surfacing the name lets the user catch a
        # misdirection here before any components are created.
        if workspace.display_name:
            ws_clause = f"  Workspace: [b]{workspace.display_name}[/]."
        else:
            ws_clause = ""
        self._set_status(
            f"[#86EFAC]✓  Authenticated.[/]{ws_clause}  Loaded "
            f"[b]{len(workspace.products)}[/] product(s), "
            f"[b]{len(workspace.components)}[/] component(s), "
            f"[b]{len(workspace.contact_profiles)}[/] contact profile(s)."
        )
        from sbomify_action.cli.wizard.screens.product import ProductScreen

        self.wizard.push_screen(ProductScreen())

    def _on_auth_error(self, message: str) -> None:
        from rich.markup import escape as rich_escape

        self.query_one("#auth-progress", Container).remove_children()
        self.query_one("#submit", Button).disabled = False
        self.query_one("#token", Input).disabled = False
        self.query_one("#token", Input).focus()
        # API error text: drop the developer-facing status code and escape
        # stray ``[`` so it can't be parsed as markup.
        self._set_status(f"[#F87171]{rich_escape(strip_status_codes(message))}[/]")

    def _set_status(self, markup: str) -> None:
        self.query_one("#auth-status", Static).update(markup)

    def _token_help(self) -> str:
        return (
            "Paste your sbomify API token from "
            f"{self.wizard.opts.api_base_url}/account/api-tokens.\n"
            "Tip: set [b]SBOMIFY_TOKEN[/] in your shell env and the wizard skips this prompt next time."
        )
