"""Authenticate screen — token entry + workspace prefetch.

If a token was already passed via `--token` / `$SBOMIFY_TOKEN`, we skip
straight to the validation worker. Otherwise the user types one in.
After a successful `whoami` we prefetch products/components/profiles
concurrently so downstream screens render instantly.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Button, Input, LoadingIndicator, Static
from textual.worker import Worker, WorkerState

from sbomify_action.cli.wizard.client import (
    SbomifyAPIError,
    SbomifyAuthError,
    SbomifyClient,
)
from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import WorkspaceSnapshot


class AuthenticateScreen(WizardScreen):
    """Phase 2 — collect / validate the sbomify API token."""

    step_index = 3
    step_title = "Authenticate"
    step_subtitle = "Validate your sbomify API token and load your workspace."

    # Standard keys:  Tab/Shift+Tab focus chain · Enter submits (priority so
    # the Input doesn't keep it for itself) · Esc returns to the previous screen.
    BINDINGS = [
        Binding("enter", "submit", "Submit", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="wizard-panel"):
            yield Static("[b #8A7DFF]API token[/]", classes="wizard-title")
            yield Static(self._token_help(), classes="wizard-muted")
            yield Input(
                placeholder="sbom_xxxxxxxxxxxxxxxxxxxxxxxx",
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
        self._start_auth(self.query_one("#token", Input).value.strip())

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

    def _auth_worker(self, token: str) -> "tuple[SbomifyClient | None, WorkspaceSnapshot | None, str | None]":
        """Background work: validate token + prefetch workspace."""
        client = SbomifyClient(self.wizard.opts.api_base_url, token)
        try:
            client.whoami()
        except SbomifyAuthError as e:
            return None, None, f"Token rejected: {e.detail or 'invalid credentials'}"
        except SbomifyAPIError as e:
            return None, None, f"Could not reach sbomify ({e.status}): {e.detail or e}"

        # Each fetch needs its own client so we don't share a non-thread-safe
        # requests.Session across the pool.
        def _list_products() -> list[dict[str, object]]:
            return SbomifyClient(self.wizard.opts.api_base_url, token).list_products()

        def _list_components() -> list[dict[str, object]]:
            return SbomifyClient(self.wizard.opts.api_base_url, token).list_components()

        def _list_profiles() -> list[dict[str, object]]:
            return SbomifyClient(self.wizard.opts.api_base_url, token).list_contact_profiles()

        try:
            with ThreadPoolExecutor(max_workers=3) as pool:
                products_f = pool.submit(_list_products)
                components_f = pool.submit(_list_components)
                profiles_f = pool.submit(_list_profiles)
                products = products_f.result()
                components = components_f.result()
                profiles = profiles_f.result()
        except SbomifyAPIError as e:
            return None, None, f"Workspace fetch failed: {e.detail or e}"

        workspace = WorkspaceSnapshot(
            user={},
            products=products,
            components=components,
            contact_profiles=profiles,
        )
        return client, workspace, None

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != "authenticate":
            return
        if event.state == WorkerState.SUCCESS:
            # Textual types `worker.result` as `T | None` because workers
            # *can* return None; ours always returns the 3-tuple by
            # construction, but the type narrows here so static checkers
            # don't trip on the unpack.
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

    def _on_auth_success(self, client: SbomifyClient, workspace: WorkspaceSnapshot) -> None:
        self.wizard.state.api = client
        self.wizard.state.workspace = workspace
        # Branch on the welcome-screen intent: the onboarding flow walks
        # the user through picking a product + configuring each component,
        # while the edit flow drops them straight onto the list of
        # existing workflows.
        if self.wizard.flow_mode == "edit":
            from sbomify_action.cli.wizard.screens.edit_existing import EditExistingScreen

            self.wizard.push_screen(EditExistingScreen())
        else:
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
            "Paste your sbomify [#8A7DFF]API token[/] from "
            f"[#F4B57F]{self.wizard.opts.api_base_url}/account/api-tokens[/].\n"
            "[#5E5E5E]Tip: set [#CBCCCE]SBOMIFY_TOKEN[/] in your shell env and the wizard "
            "will skip this prompt next time.[/]"
        )


class Container(Widget):
    """A bare container widget for dynamically mounting/removing children.

    Plain `Widget` works for this — exposing it as a named subclass keeps
    the intent clear at call sites.
    """

    DEFAULT_CSS = """
    Container {
        height: auto;
        width: 100%;
    }
    """
