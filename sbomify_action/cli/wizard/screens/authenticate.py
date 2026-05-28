"""Authenticate screen — token entry + parallel workspace prefetch."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Button, Input, LoadingIndicator, Static
from textual.worker import Worker, WorkerState

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import WorkspaceSnapshot
from sbomify_action.exceptions import APIError, AuthError
from sbomify_action.sbomify_api import SbomifyApiClient


class Container(Widget):
    """Bare container used to swap a LoadingIndicator in / out."""

    DEFAULT_CSS = """
    Container { height: auto; width: 100%; }
    """


class AuthenticateScreen(WizardScreen):
    """Phase 3 — validate token + prefetch products/components/profiles."""

    step_index = 3
    step_title = "Authenticate"
    step_subtitle = "Validate your sbomify API token and load your workspace."

    BINDINGS = [
        Binding("enter", "submit", "Submit", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="wizard-panel"):
            yield Static("[b]API token[/]", classes="wizard-title")
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

        def _list_products() -> list[dict[str, object]]:
            return SbomifyApiClient(base_url, token).list_products()

        def _list_components() -> list[dict[str, object]]:
            return SbomifyApiClient(base_url, token).list_components()

        def _list_profiles() -> list[dict[str, object]]:
            return SbomifyApiClient(base_url, token).list_contact_profiles()

        try:
            with ThreadPoolExecutor(max_workers=3) as pool:
                products = pool.submit(_list_products).result()
                components = pool.submit(_list_components).result()
                profiles = pool.submit(_list_profiles).result()
        except APIError as e:
            return None, None, f"Workspace fetch failed: {e}"

        workspace = WorkspaceSnapshot(products=products, components=components, contact_profiles=profiles)
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
