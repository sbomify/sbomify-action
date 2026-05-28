"""Apply screen — run apply_plan on a worker, stream logs to a RichLog."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, RichLog, Static
from textual.worker import Worker, WorkerState

from sbomify_action.cli.wizard import apply as apply_mod
from sbomify_action.cli.wizard.screens._base import WizardScreen

# Log-line colours pulled from the sbomify marketing palette so they
# read naturally against the wizard's dark background. See styles.tcss
# for the source-of-truth token names.
_COLOR_BY_KIND = {
    "info": "#CBCCCE",  # tertiaryText
    "success": "#86EFAC",  # brand-coherent mint
    "warning": "#F4B57F",  # gradient peach
    "error": "#F87171",  # soft red, pairs with the dark theme
}


class ApplyScreen(WizardScreen):
    """Phase 6b — actually do the work, log line by line as it happens."""

    step_index = 6
    step_title = "Apply"
    step_subtitle = "Creating components and writing the workflow…"

    BINDINGS = [
        Binding("escape", "noop", "", show=False),
    ]

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="wizard-panel"):
            yield Static("[b]Apply log[/]", classes="wizard-title")
            yield RichLog(id="apply-log", wrap=True, markup=True, highlight=False)
        with Horizontal(classes="button-row"):
            yield Button("Continue ▸", id="continue", variant="primary", disabled=True)

    def on_mount(self) -> None:
        self.run_worker(self._apply_worker, name="apply", thread=True, exclusive=True)

    def action_noop(self) -> None:
        """Swallow Escape while apply is running so the user can't bail mid-write."""

    def _apply_worker(self) -> str | None:
        """Run apply_plan; return None on success, error message on failure."""
        log_widget = self.query_one("#apply-log", RichLog)

        def log(kind: str, message: str) -> None:
            colour = _COLOR_BY_KIND.get(kind, "white")
            log_widget.write(f"[{colour}]{kind:>8}[/]  {message}")

        try:
            apply_mod.apply_plan(self.wizard.state, self.wizard.opts, log=log)
        except Exception as exc:  # noqa: BLE001
            log("error", str(exc))
            return str(exc)
        return None

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != "apply":
            return
        if event.state == WorkerState.SUCCESS:
            self.query_one("#continue", Button).disabled = False
            self.query_one("#continue", Button).focus()
        elif event.state == WorkerState.ERROR:
            self.query_one("#apply-log", RichLog).write(f"[#F87171]worker error: {event.worker.error}[/]")
            self.query_one("#continue", Button).disabled = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "continue":
            from sbomify_action.cli.wizard.screens.done import DoneScreen

            self.wizard.push_screen(DoneScreen())
