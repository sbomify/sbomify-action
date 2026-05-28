"""Apply screen — run apply_plan on a worker, stream logs to a RichLog."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, RichLog
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

    step_index = 7
    step_title = "Apply"
    step_subtitle = "Creating components and writing the workflow…"

    BINDINGS = [
        Binding("escape", "back_if_done", "", show=False, priority=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        # Toggled by on_worker_state_changed so action_back_if_done /
        # the Continue button can switch behaviour once the worker has
        # finished. Don't allow Escape mid-apply — bailing while we're
        # part-way through API mutations leaves the workspace in a
        # weird state.
        self._worker_done = False
        self._worker_error = False

    def compose_body(self) -> ComposeResult:
        panel = Vertical(classes="wizard-panel")
        panel.border_title = "⏳  Applying"
        panel.border_subtitle = "live log"
        with panel:
            yield RichLog(id="apply-log", wrap=True, markup=True, highlight=False)
        with Horizontal(classes="button-row"):
            yield Button("Continue ▸", id="continue", variant="primary", disabled=True)

    def on_mount(self) -> None:
        self.run_worker(self._apply_worker, name="apply", thread=True, exclusive=True)

    def action_back_if_done(self) -> None:
        """Escape pops back to the previous screen, but only once the
        apply worker has finished — bailing mid-apply could leave the
        sbomify workspace half-mutated."""
        if self._worker_done:
            self.app.pop_screen()

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
            self._worker_done = True
            result = event.worker.result
            btn = self.query_one("#continue", Button)
            if result is None:
                # apply_plan returned cleanly.
                btn.label = "Continue ▸"
                btn.disabled = False
                btn.focus()
            else:
                # _apply_worker caught an exception and returned its
                # message. The user can't usefully continue to Done
                # from a half-applied state — send them back to Review
                # to retry instead.
                self._worker_error = True
                btn.label = "◂ Back to fix"
                btn.variant = "default"
                btn.disabled = False
                btn.focus()
                self.query_one("#apply-log", RichLog).write(
                    "[#F4B57F]Apply did not complete. Escape or 'Back to fix' "
                    "returns to Review so you can retry.[/]"
                )
        elif event.state == WorkerState.ERROR:
            self._worker_done = True
            self._worker_error = True
            self.query_one("#apply-log", RichLog).write(
                f"[#F87171]worker error: {event.worker.error}[/]"
            )
            btn = self.query_one("#continue", Button)
            btn.label = "◂ Back to fix"
            btn.variant = "default"
            btn.disabled = False
            btn.focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "continue":
            if self._worker_error:
                # Pop straight back so the user can change their plan
                # or fix the upstream condition that caused the error.
                self.app.pop_screen()
                return
            from sbomify_action.cli.wizard.screens.done import DoneScreen

            self.wizard.push_screen(DoneScreen())
