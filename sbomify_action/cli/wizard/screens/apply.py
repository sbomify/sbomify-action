"""Apply screen — ProgressBar + RichLog as side effects happen on a worker."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, ProgressBar, RichLog, Static
from textual.worker import Worker, WorkerState

from sbomify_action.cli.wizard.apply import LogKind, apply_plan
from sbomify_action.cli.wizard.screens._base import WizardScreen


class ApplyScreen(WizardScreen):
    """Phase 6 — run `apply_plan` and stream output to the user."""

    step_index = 6
    step_title = "Applying"
    step_subtitle = "Creating components on sbomify and writing workflow files."

    # Apply is non-interactive — user can only watch or cancel via Ctrl-C.
    BINDINGS = [
        Binding("escape", "noop", "", show=False),
    ]

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="wizard-panel"):
            yield Static("[b #8A7DFF]Applying plan…[/]", classes="wizard-title")
            yield ProgressBar(id="progress", show_eta=False)
            yield Static("", id="status", markup=True, classes="wizard-muted")
            yield RichLog(id="log", highlight=False, markup=True, wrap=True, max_lines=400)
        with Horizontal(classes="button-row"):
            yield Button("Continue  ▸", id="continue", variant="primary", disabled=True)

    def on_mount(self) -> None:
        # Total = product + helper-project + N components + sbomify.json files + workflow files
        plan = self.wizard.state.plan
        total = 2 + len(plan.create_components)
        total += len(plan.sbomify_json_files)
        total += sum(1 for _, _, action in plan.workflow_files if action != "skip")
        if plan.create_initial_release:
            total += 1
        self.query_one("#progress", ProgressBar).update(total=max(total, 1), progress=0)
        self.run_worker(
            self._apply_worker,
            name="apply",
            thread=True,
            exclusive=True,
            description="Applying plan",
        )

    def _apply_worker(self) -> str | None:
        """Run apply_plan; return None on success or an error string."""
        try:
            apply_plan(
                self.wizard.state,
                self.wizard.opts,
                log=lambda kind, msg: self.app.call_from_thread(self._log_line, kind, msg),
            )
            return None
        except Exception as e:  # noqa: BLE001 — surface every failure to the user
            return f"{type(e).__name__}: {e}"

    def _log_line(self, kind: LogKind, message: str) -> None:
        log = self.query_one("#log", RichLog)
        prefix = {
            "info": "[#8A7DFF]·[/]",
            "success": "[#4ADE80]✓[/]",
            "warning": "[#F4B57F]![/]",
            "error": "[#F87171]✗[/]",
        }.get(kind, "·")
        log.write(f"{prefix}  {message}")
        progress = self.query_one("#progress", ProgressBar)
        progress.advance(1)
        self.query_one("#status", Static).update(f"[#CBCCCE]{message}[/]")

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != "apply":
            return
        if event.state == WorkerState.SUCCESS:
            error = event.worker.result
            if error is None:
                self._on_done()
            else:
                self._on_failure(error)
        elif event.state == WorkerState.ERROR:
            self._on_failure(f"Unexpected error: {event.worker.error}")

    def _on_done(self) -> None:
        self.query_one("#progress", ProgressBar).update(progress=self.query_one("#progress", ProgressBar).total or 1)
        self.query_one("#status", Static).update("[#4ADE80]Done.[/]")
        button = self.query_one("#continue", Button)
        button.disabled = False
        button.focus()

    def _on_failure(self, message: str) -> None:
        self.query_one("#status", Static).update(f"[#F87171]Apply failed: {message}[/]")
        self.query_one("#log", RichLog).write(f"[#F87171]✗  {message}[/]")
        button = self.query_one("#continue", Button)
        button.label = "Close"
        button.disabled = False
        button.focus()

    def action_noop(self) -> None:
        pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "continue":
            from sbomify_action.cli.wizard.screens.done import DoneScreen

            self.wizard.push_screen(DoneScreen(dry_run=False))
