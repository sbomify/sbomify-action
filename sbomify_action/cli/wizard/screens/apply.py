"""Apply screen — run apply_plan on a worker, stream logs to a RichLog."""

from __future__ import annotations

from rich.markup import escape as rich_escape
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

    step_index = 8
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
        # Captured from the DOM on the main thread in ``on_mount`` so the
        # worker thread never queries widgets directly. Always assigned
        # before the worker is started.
        self._log_widget: RichLog | None = None

    def compose_body(self) -> ComposeResult:
        # Error banner sits ABOVE the log so it stays visible even when
        # the log has scrolled past the line that caused the failure.
        # Hidden until on_worker_state_changed populates it.
        error_banner = Static("", id="apply-error-banner", markup=True)
        error_banner.display = False

        panel = Vertical(classes="wizard-panel", id="apply-panel")
        panel.border_title = "⏳  Applying"
        panel.border_subtitle = "live log"
        with panel:
            yield error_banner
            yield RichLog(id="apply-log", wrap=True, markup=True, highlight=False)
        with Horizontal(classes="button-row"):
            # Back is disabled during apply (you can't bail mid-API-
            # mutation) and enabled by on_worker_state_changed when
            # the worker finishes. Continue is the primary path after
            # success; it stays disabled on error and Back becomes
            # the only viable option.
            yield Button("◂ Back", id="back", disabled=True)
            yield Button("Continue ▸", id="continue", variant="primary", disabled=True)

    def on_mount(self) -> None:
        # Resolve the log widget on the main thread BEFORE the worker
        # starts; the worker only holds a reference and never queries the
        # DOM itself (DOM traversal isn't thread-safe in Textual).
        self._log_widget = self.query_one("#apply-log", RichLog)
        self.run_worker(self._apply_worker, name="apply", thread=True, exclusive=True)

    def action_back_if_done(self) -> None:
        """Escape pops back to the previous screen, but only once the
        apply worker has finished — bailing mid-apply could leave the
        sbomify workspace half-mutated."""
        if self._worker_done:
            self.app.pop_screen()

    def _apply_worker(self) -> str | None:
        """Run apply_plan; return None on success, error message on failure.

        Runs on a Textual worker thread (``thread=True``). Textual widgets
        are not thread-safe, so every DOM mutation hops back to the main
        thread via ``app.call_from_thread`` — without it, concurrent paints
        racing with ``RichLog.write`` corrupt the log's internal buffer.
        """
        log_widget = self._log_widget
        assert log_widget is not None  # set in on_mount before the worker starts
        app = self.app

        def log(kind: str, message: str) -> None:
            # ``RichLog`` is mounted with ``markup=True`` so the per-kind colour
            # tags work. ``message`` is untrusted (API errors, URLs containing
            # `[`, exception text) — escape it so a stray `[` doesn't get
            # parsed as markup and either misrender the line or raise mid-log.
            colour = _COLOR_BY_KIND.get(kind, "white")
            line = f"[{colour}]{kind:>8}[/]  {rich_escape(message)}"
            app.call_from_thread(log_widget.write, line)

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
            back_btn = self.query_one("#back", Button)
            continue_btn = self.query_one("#continue", Button)
            back_btn.disabled = False
            if result is None:
                # apply_plan returned cleanly. Swap the panel title to
                # a positive marker so the user has a clear "done"
                # signal — the hourglass would otherwise hover over a
                # finished operation.
                try:
                    panel = self.query_one("#apply-panel", Vertical)
                    panel.border_title = "✓  Applied"
                    panel.border_subtitle = "ready to finish"
                except Exception:  # noqa: BLE001
                    pass
                continue_btn.label = "Continue ▸"
                continue_btn.disabled = False
                continue_btn.focus()
            else:
                # _apply_worker caught an exception and returned its
                # message. The user can't usefully continue to Done
                # from a half-applied state — surface the error in
                # the pinned banner so it doesn't scroll past, and
                # leave only the Back button enabled.
                self._worker_error = True
                self._show_error_banner(result)
                continue_btn.label = "(apply failed)"
                continue_btn.disabled = True
                back_btn.variant = "primary"
                back_btn.focus()
        elif event.state == WorkerState.ERROR:
            self._worker_done = True
            self._worker_error = True
            back_btn = self.query_one("#back", Button)
            continue_btn = self.query_one("#continue", Button)
            error_text = str(event.worker.error)
            self._show_error_banner(error_text)
            # ``RichLog`` is markup=True; escape the worker-error message so a
            # `[` in the exception text (eg "APIError [404] - ...") doesn't
            # collide with the colour wrapping tags.
            self.query_one("#apply-log", RichLog).write(f"[#F87171]worker error: {rich_escape(error_text)}[/]")
            continue_btn.label = "(apply failed)"
            continue_btn.disabled = True
            back_btn.variant = "primary"
            back_btn.disabled = False
            back_btn.focus()

    def _show_error_banner(self, message: str) -> None:
        """Surface the error in a pinned banner above the log so it
        survives the log scrolling past."""
        try:
            banner = self.query_one("#apply-error-banner", Static)
        except Exception:  # noqa: BLE001
            return
        # ``banner`` is a Static with markup=True. The message is API/exception
        # text which can contain `[` — escape so a stray bracket can't either
        # mis-style the rest of the banner or raise from markup parsing.
        banner.update(
            f"[#F87171]✗  Apply failed.[/]  [#CBCCCE]{rich_escape(message)}[/]\n"
            "[#5E5E5E]Press [b]◂ Back[/] (or [b]Esc[/]) to return to Review and retry.[/]"
        )
        banner.display = True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            if self._worker_done:
                self.app.pop_screen()
            return
        if event.button.id == "continue":
            if self._worker_error:
                # Shouldn't happen — Continue is disabled on error —
                # but defend in depth.
                self.app.pop_screen()
                return
            from sbomify_action.cli.wizard.screens.done import DoneScreen

            self.wizard.push_screen(DoneScreen())
