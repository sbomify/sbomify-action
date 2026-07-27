"""Publish screen — generate and upload the first SBOMs locally."""

from __future__ import annotations

from rich.markup import escape as rich_escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, RichLog, Static
from textual.worker import Worker, WorkerState

from sbomify_action.cli.wizard import publish as publish_mod
from sbomify_action.cli.wizard.ci_emitter import MatrixRow, matrix_rows
from sbomify_action.cli.wizard.screens._base import WizardScreen

# Same palette as the Apply screen's log (see styles.tcss for the token
# names), plus a muted "output" tier for raw pipeline lines so the
# wizard's own status lines stand out from the subprocess firehose.
_COLOR_BY_KIND = {
    "info": "#CBCCCE",  # tertiaryText
    "success": "#86EFAC",  # brand-coherent mint
    "warning": "#F4B57F",  # gradient peach
    "error": "#F87171",  # soft red, pairs with the dark theme
    "output": "#5E5E5E",  # muted — raw pipeline output
}


class PublishScreen(WizardScreen):
    """Phase 9 — run the pipeline locally so the first SBOMs land now.

    Unlike Apply (which auto-starts on mount), publishing waits for an
    explicit button press: it spawns real pipeline subprocesses that can
    take minutes (generation + enrichment) and it's genuinely optional —
    the workflow file is already written, so skipping just means CI does
    the first publish on the next push instead.
    """

    step_index = 9
    step_title = "Publish"
    step_subtitle = "Optional — publish your first SBOMs now instead of waiting for CI."

    BINDINGS = [
        Binding("enter", "advance", "Publish ▸", show=True, priority=True),
        Binding("escape", "back_if_not_running", "Back", show=True, priority=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        # "idle" until the user presses Publish, "running" while the
        # worker is streaming, "done" once it finished (either way).
        self._phase: str = "idle"
        self._had_failures = False
        # Captured from the DOM on the main thread in ``on_mount`` so the
        # worker thread never queries widgets directly (DOM traversal is
        # not thread-safe in Textual).
        self._log_widget: RichLog | None = None

    def compose_body(self) -> ComposeResult:
        # Failure banner sits ABOVE the log so it survives the log
        # scrolling past the lines that caused it. Hidden until needed.
        banner = Static("", id="publish-banner", markup=True)
        banner.display = False

        panel = Vertical(classes="wizard-panel", id="publish-panel")
        panel.border_title = "⏫  First publish"
        panel.border_subtitle = f"{len(self._rows())} run(s) planned"
        with panel:
            yield Static(self._planned_markup(), classes="wizard-muted", id="publish-planned")
            yield banner
            yield RichLog(id="publish-log", wrap=True, markup=True, highlight=False)
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Skip ▸", id="skip")
            yield Button("Publish now ▸", id="publish", variant="primary")

    def on_mount(self) -> None:
        self._log_widget = self.query_one("#publish-log", RichLog)
        self.query_one("#publish", Button).focus()

    def _rows(self) -> list[MatrixRow]:
        """The planned matrix rows — same helper the emitted workflow used."""
        state = self.wizard.state
        component_ids = {str(rel): cid for rel, cid in state.component_ids.items()}
        return matrix_rows(
            state.plan.create_components,
            state.plan.sbom_formats or ["cyclonedx"],
            component_ids,
        )

    def _planned_markup(self) -> str:
        """One line per planned run + a note on credentials and skipping."""
        lines = [
            f"  [#8A7DFF]▸[/]  {rich_escape(row.component_name)}  "
            f"[#5E5E5E]{rich_escape(row.lockfile)}[/]  [#CBCCCE]→ {row.sbom_format}[/]"
            for row in self._rows()
        ]
        lines.append("")
        lines.append(
            "[#5E5E5E]Runs the same pipeline your new workflow runs in CI, using this "
            "wizard session's token. Skipping is fine — CI publishes on the next push.[/]"
        )
        return "\n".join(lines)

    def action_advance(self) -> None:
        self.route_enter(self._advance)

    def action_back_if_not_running(self) -> None:
        """Escape pops back, but never mid-publish — a run in flight would
        keep uploading with nobody watching the log."""
        if self._phase != "running":
            self.app.pop_screen()

    def _advance(self) -> None:
        if self._phase == "idle":
            self._start_publish()
        elif self._phase == "done":
            self._continue_to_done()

    def _start_publish(self) -> None:
        self._phase = "running"
        for button_id in ("back", "skip", "publish"):
            self.query_one(f"#{button_id}", Button).disabled = True
        panel = self.query_one("#publish-panel", Vertical)
        panel.border_subtitle = "publishing…"
        self.run_worker(self._publish_worker, name="publish", thread=True, exclusive=True)

    def _publish_worker(self) -> bool:
        """Run run_publish on a worker thread; returns its all-ok flag.

        Textual widgets are not thread-safe, so every log line hops back
        to the main thread via ``app.call_from_thread``.
        """
        log_widget = self._log_widget
        assert log_widget is not None  # set in on_mount, before the button can start us
        app = self.app

        def log(kind: str, message: str) -> None:
            # Raw pipeline output is high-volume — render it muted and
            # unprefixed so the wizard's own status lines stay scannable.
            # Everything is untrusted text (subprocess output, exception
            # text); escape so a stray `[` can't break markup parsing.
            colour = _COLOR_BY_KIND.get(kind, "white")
            if kind == "output":
                line = f"[{colour}]{rich_escape(message)}[/]"
            else:
                line = f"[{colour}]{kind:>8}[/]  {rich_escape(message)}"
            app.call_from_thread(log_widget.write, line)

        return publish_mod.run_publish(self.wizard.state, self.wizard.opts, log=log)

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != "publish":
            return
        if event.state not in (WorkerState.SUCCESS, WorkerState.ERROR):
            return
        self._phase = "done"
        back_btn = self.query_one("#back", Button)
        skip_btn = self.query_one("#skip", Button)
        publish_btn = self.query_one("#publish", Button)
        back_btn.disabled = False
        skip_btn.display = False
        panel = self.query_one("#publish-panel", Vertical)

        if event.state == WorkerState.ERROR:
            # run_publish is written to never raise; defend anyway. The
            # step stays best-effort, so Continue remains available.
            self._had_failures = True
            error_text = str(event.worker.error)
            if self._log_widget is not None:
                self._log_widget.write(f"[#F87171]worker error: {rich_escape(error_text)}[/]")
            self._show_banner(error_text)
            all_ok = False
        else:
            all_ok = bool(event.worker.result)
            if not all_ok:
                self._had_failures = True
                self._show_banner("Some runs failed — see the log above. The CI workflow will retry on the next push.")

        if all_ok:
            panel.border_title = "✓  Published"
            panel.border_subtitle = "ready to finish"
        else:
            panel.border_title = "⚠  Published with failures"
            panel.border_subtitle = "CI will retry on the next push"
        publish_btn.label = "Continue ▸"
        publish_btn.disabled = False
        publish_btn.focus()

    def _show_banner(self, message: str) -> None:
        try:
            banner = self.query_one("#publish-banner", Static)
        except Exception:  # noqa: BLE001
            return
        banner.update(f"[#F4B57F]⚠  {rich_escape(message)}[/]")
        banner.display = True

    def _continue_to_done(self) -> None:
        from sbomify_action.cli.wizard.screens.done import DoneScreen

        self.wizard.push_screen(DoneScreen())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            if self._phase != "running":
                self.app.pop_screen()
            return
        if event.button.id == "skip":
            # Explicitly not publishing — leave publish_outcomes empty so
            # the Done screen renders exactly as it did pre-publish-step.
            self._continue_to_done()
            return
        if event.button.id == "publish":
            self._advance()
