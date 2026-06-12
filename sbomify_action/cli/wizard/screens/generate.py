"""Generate screen — optional final step: build + upload the SBOM(s) now.

Only reached when ``generate.generation_available`` is true (the SBOM
generators are installed and the user authenticated). Offers a yes/no:
on "Generate" it runs the real generate→upload pipeline once per
(component, format) on a worker thread, streaming each child line into a
RichLog; on "Skip" (or after a run) it advances to Done.
"""

from __future__ import annotations

from rich.markup import escape as rich_escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, RichLog, Static
from textual.worker import Worker, WorkerState

from sbomify_action.cli.wizard import generate as generate_mod
from sbomify_action.cli.wizard.screens._base import WizardScreen

# Same per-kind palette the Apply screen uses, so the two live logs read
# identically.
_COLOR_BY_KIND = {
    "info": "#CBCCCE",
    "success": "#86EFAC",
    "warning": "#F4B57F",
    "error": "#F87171",
}


class GenerateScreen(WizardScreen):
    """Phase 6d — optionally generate + upload the first SBOM(s) in place."""

    step_index = 8
    step_title = "Generate"
    step_subtitle = "Optional — build and upload your first SBOM(s) right now."

    BINDINGS = [
        Binding("enter", "submit", "", show=False, priority=True),
        Binding("escape", "skip", "Skip", show=True, priority=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        # NB: don't name these ``_running`` / ``_done`` — Textual's
        # MessagePump owns ``_running`` internally and would clobber ours.
        self._generating = False
        self._finished = False
        self._log_widget: RichLog | None = None

    def compose_body(self) -> ComposeResult:
        offer = Vertical(classes="wizard-panel", id="generate-offer")
        offer.border_title = "◆  Generate & upload now?"
        offer.border_subtitle = "a live end-to-end test of what you just set up"
        with offer:
            yield Static(self._offer_text(), classes="wizard-muted")

        # Hidden until the user opts in — then the offer panel is swapped
        # for this live log, mirroring the Apply screen.
        log_panel = Vertical(classes="wizard-panel", id="generate-log-panel")
        log_panel.border_title = "⏳  Generating"
        log_panel.border_subtitle = "live log"
        log_panel.display = False
        with log_panel:
            yield RichLog(id="generate-log", wrap=True, markup=True, highlight=False)

        with Horizontal(classes="button-row"):
            yield Button("Skip ▸", id="skip")
            yield Button("Generate  ▸", id="generate", variant="primary")
            # Revealed once a run finishes; routes to Done.
            yield Button("Continue  ▸", id="continue", variant="primary", disabled=True)

    def on_mount(self) -> None:
        self.query_one("#continue", Button).display = False
        self.query_one("#generate", Button).focus()

    # ----- navigation --------------------------------------------------

    def action_submit(self) -> None:
        self.route_enter(self._on_enter)

    def _on_enter(self) -> None:
        if self._finished:
            self._go_done()
        elif not self._generating:
            self._start_generate()

    def action_skip(self) -> None:
        # Skip is the offer-stage Escape; once a run is in flight bailing
        # would orphan an in-progress upload, so ignore it then. After the
        # run finishes Escape just advances to Done.
        if self._generating:
            return
        self._go_done()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "skip":
            self.action_skip()
        elif event.button.id == "generate":
            if not self._generating and not self._finished:
                self._start_generate()
        elif event.button.id == "continue":
            self._go_done()

    def _go_done(self) -> None:
        from sbomify_action.cli.wizard.screens.done import DoneScreen

        self.wizard.push_screen(DoneScreen())

    # ----- generation --------------------------------------------------

    def _start_generate(self) -> None:
        self._generating = True
        self.query_one("#generate-offer", Vertical).display = False
        self.query_one("#generate-log-panel", Vertical).display = True
        self.query_one("#skip", Button).disabled = True
        self.query_one("#generate", Button).disabled = True
        # Resolve the log widget on the main thread before the worker runs;
        # the worker only writes to it via call_from_thread (Textual DOM
        # access isn't thread-safe).
        self._log_widget = self.query_one("#generate-log", RichLog)
        self.run_worker(self._generate_worker, name="generate", thread=True, exclusive=True)

    def _generate_worker(self) -> tuple[int, int]:
        log_widget = self._log_widget
        assert log_widget is not None  # set in _start_generate before the worker starts
        app = self.app

        def log(kind: str, message: str) -> None:
            colour = _COLOR_BY_KIND.get(kind, "white")
            # ``message`` is untrusted child output (URLs, exception text, '['
            # chars) — escape so a stray bracket can't be parsed as markup.
            line = f"[{colour}]{kind:>8}[/]  {rich_escape(message)}"
            app.call_from_thread(log_widget.write, line)

        return generate_mod.run_generation(
            self.wizard.state,
            api_base_url=self.wizard.opts.api_base_url,
            repo_root=self.wizard.opts.repo_root,
            log=log,
        )

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != "generate":
            return
        if event.state == WorkerState.SUCCESS:
            succeeded, total = event.worker.result
            self._finish(succeeded, total)
        elif event.state == WorkerState.ERROR:
            # run_generation catches per-job failures itself; reaching here
            # means something unexpected escaped. Surface it and let the user
            # continue to Done (the workflow file is already written).
            self.query_one("#generate-log", RichLog).write(
                f"[#F87171]worker error: {rich_escape(str(event.worker.error))}[/]"
            )
            self._finish(0, 0)

    def _finish(self, succeeded: int, total: int) -> None:
        self._generating = False
        self._finished = True
        # Record on state so Done can add a line to its summary.
        self.wizard.state.generated_ok = succeeded
        self.wizard.state.generated_total = total

        panel = self.query_one("#generate-log-panel", Vertical)
        if total > 0 and succeeded == total:
            panel.border_title = "✓  Generated"
            panel.border_subtitle = f"uploaded {succeeded}/{total}"
        elif succeeded > 0:
            panel.border_title = "⚠  Partially generated"
            panel.border_subtitle = f"uploaded {succeeded}/{total}"
        else:
            panel.border_title = "✗  Generation failed"
            panel.border_subtitle = "see log above"

        self.query_one("#generate", Button).display = False
        self.query_one("#skip", Button).display = False
        cont = self.query_one("#continue", Button)
        cont.disabled = False
        cont.display = True
        cont.focus()

    # ----- offer text --------------------------------------------------

    def _offer_text(self) -> str:
        jobs = generate_mod.plan_generation_jobs(self.wizard.state)
        runnable = [j for j in jobs if j.available]
        skipped = [j for j in jobs if not j.available]

        lines = [
            "You're authenticated and the SBOM generators are installed here, so the",
            "wizard can build and upload your first SBOM(s) now — a live end-to-end test",
            "of the workflow you just configured. (You can always Skip and let CI do it.)",
            "",
            "[#CBCCCE]This will generate and upload:[/]",
        ]
        for job in runnable:
            lines.append(
                f"  [#86EFAC]•[/]  [b]{rich_escape(job.component_name)}[/]  "
                f"[#5E5E5E]({rich_escape(job.lockfile_rel)})[/]  [#5E5E5E]→[/]  {job.sbom_format}"
            )
        lines.append("")
        lines.append(
            f"[#5E5E5E]{len(runnable)} SBOM(s) — uploaded to sbomify; the files aren't written to your repo.[/]"
        )
        if skipped:
            lines.append(f"[#F4B57F]⚠  {len(skipped)} skipped — no generator installed for their lockfile.[/]")
        return "\n".join(lines)
