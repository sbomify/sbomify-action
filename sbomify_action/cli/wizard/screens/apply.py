"""Apply screen — run apply_plan on a worker, stream logs to a RichLog."""

from __future__ import annotations

from typing import Any

from rich.markup import escape as rich_escape
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, RichLog, Static
from textual.worker import Worker, WorkerState

from sbomify_action.cli.wizard import apply as apply_mod
from sbomify_action.cli.wizard.screens._base import WizardScreen, strip_status_codes
from sbomify_action.exceptions import PlanLimitError

# Log-line colors pulled from the sbomify marketing palette so they
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

    step_index = 9
    step_title = "Apply"
    step_subtitle = "Creating components and writing the workflow…"

    BINDINGS = [
        # Both are gated by ``check_action`` on ``_worker_done``: during the
        # apply neither is offered (bailing part-way through API mutations
        # leaves the workspace half-written), and once it finishes both
        # appear in the footer. They used to be permanently hidden, which
        # left the finished screen showing a focused "Continue ▸" button and
        # a footer with no Enter or Escape hint at all.
        Binding("enter", "continue_if_done", "Continue ▸", show=True, priority=True),
        Binding("escape", "back_if_done", "Back", show=True, priority=True),
    ]

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action in ("continue_if_done", "back_if_done"):
            return self._worker_done
        return True

    def __init__(self) -> None:
        super().__init__()
        # Toggled by on_worker_state_changed so action_back_if_done /
        # the Continue button can switch behavior once the worker has
        # finished. Don't allow Escape mid-apply — bailing while we're
        # part-way through API mutations leaves the workspace in a
        # weird state.
        self._worker_done = False
        self._worker_error = False
        # Set when the apply failed on a plan limit — drives the tailored
        # recovery CTA (reuse an existing product / component instead of
        # "retry", which would just re-fail).
        self._plan_limit: PlanLimitError | None = None
        # When the plan limit was on products and the workspace has exactly
        # one existing product, this holds it so the primary button can flip
        # the plan to "use existing" and retry in place — one keypress
        # instead of walking Back through four screens.
        self._reuse_product: dict[str, Any] | None = None
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

    def compose_actions(self) -> ComposeResult:
        with Horizontal(classes="button-row"):
            # Back is disabled during apply (you can't bail mid-API-
            # mutation) and enabled by on_worker_state_changed when
            # the worker finishes. Continue is the primary path after
            # success; on a plan-limit failure it's repurposed as the
            # "use existing product & retry" action, and on any other
            # error it stays disabled with Back the only viable option.
            yield Button("◂ Back", id="back", disabled=True)
            yield Button("Continue ▸", id="continue", variant="primary", disabled=True)

    def on_mount(self) -> None:
        # Resolve the log widget on the main thread BEFORE the worker
        # starts; the worker only holds a reference and never queries the
        # DOM itself (DOM traversal isn't thread-safe in Textual).
        self._log_widget = self.query_one("#apply-log", RichLog)
        self.run_worker(self._apply_worker, name="apply", thread=True, exclusive=True)

    def action_back_if_done(self) -> None:
        """Escape goes back, but only once the apply worker has finished —
        bailing mid-apply could leave the sbomify workspace half-mutated."""
        self._go_back()

    def action_continue_if_done(self) -> None:
        """Enter presses whatever Continue currently means — advance to Done,
        or (after a plan limit) reuse the existing product and retry.

        Routed through ``route_enter`` so Enter on a focused Back button
        still goes back, matching every other screen.
        """
        if not self._worker_done:
            return
        self.route_enter(self._activate_continue)

    def _activate_continue(self) -> None:
        button = self.query_one("#continue", Button)
        if not button.disabled:
            button.press()

    def _go_back(self) -> None:
        """Navigate back after the worker has finished.

        On a plan-limit failure this jumps straight to the screen where the
        user can fix the plan (Pick a product / Components) instead of
        stranding them on Review, where pressing Apply again would fail
        identically. Any other failure (or success) pops one screen as
        before.
        """
        if not self._worker_done:
            return
        target: type[WizardScreen] | None = None
        if self._plan_limit is not None:
            if self._plan_limit.resource == "product":
                from sbomify_action.cli.wizard.screens.product import ProductScreen

                target = ProductScreen
            elif self._plan_limit.resource == "component":
                from sbomify_action.cli.wizard.screens.components import ComponentsScreen

                target = ComponentsScreen
        stack = self.app.screen_stack
        if target is not None and any(isinstance(s, target) for s in stack):
            while not isinstance(self.app.screen_stack[-1], target):
                self.app.pop_screen()
        else:
            self.app.pop_screen()

    def _apply_worker(self) -> Exception | None:
        """Run apply_plan; return None on success, the exception on failure.

        Runs on a Textual worker thread (``thread=True``). Textual widgets
        are not thread-safe, so every DOM mutation hops back to the main
        thread via ``app.call_from_thread`` — without it, concurrent paints
        racing with ``RichLog.write`` corrupt the log's internal buffer.
        """
        log_widget = self._log_widget
        assert log_widget is not None  # set in on_mount before the worker starts
        app = self.app

        def log(kind: str, message: str) -> None:
            # ``RichLog`` is mounted with ``markup=True`` so the per-kind color
            # tags work. ``message`` is untrusted (API errors, URLs containing
            # `[`, exception text) — escape it so a stray `[` doesn't get
            # parsed as markup and either misrender the line or raise mid-log.
            # HTTP status markers are stripped: the human-readable detail is
            # what the user acts on; the code is developer noise.
            color = _COLOR_BY_KIND.get(kind, "white")
            line = f"[{color}]{kind:>8}[/]  {rich_escape(strip_status_codes(message))}"
            app.call_from_thread(log_widget.write, line)

        try:
            apply_mod.apply_plan(self.wizard.state, self.wizard.opts, log=log)
        except Exception as exc:  # noqa: BLE001
            log("error", str(exc))
            return exc
        return None

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != "apply":
            return
        if event.state == WorkerState.SUCCESS:
            self._worker_done = True
            # ``check_action`` results are cached, so the Enter/Escape hints
            # stay hidden until we explicitly invalidate them.
            self.refresh_bindings()
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
                self._on_apply_failed(result, back_btn, continue_btn)
        elif event.state == WorkerState.ERROR:
            self._worker_done = True
            self._worker_error = True
            self.refresh_bindings()
            back_btn = self.query_one("#back", Button)
            continue_btn = self.query_one("#continue", Button)
            error_text = strip_status_codes(str(event.worker.error))
            self._show_error_banner(error_text)
            # ``RichLog`` is markup=True; escape the worker-error message so a
            # `[` in the exception text doesn't collide with the color tags.
            self.query_one("#apply-log", RichLog).write(f"[#F87171]worker error: {rich_escape(error_text)}[/]")
            continue_btn.label = "(apply failed)"
            continue_btn.disabled = True
            back_btn.variant = "primary"
            back_btn.disabled = False
            back_btn.focus()

    def _on_apply_failed(self, error: Exception, back_btn: Button, continue_btn: Button) -> None:
        """Render the failure state: tailored recovery for plan limits,
        generic Back-and-retry for everything else."""
        self._worker_error = True
        if isinstance(error, PlanLimitError):
            self._plan_limit = error
            self._show_plan_limit_banner(error)
        else:
            self._show_error_banner(strip_status_codes(str(error)))
        if self._reuse_product is not None:
            name = str(self._reuse_product.get("name") or "existing product")
            continue_btn.label = f"Use '{name}' & retry ▸"
            continue_btn.disabled = False
            back_btn.disabled = False
            continue_btn.focus()
        else:
            continue_btn.label = "(apply failed)"
            continue_btn.disabled = True
            back_btn.variant = "primary"
            back_btn.disabled = False
            back_btn.focus()

    def _show_plan_limit_banner(self, error: PlanLimitError) -> None:
        """Plan-limit failures get a real recovery path, not "retry".

        Retrying the same plan re-fails identically, so the CTA depends on
        what the workspace offers: reuse the (single) existing product in
        place, pick one on the product step, or free up quota / upgrade.
        """
        message = strip_status_codes(str(error))
        workspace = self.wizard.state.workspace
        products = workspace.products if workspace else []

        if error.resource == "product" and len(products) == 1:
            self._reuse_product = products[0]
            name = rich_escape(str(products[0].get("name") or "(unnamed)"))
            cta = (
                f"Press [b]Use '{name}' & retry[/] to attach everything to your existing "
                f"product instead — or delete an unused product / upgrade your plan in the "
                "sbomify dashboard, then press [b]◂ Back[/] and Apply again."
            )
        elif error.resource == "product" and products:
            cta = (
                "Press [b]◂ Back[/] (or [b]Esc[/]) to return to the [b]Pick a product[/] step "
                "and select one of your existing products instead — or delete an unused "
                "product / upgrade your plan in the sbomify dashboard, then retry."
            )
        elif error.resource == "product":
            cta = (
                "Delete an unused product (or upgrade your plan) in the sbomify dashboard, "
                "then press [b]◂ Back[/] and Apply again."
            )
        elif error.resource == "component":
            cta = (
                "Press [b]◂ Back[/] (or [b]Esc[/]) to return to the [b]Components[/] step and "
                "reuse existing components where possible — or delete unused components / "
                "upgrade your plan in the sbomify dashboard, then retry."
            )
        else:
            cta = "Free up quota (or upgrade your plan) in the sbomify dashboard, then press [b]◂ Back[/] and retry."

        self._update_banner(
            f"[#F4B57F]✗  Plan limit reached.[/]  [#CBCCCE]{rich_escape(message)}[/]\n[#5E5E5E]{cta}[/]"
        )

    def _show_error_banner(self, message: str) -> None:
        """Surface the error in a pinned banner above the log so it
        survives the log scrolling past."""
        # ``message`` is API/exception text which can contain `[` — escape so
        # a stray bracket can't mis-style the banner or raise from markup
        # parsing.
        self._update_banner(
            f"[#F87171]✗  Apply failed.[/]  [#CBCCCE]{rich_escape(message)}[/]\n"
            "[#5E5E5E]Press [b]◂ Back[/] (or [b]Esc[/]) to return to Review and retry.[/]"
        )

    def _update_banner(self, markup: str) -> None:
        try:
            banner = self.query_one("#apply-error-banner", Static)
        except Exception:  # noqa: BLE001
            return
        banner.update(markup)
        banner.display = True

    def _retry_with_existing_product(self) -> None:
        """Flip the plan from create-product to use-existing and re-run apply.

        ``apply_plan`` resets its own output state and component creation is
        get-or-create, so re-running on the same screen is safe.
        """
        product = self._reuse_product
        assert product is not None
        plan = self.wizard.state.plan
        plan.create_product = None
        plan.use_product_id = str(product.get("id") or "")

        self._worker_done = False
        self._worker_error = False
        self._plan_limit = None
        self._reuse_product = None
        # Back in flight — withdraw the Enter/Escape hints again.
        self.refresh_bindings()
        try:
            banner = self.query_one("#apply-error-banner", Static)
            banner.display = False
            panel = self.query_one("#apply-panel", Vertical)
            panel.border_title = "⏳  Applying"
            panel.border_subtitle = "live log"
        except Exception:  # noqa: BLE001
            pass
        back_btn = self.query_one("#back", Button)
        continue_btn = self.query_one("#continue", Button)
        back_btn.disabled = True
        back_btn.variant = "default"
        continue_btn.label = "Continue ▸"
        continue_btn.disabled = True
        log = self.query_one("#apply-log", RichLog)
        log.write("")
        log.write(f"[#CBCCCE]Retrying with existing product [b]{rich_escape(str(product.get('name') or ''))}[/] …[/]")
        self.run_worker(self._apply_worker, name="apply", thread=True, exclusive=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self._go_back()
            return
        if event.button.id == "continue":
            if self._reuse_product is not None:
                self._retry_with_existing_product()
                return
            if self._worker_error:
                # Shouldn't happen — Continue is disabled on error —
                # but defend in depth.
                self.app.pop_screen()
                return
            from sbomify_action.cli.wizard.screens.done import DoneScreen

            self.wizard.push_screen(DoneScreen())
