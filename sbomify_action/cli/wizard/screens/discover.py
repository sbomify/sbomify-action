"""Discover screen — pick the lockfiles you want to track."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, SelectionList, Static
from textual.widgets.selection_list import Selection

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import DiscoveredLockfile


class DiscoverScreen(WizardScreen):
    """Phase 1 — show every lockfile we found and let the user untick any."""

    step_index = 2
    step_title = "Discover lockfiles"
    step_subtitle = "We scanned the repo for known lockfiles. Untick any you don't want to track."

    # Standard TUI key model:
    #   ↑/↓  move within picker / between buttons
    #   Tab / Shift+Tab  hop between picker → Back → Continue
    #   Space  toggle the highlighted lockfile (SelectionList default)
    #   Enter  confirm + advance (priority so the picker's Enter doesn't swallow it)
    #   a / n  select all / none
    #   Esc  back
    BINDINGS = [
        Binding("a", "select_all", "All", show=True),
        Binding("n", "select_none", "None", show=True),
        Binding("enter", "confirm", "Continue", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._found: list[DiscoveredLockfile] = []

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="wizard-panel"):
            yield Static("[b #8A7DFF]Discovered lockfiles[/]", classes="wizard-title")
            yield Static(id="discover-summary", markup=True, classes="wizard-muted")
            yield SelectionList[str](id="lockfile-picker")
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Continue  ▸", id="continue", variant="primary")

    def on_mount(self) -> None:
        # App.__init__ already ran discovery so the welcome screen could
        # show coverage stats. Reuse that result instead of scanning again.
        self._found = list(self.wizard.state.discovered)
        picker = self.query_one("#lockfile-picker", SelectionList)
        summary = self.query_one("#discover-summary", Static)
        if not self._found:
            summary.update(
                "[#F87171]No lockfiles found.[/]\n"
                "[#CBCCCE]The wizard supports popular ecosystems (Python, JS, Go, Rust, etc.). "
                "If your project uses one, double-check you're running this from the repo root.[/]"
            )
            self.query_one("#continue", Button).disabled = True
            return
        pre_configured = sum(
            1 for lf in self._found if self.wizard.state.existing_for_lockfile(lf.rel_path) is not None
        )
        if pre_configured:
            summary.update(
                f"[#CBCCCE]Found [#F4B57F]{len(self._found)}[/] lockfile(s); "
                f"[#4ADE80]{pre_configured}[/] already wired up. Each becomes a Component on sbomify.[/]"
            )
        else:
            summary.update(
                f"[#CBCCCE]Found [#F4B57F]{len(self._found)}[/] lockfile(s). Each one becomes a Component on sbomify.[/]"
            )
        for lf in self._found:
            existing = self.wizard.state.existing_for_lockfile(lf.rel_path)
            tag = "  [#4ADE80]· already configured[/]" if existing else ""
            label = f"[b]{lf.rel_path}[/]  [#5E5E5E]·[/] [#8A7DFF]{lf.ecosystem}[/]{tag}"
            picker.add_option(Selection(label, str(lf.rel_path), initial_state=True))
        picker.focus()

    def action_select_all(self) -> None:
        self.query_one("#lockfile-picker", SelectionList).select_all()

    def action_select_none(self) -> None:
        self.query_one("#lockfile-picker", SelectionList).deselect_all()

    def action_confirm(self) -> None:
        self._continue()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "continue":
            self._continue()

    def _continue(self) -> None:
        picker = self.query_one("#lockfile-picker", SelectionList)
        selected_paths = {str(v) for v in picker.selected}
        chosen = [lf for lf in self._found if str(lf.rel_path) in selected_paths]
        if not chosen:
            self.app.bell()
            self.query_one("#discover-summary", Static).update("[#F87171]Pick at least one lockfile to continue.[/]")
            return
        self.wizard.state.selected = chosen
        from sbomify_action.cli.wizard.screens.authenticate import AuthenticateScreen

        self.wizard.push_screen(AuthenticateScreen())
