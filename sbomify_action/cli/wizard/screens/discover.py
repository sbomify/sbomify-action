"""Discover screen — multi-select lockfiles to track."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, SelectionList, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen


class DiscoverScreen(WizardScreen):
    """Phase 2 — multi-select discovered lockfiles."""

    step_index = 2
    step_title = "Discover lockfiles"
    step_subtitle = "Pick the lockfiles the SBOM workflow should track."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        # priority so the SelectionList can't swallow Escape.
        Binding("escape", "app.pop_screen", "Back", show=True, priority=True),
        Binding("space", "toggle_selection", "Toggle", show=True),
        # Bulk operations for users with many lockfiles — Tab-and-Space
        # through 20 rows gets old fast.
        Binding("a", "select_all", "All", show=True),
        Binding("n", "select_none", "None", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        panel = Vertical(classes="wizard-panel")
        panel.border_title = "◆  Lockfiles"
        panel.border_subtitle = f"{len(self.wizard.state.discovered)} found"
        with panel:
            yield Static(
                "Use [b]Space[/] to toggle each lockfile, [b]a[/] to select all, "
                "[b]n[/] to select none, [b]Enter[/] when you're done.",
                classes="wizard-muted",
            )
            yield SelectionList[int](id="lockfile-list")
            yield Static("", id="discover-status", markup=True)
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next  ▸", id="next", variant="primary")

    def on_mount(self) -> None:
        sel = self.query_one("#lockfile-list", SelectionList)
        for idx, lf in enumerate(self.wizard.state.discovered):
            label = f"{lf.rel_path}  [#5E5E5E]({lf.ecosystem})[/]"
            sel.add_option((label, idx, True))  # default-selected
        sel.focus()

    def action_toggle_selection(self) -> None:
        """Custom toggle action — Textual's built-in `action_toggle` is generic."""
        self.query_one("#lockfile-list", SelectionList).action_select()
        self._clear_status()

    def action_select_all(self) -> None:
        self.query_one("#lockfile-list", SelectionList).select_all()
        self._clear_status()

    def action_select_none(self) -> None:
        self.query_one("#lockfile-list", SelectionList).deselect_all()
        self._clear_status()

    def action_submit(self) -> None:
        self._advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()

    def _advance(self) -> None:
        sel = self.query_one("#lockfile-list", SelectionList)
        indices = list(sel.selected)
        if not indices:
            # Replace the silent bell with a visible hint so the user
            # knows why nothing happened.
            status = self.query_one("#discover-status", Static)
            status.update(
                "[#F87171]Pick at least one lockfile to continue — "
                "press [b]Space[/] to toggle, [b]a[/] to select all.[/]"
            )
            self.app.bell()
            return
        self.wizard.state.selected = [self.wizard.state.discovered[i] for i in indices]
        from sbomify_action.cli.wizard.screens.authenticate import AuthenticateScreen

        self.wizard.push_screen(AuthenticateScreen())

    def _clear_status(self) -> None:
        try:
            self.query_one("#discover-status", Static).update("")
        except Exception:  # noqa: BLE001
            pass
