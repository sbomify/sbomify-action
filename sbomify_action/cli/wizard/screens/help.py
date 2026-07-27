"""Help modal — global keybind cheat sheet.

Pushed by the ``?`` binding on ``WizardApp`` from any screen. ESC or
``?`` again closes it.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Container, Middle, Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

_HELP_BODY = (
    "[b]Navigation[/]\n"
    "  [#8A7DFF]Enter[/]       Advance to the next screen\n"
    "  [#8A7DFF]Escape[/]      Go back to the previous screen\n"
    "  [#8A7DFF]Tab[/]         Move focus to the next widget\n"
    "  [#8A7DFF]Shift+Tab[/]   Move focus to the previous widget\n"
    "  [#8A7DFF]Ctrl+C[/]      Quit the wizard (press twice within 3s to confirm)\n"
    "\n"
    "[b]Lists & selections[/]\n"
    "  [#8A7DFF]↑/↓[/]         Move highlight in OptionList / SelectionList\n"
    "  [#8A7DFF]Space[/]       Toggle a row (multi-select on Discover)\n"
    "  [#8A7DFF]a[/] / [#8A7DFF]n[/]       Select all / none on Discover\n"
    "\n"
    "[b]Flow[/]\n"
    "  01  Pick which lockfiles to track\n"
    "  02  Authenticate against sbomify\n"
    "  03  Pick a product\n"
    "  04  Reuse or create a component per lockfile\n"
    "  05  Configure (workflow shape)\n"
    "  06  Configure (SBOM content)\n"
    "  07  Review the plan (diff before commit)\n"
    "  08  Apply — write workflow + finalise components\n"
    "  09  Publish — generate & upload your first SBOMs (optional)\n"
    "\n"
    "[#5E5E5E]Press [b]?[/] or [b]Esc[/] to close this help.[/]"
)


class HelpScreen(ModalScreen[None]):
    """Floating keybind cheat sheet, pushed by the ``?`` shortcut."""

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    HelpScreen #help-card {
        background: #201B4C;
        border: thick #8A7DFF;
        padding: 1 2;
        width: 70;
        height: auto;
    }
    HelpScreen #help-title {
        color: #F4B57F;
        text-style: bold;
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss_self", "Close", show=True),
        Binding("question_mark", "dismiss_self", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Center(), Middle():
            card = Container(id="help-card")
            with card:
                yield Static("◆  sbomify wizard — keybinds", id="help-title")
                yield Vertical(Static(_HELP_BODY, markup=True))

    def action_dismiss_self(self) -> None:
        self.dismiss(None)
