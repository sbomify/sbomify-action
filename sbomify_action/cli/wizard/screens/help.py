"""Help modal — global keybind cheat sheet.

Pushed by the ``?`` binding on ``WizardApp`` from any screen. ESC or
``?`` again closes it.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

_HELP_BODY = (
    "[b]Navigation[/]\n"
    "  [#8A7DFF]Enter[/]       Advance to the next screen\n"
    "  [#8A7DFF]Escape[/]      Go back to the previous screen\n"
    "  [#8A7DFF]Tab[/]         Move focus to the next widget\n"
    "  [#8A7DFF]Shift+Tab[/]   Move focus to the previous widget\n"
    "  [#8A7DFF]Ctrl+C[/]      Quit (press twice within 3s to confirm)\n"
    "  [#8A7DFF]? / F1[/]      This help (use F1 while typing in a text field)\n"
    "\n"
    "[b]Lists & selections[/]\n"
    "  [#8A7DFF]↑/↓[/]         Move highlight in OptionList / SelectionList\n"
    "  [#8A7DFF]Space[/]       Toggle a row (multi-select on Discover)\n"
    "  [#8A7DFF]a[/] / [#8A7DFF]n[/]       Select all / none on Discover\n"
    "\n"
    "[b]Flow[/]\n"
    "  01  Welcome\n"
    "  02  Pick which lockfiles to track\n"
    "  03  Authenticate against sbomify\n"
    "  04  Pick a product\n"
    "  05  Reuse or create a component per lockfile\n"
    "  06  Configure (workflow shape)\n"
    "  07  Configure (SBOM content)\n"
    "  08  Review the plan (diff before commit)\n"
    "  09  Apply — write workflow + finalise components"
)

# Pinned below the scrolling body so the way *out* of the help sheet is
# never the thing that scrolled off. It used to live at the end of the
# body text, which meant that on an 80x24 terminal — the default nearly
# everywhere — the card was cut off around step 04 and the only
# instruction for closing it was invisible.
_HELP_DISMISS = "[#5E5E5E]Press [b]?[/] or [b]Esc[/] to close this help.[/]"


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
        /* Shrink to fit a narrow terminal instead of overflowing it. */
        width: 70;
        max-width: 100%;
        /* Take the terminal's height, capped at what the sheet actually
         * needs. NOT ``height: auto``: an auto card sized to its content
         * renders taller than a short terminal and the bottom — including
         * the only instruction for closing the sheet — is cut off. */
        height: 100%;
        max-height: 30;
    }
    HelpScreen #help-title {
        color: #F4B57F;
        text-style: bold;
        margin-bottom: 1;
    }
    /* The cheat sheet scrolls; the title above and the dismiss hint below
     * are pinned, so the way out is always visible. */
    HelpScreen #help-body {
        height: 1fr;
        scrollbar-size-vertical: 1;
        scrollbar-background: #201B4C;
        scrollbar-color: #37306B;
        scrollbar-color-hover: #8A7DFF;
        scrollbar-color-active: #8A7DFF;
    }
    HelpScreen #help-dismiss {
        height: auto;
        margin-top: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss_self", "Close", show=True),
        Binding("question_mark", "dismiss_self", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        # ``align: center middle`` on the screen does the centering; the old
        # Center/Middle wrappers fought the card's percentage height.
        with Container(id="help-card"):
            yield Static("◆  sbomify wizard — keybinds", id="help-title")
            with VerticalScroll(id="help-body"):
                yield Static(_HELP_BODY, markup=True)
            yield Static(_HELP_DISMISS, id="help-dismiss", markup=True)

    def action_dismiss_self(self) -> None:
        self.dismiss(None)
