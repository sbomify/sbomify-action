"""Radio button whose inner glyph reflects its on/off state.

Textual's stock ``RadioButton`` always renders ``▐●▌`` regardless of
selection state — the on/off distinction is purely a CSS style
(white+bold when selected, muted otherwise). That works in a richly
colored TTY but breaks in two practical cases:

  - Users with limited contrast / color vision can't tell which radio
    is active.
  - Copy/pasting a wizard screen into chat or a bug report strips
    color formatting, leaving three identical ``▐●▌`` rows that
    look like a multi-select bug rather than a single-choice radio.

``StatefulRadioButton`` overrides the inner glyph to ``●`` only when
selected; unselected radios render with ``○``. The visual difference
is then encoded in the character itself, not just the color.
"""

from __future__ import annotations

from textual.content import Content
from textual.style import Style
from textual.widgets import RadioButton


class StatefulRadioButton(RadioButton):
    """RadioButton with state-aware inner glyph (``○`` off, ``●`` on)."""

    BUTTON_INNER_OFF = "○"  # ○ — empty circle
    BUTTON_INNER_ON = "●"  # ● — filled circle

    @property
    def _button(self) -> Content:
        """Render ``▐●▌`` when selected, ``▐○▌`` when not.

        Mirrors the parent's ``_button`` shape (left + inner + right
        glyphs styled per ``toggle--button`` / its side variant) but
        swaps the inner character based on ``self.value`` so the
        selection state is visually unambiguous even with color
        information stripped.
        """
        button_style = self.get_visual_style("toggle--button")
        side_style = Style(
            foreground=button_style.background,
            background=self.background_colors[1],
        )
        inner = self.BUTTON_INNER_ON if self.value else self.BUTTON_INNER_OFF
        return Content.assemble(
            (self.BUTTON_LEFT, side_style),
            (inner, button_style),
            (self.BUTTON_RIGHT, side_style),
        )
