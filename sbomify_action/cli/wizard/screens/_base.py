"""Shared screen scaffolding for the wizard.

``WizardScreen`` provides the consistent visual frame every screen
uses: a Textual ``Header``, a body region the subclass fills, and a
``Footer`` with keybind hints. Subclasses override
``compose_body`` and the ``step_index`` / ``step_title`` class vars.

The crumb at the top of every screen renders the wizard's progress
as a connected segmented track + a numbered position chip + the
current step title. Keeping it consistent across screens means users
always see where they are without needing to re-orient.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Callable, ClassVar

from textual import events
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, RadioSet, Static

if TYPE_CHECKING:
    from sbomify_action.cli.wizard.app import WizardApp


TOTAL_STEPS = 9

# HTTP status markers as ``_build_error`` emits them: ``prefix [NNN]`` at the
# end of a clause, or ``prefix [NNN] - detail`` when a detail follows. Anchored
# to that exact shape — the code must be a real HTTP status (1xx–5xx) AND be
# followed by `` - `` or the end of the string — so an embedded, quoted name
# like ``'Widget [123]'`` (the ``[123]`` is followed by ``'``, not `` - ``/end)
# is left untouched.
_STATUS_CODE_RE = re.compile(r"\s*\[[1-5]\d{2}\]\s*(?:-\s*|$)")


def strip_status_codes(message: str) -> str:
    """Remove HTTP status-code markers from an API error message.

    ``"Failed to create product 'X'. [403] - You have reached…"`` becomes
    ``"Failed to create product 'X'. You have reached…"``. Full error text
    (codes included) still lands in the debug log via the exception itself;
    this only cleans what the TUI renders. Only markers in the shape
    ``_build_error`` produces are stripped, so a bracketed number inside a
    product/component name isn't mangled.
    """
    return _STATUS_CODE_RE.sub(" ", message).strip()


def ellipsize(value: str, limit: int) -> str:
    """Clip ``value`` to ``limit`` cells, ending with a single ellipsis.

    Used for API-supplied names on the label/value screens (the Review plan
    summary in particular). Those layouts align a fixed-width label column
    against a value; letting a 70-character product name wrap re-flows the
    continuation to column 0 and breaks the alignment for every row below
    it. Truncating keeps the column intact — the full value is still on the
    Product / Components screen the user just came from.
    """
    if limit <= 1 or len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


# Responsive breakpoints (terminal cells).
#
# The screen body scrolls (``.wizard-scroll``) and the action row is pinned
# below it (``compose_actions``), so no breakpoint is ever load-bearing for
# *reachability* — Back/Next are on screen at every size, and content that
# doesn't fit scrolls instead of being clipped away. That makes these bounds
# purely about comfort:
#
#   * Below MIN_* the frame itself (header + crumb + one usable body row +
#     actions + footer) stops making sense, so we swap the body for a
#     "resize your terminal" prompt (k9s / lazygit do the same). Kept
#     deliberately low so the wizard still runs in an IDE's integrated
#     terminal panel, which is typically wide but only 10–20 rows tall.
#   * Below ROOMY_* we shed the comfortable layout: the explanatory
#     rationale prose is dropped and paddings tighten, via ``-compact``.
#   * The welcome mascot (ART_*) and the "what we'll do" preview
#     (PREVIEW_*) each have their own bound, because they're the two
#     tallest optional elements and they fit in very different terminals.
#     They also *compete*: PREVIEW_WITH_ART_HEIGHT is the bound that
#     applies once the mascot is already taking 22 rows, so a
#     medium-tall terminal shows one or the other rather than
#     overflowing with both.
MIN_WIDTH = 60
MIN_HEIGHT = 12
ART_WIDTH = 100
ART_HEIGHT = 44
PREVIEW_HEIGHT = 30
PREVIEW_WITH_ART_HEIGHT = 56
ROOMY_WIDTH = 100
ROOMY_HEIGHT = 63


class WizardScroll(VerticalScroll):
    """The screen body's scroll region.

    Focusable only while it actually has something to scroll. Textual makes
    every scrollable container focusable so keyboard users can pan text that
    isn't otherwise reachable — which the wizard needs on the screens whose
    overflow is pure prose (Done's OIDC instructions, Welcome's panels).

    But an unconditionally-focusable container is a tab stop with no visible
    effect whenever the content already fits, which is most screens most of
    the time: Tab appears to do nothing, then works again on the next press.
    Gating on ``show_vertical_scrollbar`` keeps the stop exactly when it does
    something and the scrollbar is on screen to show it.
    """

    def allow_focus(self) -> bool:
        return self.show_vertical_scrollbar

    def on_mount(self) -> None:
        # Open at the top of the content, always. A screen whose body
        # overflows can otherwise land mid-way through it: Review's diff
        # panel takes ``1fr`` and, once its min-height pushes the body past
        # the viewport, the initial layout settled at the *bottom* — so the
        # confirmation screen opened with the plan summary (product,
        # release strategy, credentials) already scrolled off the top, which
        # is precisely the part the user is there to check.
        #
        # Deferred: the offending scroll is applied during the screen's own
        # mount/layout pass, so resetting synchronously here would be undone.
        self.call_after_refresh(self.scroll_home, animate=False)


class WizardScreen(Screen[None]):
    """Common header + body + footer frame for every wizard phase."""

    step_index: ClassVar[int] = 0
    step_title: ClassVar[str] = ""

    # Plain instance attribute so screens that compute the subtitle from
    # constructor args can assign in __init__ without mypy complaints.
    step_subtitle: str = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical(classes="wizard-body"):
            yield Static(self._crumb_markup(), classes="wizard-step-crumb")
            if self.step_subtitle:
                yield Static(self.step_subtitle, classes="wizard-subtitle")
            # The body scrolls; the action row below it does not. Panels can
            # therefore be as tall as they need to be (a monorepo's worth of
            # component cards, the full attestation rationale) without ever
            # pushing Back/Next past the bottom of the terminal.
            with WizardScroll(classes="wizard-scroll"):
                yield from self.compose_body()
            yield from self.compose_actions()
        # Shown (and the body hidden) only when the terminal is below the
        # minimum supported size — see ``_apply_responsive``. The text is
        # filled in on resize so it can quote the live dimensions.
        yield Static("", id="too-small")
        yield Footer()

    def on_resize(self, event: events.Resize) -> None:
        self._apply_responsive(event.size.width, event.size.height)

    def _apply_responsive(self, width: int, height: int) -> None:
        """Toggle responsive classes from the current terminal size.

        Three independent toggles (CSS in ``styles.tcss`` keys off them):

        * ``-tiny`` — below the supported minimum: swap the whole body for
          a resize prompt.
        * ``-compact`` — below the roomy bound: drop the "what we'll do"
          preview and tighten padding so the content still fits.
        * ``-no-art`` — below the art bound: hide the welcome mascot. Kept
          separate from ``-compact`` because the art fits in many terminals
          that are still too short for the full comfortable layout, so a
          "compact but show the art" middle tier is the common case.
        * ``-no-preview`` — below the preview bound: hide the welcome "what
          we'll do" list. Also its own bound (the list is short text that
          fits well below the roomy layout) so we keep showing it rather
          than leaving the screen half-empty on a medium-tall terminal.
          The bound is raised when the mascot is already on screen, since
          the two compete for the same rows.
        """
        too_small = width < MIN_WIDTH or height < MIN_HEIGHT
        roomy = width >= ROOMY_WIDTH and height >= ROOMY_HEIGHT
        show_art = width >= ART_WIDTH and height >= ART_HEIGHT
        show_preview = height >= (PREVIEW_WITH_ART_HEIGHT if show_art else PREVIEW_HEIGHT)
        self.set_class(too_small, "-tiny")
        self.set_class(not too_small and not roomy, "-compact")
        self.set_class(not too_small and not show_art, "-no-art")
        self.set_class(not too_small and not show_preview, "-no-preview")
        if too_small:
            try:
                self.query_one("#too-small", Static).update(self._too_small_markup(width, height))
            except NoMatches:
                # The guard node isn't mounted yet (resize fired mid-compose);
                # the next resize repaints. Narrow to NoMatches so a real
                # rendering/markup error still surfaces instead of being swallowed.
                pass

    @staticmethod
    def _too_small_markup(width: int, height: int) -> str:
        """Centered 'please resize' notice quoting the live terminal size."""
        return (
            "[b #F4B57F]⚠  Terminal too small[/]\n\n"
            f"[#CBCCCE]Current size[/]  [b]{width}×{height}[/]\n"
            f"[#CBCCCE]Minimum size[/]  [b]{MIN_WIDTH}×{MIN_HEIGHT}[/]\n\n"
            "[#8A7DFF]Resize this window to continue.[/]"
        )

    def compose_body(self) -> ComposeResult:
        """Override to yield body widgets (panels, inputs, tables, …).

        Everything yielded here lands inside the scrolling region. Anything
        that must stay visible regardless of content height — the Back/Next
        row, a validation status line — belongs in ``compose_actions``.
        """
        return iter(())

    def compose_actions(self) -> ComposeResult:
        """Override to yield the pinned action row (and any status line
        that must stay visible with it).

        Rendered below the scrolling body and never scrolls, so the
        primary action is on screen at every terminal size.
        """
        return iter(())

    def route_enter(self, forward: Callable[[], None]) -> None:
        """Route a screen-level Enter to the right action based on focus.

        Every wizard screen declares ``Binding("enter", "submit", priority=True)``
        so an ``Input`` or ``SelectionList`` can't swallow Enter and strand
        the user (eg the password Input on Authenticate). But that same
        priority binding hijacks Enter from focused widgets that DO want
        to own it:

        - Focused non-primary ``Button`` (Back, Cancel) → press it
          instead of advancing forward.
        - Focused ``RadioSet`` → commit the highlighted radio. Without
          this, Enter inside a RadioSet skips past the radio selection
          entirely and jumps to the next screen (see the profile-picker
          regression: pressing Enter on the augmentation RadioSet to
          select 'Use a contact profile' advanced the screen before the
          radio could change).
        - Anything else → run ``forward`` (the screen's advance action).

        Primary buttons fall through too, so Enter on a focused primary
        button still does what the same screen action does anyway.
        """
        focused = self.focused
        if isinstance(focused, Button) and focused.variant != "primary":
            focused.press()
            return
        if isinstance(focused, RadioSet):
            action = getattr(focused, "action_toggle_button", None)
            if callable(action):
                action()
                return
        forward()

    def _crumb_markup(self) -> str:
        """Numbered position chip + connected segment track + step title.

        Visually:

            01 / 08  │  ●━━━○━━━○━━━○━━━○━━━○━━━○━━━○  │  Welcome
            03 / 08  │  ●━━━●━━━●━━━○━━━○━━━○━━━○━━━○  │  Authenticate

        - Filled purple dots are completed steps.
        - The current dot is bolded so it stands out from past steps.
        - Connector glyphs darken between unfinished steps to hint at
          progress direction.
        """
        chips: list[str] = []
        for i in range(1, TOTAL_STEPS + 1):
            if i < self.step_index:
                chips.append("[#8A7DFF]●[/]")
            elif i == self.step_index:
                chips.append("[b #8A7DFF]●[/]")
            else:
                chips.append("[#37306B]○[/]")
        connector_done = "[#8A7DFF]━━[/]"
        connector_pending = "[#37306B]━━[/]"
        track_parts: list[str] = []
        for i, chip in enumerate(chips, start=1):
            track_parts.append(chip)
            if i < TOTAL_STEPS:
                track_parts.append(connector_done if i < self.step_index else connector_pending)
        track = "".join(track_parts)
        position = f"[b #8A7DFF]{self.step_index:02d}[/][#5E5E5E] / {TOTAL_STEPS:02d}[/]"
        divider = "[#37306B]│[/]"
        return f"  {position}  {divider}  {track}  {divider}  [b]{self.step_title}[/]"

    @property
    def wizard(self) -> "WizardApp":
        """Typed accessor for the app — avoids cast boilerplate at call sites."""
        from sbomify_action.cli.wizard.app import WizardApp

        app = self.app
        assert isinstance(app, WizardApp)
        return app
