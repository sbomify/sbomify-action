"""Paged-form scaffolding for the wizard's long data-entry screens.

The wizard is a fit-to-viewport TUI — nothing scrolls — but a couple of
screens collect more fields than fit on an 80×24 terminal (the contact
profile form, the sbomify.json form). Rather than scroll them, we split
them into a handful of fit-to-viewport *pages*: all the panels stay
mounted (so the inputs keep their values when you move between pages),
but only the current page is displayed.

A subclass supplies:

* ``PAGE_TITLES`` — one title per page (drives the "Step n of N" header);
* ``compose_page(index)`` — yields that page's panels;
* ``save()`` — called when the user presses Next/Save on the last page.

The base renders the page indicator, the mounted-but-hidden page
containers, a shared status line, and the Back / Next button row, and
wires up the navigation:

* Next advances a page, or calls ``save()`` on the last page.
* Back steps back a page, or pops the screen from the first page (so
  Back / Escape from page 1 returns to whoever pushed the form).
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen


class PagedFormScreen(WizardScreen):
    """A ``WizardScreen`` whose body is a sequence of fit-to-viewport pages."""

    # One entry per page; subclasses override. ``compose_page`` is called
    # once per index in range(len(PAGE_TITLES)).
    PAGE_TITLES: ClassVar[list[str]] = []

    BINDINGS = [
        # Enter advances / saves; Escape steps back (or pops from page 1).
        # priority=True so a focused Input can't swallow them — navigation
        # is routed through ``route_enter`` so a focused Back button still
        # acts as Back. (Mirrors the other wizard screens.) The footer hint
        # is the page-agnostic "Continue" because Enter means Next on every
        # page but the last and Save on the last — the primary button itself
        # carries the precise "Next ▸" / "Save ▸" label.
        Binding("enter", "submit", "Continue", show=True, priority=True),
        Binding("escape", "back", "Back", show=True, priority=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        # Fail fast on a subclass that forgot PAGE_TITLES — otherwise the
        # indicator reads "Step 1 of 0" and the navigation math treats page 0
        # as the last page, silently breaking the form.
        if not self.PAGE_TITLES:
            raise ValueError(f"{type(self).__name__} must define a non-empty PAGE_TITLES (one entry per page).")
        self._page = 0

    # -- subclass hooks ------------------------------------------------

    def compose_page(self, index: int) -> ComposeResult:
        """Yield the panels for page ``index``. Override in subclasses."""
        return iter(())

    def save(self) -> None:
        """Commit the form. Called on Next/Save from the last page."""

    # -- composition ---------------------------------------------------

    def compose_body(self) -> ComposeResult:
        yield Static(
            self._indicator_markup(),
            id="form-page-indicator",
            classes="wizard-page-indicator",
        )
        for index in range(self._page_count):
            page = Vertical(classes="form-page", id=f"form-page-{index}")
            # Only the first page is visible on mount; the rest stay
            # mounted-but-hidden so their inputs preserve values.
            if index != 0:
                page.display = False
            with page:
                yield from self.compose_page(index)
        yield Static("", id="form-status", markup=True)
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="form-back")
            yield Button(self._next_label(), id="form-next", variant="primary")

    # -- navigation ----------------------------------------------------

    @property
    def _page_count(self) -> int:
        return len(self.PAGE_TITLES)

    def _is_last_page(self) -> bool:
        return self._page >= self._page_count - 1

    def _next_label(self) -> str:
        return "Save  ▸" if self._is_last_page() else "Next  ▸"

    def _indicator_markup(self) -> str:
        title = self.PAGE_TITLES[self._page] if self.PAGE_TITLES else ""
        return f"[#8A7DFF]Step {self._page + 1} of {self._page_count}[/]  [#37306B]│[/]  [b]{title}[/]"

    def action_submit(self) -> None:
        self.route_enter(self._advance)

    def action_back(self) -> None:
        if self._page == 0:
            self.app.pop_screen()
        else:
            self._show_page(self._page - 1)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "form-next":
            self._advance()
        elif event.button.id == "form-back":
            self.action_back()

    def _advance(self) -> None:
        if self._is_last_page():
            self.save()
        else:
            self._show_page(self._page + 1)

    def _show_page(self, index: int) -> None:
        index = max(0, min(index, self._page_count - 1))
        self._page = index
        for i in range(self._page_count):
            self.query_one(f"#form-page-{i}").display = i == index
        self.query_one("#form-page-indicator", Static).update(self._indicator_markup())
        self.query_one("#form-next", Button).label = self._next_label()
        self._set_status("")
        self._focus_first(index)

    def _focus_first(self, index: int) -> None:
        """Move focus to the first interactive control on the given page,
        in DOM order — a page may lead with a RadioSet (lifecycle) rather
        than an Input."""
        page = self.query_one(f"#form-page-{index}")
        for widget in page.query("Input, RadioSet"):
            widget.focus()
            return

    # -- helpers for subclasses ---------------------------------------

    def _set_status(self, markup: str) -> None:
        self.query_one("#form-status", Static).update(markup)

    @property
    def next_button(self) -> Button:
        """The primary Next/Save button — subclasses disable it mid-save."""
        return self.query_one("#form-next", Button)

    def _goto_page(self, index: int) -> None:
        """Public-ish jump used by ``save()`` to surface a field error on
        the page that owns the offending input."""
        if index != self._page:
            self._show_page(index)
