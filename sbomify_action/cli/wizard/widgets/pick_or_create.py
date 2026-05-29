"""``PickOrCreate`` — shared 'reuse-or-make-new' picker.

Bundles the three widgets the wizard uses to let a user either pick
an existing object or supply a new one:

  - an ``OptionList`` containing a "Create new …" sentinel row at the
    top followed by every existing item;
  - an ``Input`` for the new name, hidden whenever an existing row is
    highlighted (so it can't be mistaken for an editable label for the
    selected item);
  - the auto-toggle handler that drives the hide / show.

Used by both ``ProductScreen`` (one picker for the whole screen) and
``ComponentsScreen`` (one picker per lockfile). Keeps the two screens
keyboard-consistent — same interaction, same visual shape, same
hiding rules — and concentrates the pre-highlight + visibility logic
in one place.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Input, OptionList
from textual.widgets.option_list import Option

# Sentinel id used for the "Create new …" row at the top of every
# picker. Anything else is the actual item's id.
NEW_SENTINEL = "__new__"


class PickOrCreate(Vertical):
    """OptionList + Input with shared sentinel + auto-hide behaviour."""

    DEFAULT_CSS = """
    PickOrCreate {
        height: auto;
    }
    PickOrCreate > OptionList {
        height: auto;
        max-height: 10;
        margin: 0 0 1 0;
    }
    """

    def __init__(
        self,
        existing: list[tuple[str, str]],
        *,
        create_label: str,
        placeholder: str,
        default_new_value: str = "",
        pre_select_id: str | None = None,
        id: str,
    ) -> None:
        """
        Args:
            existing: ``(label, id)`` pairs for every existing item. Labels
                may contain Rich markup; ids must be plain strings.
            create_label: Markup shown on the sentinel "create new" row.
            placeholder: Placeholder text for the new-name Input.
            default_new_value: Initial value of the Input (typically a
                suggested name derived from context).
            pre_select_id: Id of an existing item to highlight on mount.
                When ``None`` (or no match), the sentinel row is
                highlighted and the Input shown.
            id: DOM id for the outer Vertical; the OptionList and Input
                get derived ids (``{id}-list``, ``{id}-input``).
        """
        super().__init__(id=id)
        self._existing = list(existing)
        self._create_label = create_label
        self._placeholder = placeholder
        self._default_new_value = default_new_value
        self._pre_select_id = pre_select_id

    @property
    def _list_id(self) -> str:
        return f"{self.id}-list"

    @property
    def _input_id(self) -> str:
        return f"{self.id}-input"

    def compose(self) -> ComposeResult:
        options: list[Option] = [Option(self._create_label, id=NEW_SENTINEL)]
        options.extend(Option(label, id=item_id) for label, item_id in self._existing)
        yield OptionList(*options, id=self._list_id)
        yield Input(
            value=self._default_new_value,
            placeholder=self._placeholder,
            id=self._input_id,
        )

    def on_mount(self) -> None:
        listing = self.query_one(f"#{self._list_id}", OptionList)
        highlight = 0
        if self._pre_select_id is not None:
            for idx, (_label, item_id) in enumerate(self._existing, start=1):
                if item_id == self._pre_select_id:
                    highlight = idx
                    break
        listing.highlighted = highlight
        # The on_option_list_option_highlighted handler will keep the
        # Input in sync as the user navigates; set it up correctly for
        # the initial state too.
        try:
            self.query_one(f"#{self._input_id}", Input).display = highlight == 0
        except Exception:  # noqa: BLE001
            pass

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        """Toggle the Input visibility when our OptionList moves."""
        # Only act on our own list, not a sibling picker bubbling up.
        if event.option_list.id != self._list_id:
            return
        try:
            input_widget = self.query_one(f"#{self._input_id}", Input)
        except Exception:  # noqa: BLE001
            return
        input_widget.display = event.option.id == NEW_SENTINEL

    # ------------------------------------------------------------------
    # accessors used by host screens

    @property
    def picked_id(self) -> str | None:
        """Id of the highlighted row, or None if nothing's highlighted."""
        listing = self.query_one(f"#{self._list_id}", OptionList)
        if listing.highlighted is None:
            return None
        option = listing.get_option_at_index(listing.highlighted)
        return option.id

    @property
    def new_value(self) -> str:
        """Whatever's in the new-name Input, stripped of surrounding whitespace."""
        return self.query_one(f"#{self._input_id}", Input).value.strip()

    @property
    def picked_label(self) -> str | None:
        """Label of the highlighted row, or None if nothing's highlighted.

        Returned as the option's prompt — callers that just want a
        human-readable name for what the user picked can use this
        without having to keep a separate ``id → name`` map.
        """
        listing = self.query_one(f"#{self._list_id}", OptionList)
        if listing.highlighted is None:
            return None
        option = listing.get_option_at_index(listing.highlighted)
        return str(option.prompt) if option.prompt is not None else None

    def focus_list(self) -> None:
        """Move keyboard focus to the OptionList — call from the host's on_mount."""
        try:
            self.query_one(f"#{self._list_id}", OptionList).focus()
        except Exception:  # noqa: BLE001
            pass
