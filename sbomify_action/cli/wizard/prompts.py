"""Styled prompt wrappers for the sbomify.json wizard."""

from collections.abc import Callable, Sequence

import questionary
from questionary import Choice, Style
from rich.panel import Panel

from sbomify_action.console import BRAND_COLORS, console


class GoBack(Exception):
    """Raised when user presses Escape to go back."""

    pass


# Custom style - minimal, no highlighting or background colors
WIZARD_STYLE = Style(
    [
        ("qmark", "noreverse"),
        ("question", "noreverse"),
        ("answer", "noreverse"),
        ("pointer", "noreverse"),
        ("highlighted", "noreverse"),
        ("selected", "noreverse"),
        ("separator", "noreverse"),
        ("instruction", "fg:#888888 noreverse"),
        ("text", "noreverse"),
        ("disabled", "fg:#666666 italic noreverse"),
        # Autocomplete menu styling
        ("completion-menu", "bg:default noreverse"),
        ("completion-menu.completion", "bg:default noreverse"),
        ("completion-menu.completion.current", "bg:default bold noreverse"),
        ("scrollbar.background", "bg:default"),
        ("scrollbar.button", "bg:default"),
    ]
)


def print_section_header(title: str, description: str | None = None) -> None:
    """Print a styled section header.

    Args:
        title: Section title
        description: Optional description text
    """
    content = f"[bold {BRAND_COLORS['blue']}]{title}[/]"
    if description:
        content += f"\n[dim]{description}[/]"

    # Add padding before and after for readability
    console.print("\n" * 2)
    console.print(
        Panel(
            content,
            border_style=BRAND_COLORS["purple"],
            padding=(0, 1),
        )
    )
    console.print("\n")


def ask_text(
    question: str,
    default: str = "",
    validate: Callable[[str], bool | str] | None = None,
    instruction: str | None = None,
    allow_back: bool = True,
) -> str:
    """Ask for text input.

    Args:
        question: The question to ask
        default: Default value (shown in prompt)
        validate: Optional validation function (return True or error message)
        instruction: Optional instruction text
        allow_back: If True, raises GoBack on Escape

    Returns:
        User's input or empty string if skipped

    Raises:
        GoBack: If user presses Escape and allow_back is True
    """
    result = questionary.text(
        question,
        default=default,
        validate=validate,
        instruction=instruction or "(Enter to skip, Esc to go back)",
        style=WIZARD_STYLE,
    ).ask()

    if result is None:
        if allow_back:
            raise GoBack()
        return ""
    return str(result)


def ask_select(
    question: str,
    choices: Sequence[str | Choice],
    default: str | None = None,
    instruction: str | None = None,
    allow_back: bool = False,
) -> str | None:
    """Ask user to select from a list.

    Args:
        question: The question to ask
        choices: List of choices (strings or Choice objects)
        default: Default selection
        instruction: Optional instruction text
        allow_back: If True, raises GoBack on Escape

    Returns:
        Selected value or None if cancelled

    Raises:
        GoBack: If user presses Escape and allow_back is True
    """
    result = questionary.select(
        question,
        choices=list(choices),
        default=default,
        instruction=instruction or "(arrows to move, Enter to select, Esc to go back)",
        style=WIZARD_STYLE,
    ).ask()

    if result is None and allow_back:
        raise GoBack()
    return str(result) if result is not None else None


def ask_confirm(question: str, default: bool = True, allow_back: bool = True) -> bool:
    """Ask a yes/no question.

    Args:
        question: The question to ask
        default: Default answer
        allow_back: If True, raises GoBack on Escape

    Returns:
        True for yes, False for no

    Raises:
        GoBack: If user presses Escape and allow_back is True
    """
    result = questionary.confirm(
        question,
        default=default,
        style=WIZARD_STYLE,
    ).ask()

    if result is None:
        if allow_back:
            raise GoBack()
        return default
    return bool(result)


def ask_autocomplete(
    question: str,
    choices: list[str],
    validate: Callable[[str], bool | str] | None = None,
    allow_back: bool = True,
) -> str:
    """Ask for text input with autocomplete suggestions.

    Args:
        question: The question to ask
        choices: List of autocomplete suggestions
        validate: Optional validation function
        allow_back: If True, raises GoBack on Escape

    Returns:
        User's input or empty string if skipped

    Raises:
        GoBack: If user presses Escape and allow_back is True
    """
    # Note: autocomplete doesn't support instruction parameter
    result = questionary.autocomplete(
        question,
        choices=choices,
        validate=validate,
        style=WIZARD_STYLE,
    ).ask()

    if result is None:
        if allow_back:
            raise GoBack()
        return ""
    return str(result)


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[success]{message}[/]")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[info]{message}[/]")
    console.print()  # Add padding after info messages


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[warning]{message}[/]")
