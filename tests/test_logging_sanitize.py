"""Log output must not carry terminal escapes, Rich markup or workflow commands from untrusted text."""

import io
import logging

import pytest
from rich.console import Console
from rich.logging import RichHandler

from sbomify_action.logging_config import ESCAPE_RE, SanitizingFilter, logger, sanitize_log_text
from sbomify_action.submodule import _pick_version_tag


def test_strips_escape_sequences_and_control_characters() -> None:
    text = "remote: \x1b]8;;https://evil.example\x1b\\click\x1b]8;;\x1b\\ \x1b[31mred\x1b[0m\rover\x9b\x1bM"
    assert sanitize_log_text(text) == "remote: click redover"


def test_keeps_tab_and_newline() -> None:
    assert sanitize_log_text("a\tb\nc") == "a\tb\nc"


@pytest.mark.parametrize("line", ["::add-mask::secret", "  ::error::spoofed", "::stop-commands::token"])
def test_defuses_workflow_commands_on_any_line(line: str) -> None:
    clean = sanitize_log_text(f"[git] error: first line\n{line}")
    for out_line in clean.splitlines():
        assert not out_line.lstrip().startswith("::")
    assert clean.splitlines()[1].replace("\u200b", "") == line


def test_leaves_ordinary_double_colons_alone() -> None:
    assert sanitize_log_text("ruff::check failed at a::b") == "ruff::check failed at a::b"


def test_filter_rewrites_formatted_message() -> None:
    record = logging.LogRecord(
        "t", logging.ERROR, __file__, 1, "[git] error: %s", ("\x1b]0;title\x07x\n::warning::y",), None
    )
    assert SanitizingFilter().filter(record) is True
    assert record.getMessage() == "[git] error: x\n:\u200b:warning::y"


def test_filter_leaves_clean_records_untouched() -> None:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "pinned at %s", ("v1.2.3",), None)
    SanitizingFilter().filter(record)
    assert record.msg == "pinned at %s"
    assert record.args == ("v1.2.3",)


def test_action_handler_does_not_render_markup_from_messages() -> None:
    handlers = [h for h in logger.handlers if isinstance(h, RichHandler)]
    assert handlers, "the action logger should use a RichHandler outside structured mode"
    handler = handlers[0]
    assert any(isinstance(f, SanitizingFilter) for f in handler.filters)

    buffer = io.StringIO()
    original = handler.console
    handler.console = Console(file=buffer, force_terminal=True, width=200)
    try:
        logger.error("[git] error: remote: [link=https://evil.example]sign in[/link] [bold]x[/bold]")
    finally:
        handler.console = original

    output = buffer.getvalue()
    assert "\x1b]8;" not in output
    assert "[link=https://evil.example]sign in[/link]" in ESCAPE_RE.sub("", output)


def test_version_tags_reject_escape_and_markup_characters() -> None:
    hostile = [
        "v9\x1bM\x1bc",
        "v1.0\x1b]8;;https://evil.example\x1b\\",
        "v1[link=https://evil.example]",
        "v1 2",
        "1.0\n::add-mask::x",
    ]
    assert _pick_version_tag(hostile) is None
    assert _pick_version_tag(hostile + ["v1.2.3-rc.1+build_7"]) == "v1.2.3-rc.1+build_7"
