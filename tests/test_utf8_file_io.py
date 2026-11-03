"""Every text file the action reads or writes is opened as UTF-8.

Without an explicit ``encoding``, Python opens text files in the locale's
encoding. On a Windows machine with a non-UTF-8 code page (cp950, cp1252, ...)
reading an SBOM that holds any non-ASCII character then fails with
``'cp950' codec can't decode byte ...``, which the pipeline reports as an
invalid SBOM. SBOMs, lock files and manifests are UTF-8 whatever the host's
locale is, so every text-mode open has to say so.
"""

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parent.parent / "sbomify_action"

# Modules whose ``open`` is not the builtin text-file open.
_NOT_FILE_OPEN = {"os", "tarfile", "webbrowser", "zipfile", "gzip", "lzma", "bz2", "subprocess"}


def _is_binary_mode(call: ast.Call, mode_index: int) -> bool:
    mode = None
    if len(call.args) > mode_index:
        mode = call.args[mode_index]
    for kw in call.keywords:
        if kw.arg == "mode":
            mode = kw.value
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and "b" in mode.value


def _unencoded_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if any(kw.arg == "encoding" or kw.arg is None for kw in node.keywords):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "open":
            if not _is_binary_mode(node, 1):
                yield node
        elif isinstance(func, ast.Attribute) and func.attr in {"open", "read_text", "write_text"}:
            if isinstance(func.value, ast.Name) and func.value.id in _NOT_FILE_OPEN:
                continue
            if func.attr == "open" and _is_binary_mode(node, 0):
                continue
            if func.attr == "write_text" and len(node.args) >= 2:
                continue
            yield node


@pytest.mark.parametrize("path", sorted(PACKAGE.rglob("*.py")), ids=lambda p: str(p.relative_to(PACKAGE)))
def test_text_file_io_names_utf8(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders = [f"{path.relative_to(PACKAGE)}:{call.lineno}" for call in _unencoded_calls(tree)]
    assert not offenders, "text-mode file I/O without encoding='utf-8': " + ", ".join(offenders)
