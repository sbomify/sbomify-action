"""One tolerant entry point for parsing SPDX license expressions.

``license_expression`` documents ``ExpressionError`` as what an unparseable
expression raises, and every caller in this package was written to that:
each wraps ``parse`` in ``except ExpressionError`` and treats a failure as
"not a valid SPDX expression". Its parser leaks other exceptions out of the
``boolean.py`` it is built on, for input that tokenizes but cannot be
assembled into a tree::

    get_spdx_licensing().parse("MIT AND ()", validate=False)
    IndexError: list index out of range

    get_spdx_licensing().parse("( AND MIT", validate=False)
    AssertionError: Bad arguments: all arguments must be an Expression

Neither is an ``ExpressionError``, so both went straight through the guard
and ended the run -- from inside a sanitizer whose entire job is to repair a
document it already knows it cannot trust, and with a traceback naming
``boolean.py`` rather than the component or the licence string.

Parse through here instead. Any parser failure is one answer, ``None``, and
the license string is then "not valid SPDX" exactly as the callers intend.
The catch is deliberately broad: the input is an arbitrary string out of a
third-party SBOM, so the set of exceptions the parser can raise on it is not
something this package can enumerate and keep correct.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

from license_expression import Licensing, get_spdx_licensing

logger = logging.getLogger(__name__)


@functools.lru_cache(maxsize=1)
def spdx_licensing() -> Licensing:
    """The SPDX licensing instance, built once and shared.

    ``get_spdx_licensing`` builds an index of the whole SPDX symbol table, so
    the modules that need it share one rather than each holding a copy.
    """
    return get_spdx_licensing()


def parse_spdx_expression(expression: str) -> Any | None:
    """Parse ``expression``, or return ``None`` if it cannot be parsed.

    ``None`` means "this string is not an SPDX expression" -- the caller
    decides whether that demotes it to a name, a ``LicenseRef-*`` or a
    rejection.
    """
    try:
        return spdx_licensing().parse(expression, validate=False)
    except Exception:  # noqa: BLE001 - see the module docstring
        logger.debug("Could not parse license expression %r", expression, exc_info=True)
        return None


def unknown_spdx_keys(parsed: Any) -> set[str]:
    """The license keys in a parsed expression that are not on the SPDX list."""
    return {str(key) for key in spdx_licensing().unknown_license_keys(parsed)}


def is_known_spdx_expression(expression: str) -> bool:
    """True when ``expression`` parses and every key in it is a known SPDX id."""
    parsed = parse_spdx_expression(expression)
    if parsed is None:
        return False
    return not unknown_spdx_keys(parsed)
