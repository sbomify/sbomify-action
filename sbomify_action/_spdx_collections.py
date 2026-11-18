"""Reading the array-of-objects collections of a not-yet-valid SPDX document.

``packages``, ``files``, ``snippets`` and ``@graph`` are arrays of objects in
a conforming document. The enrichment and serialization passes run *before*
the validator does, on whatever JSON the user handed us, so none of that is
guaranteed here: a generator that answers ``"packages": null``, one object
instead of an array, or an array with a stray string in it is a bad document
to report, not a reason to end the run.

``value or []`` only covers the ``null`` case. A truthy non-list is still
iterated -- over its characters, for a string -- and a scalar entry still
raises ``AttributeError`` on the first ``entry.get(...)``, before the
validator can say which key was wrong.
"""

from collections.abc import Iterator
from typing import Any

__all__ = ["spdx_objects", "spdx_object_list"]


def spdx_objects(value: Any) -> Iterator[dict[str, Any]]:
    """Yield the object entries of an SPDX collection, and nothing else.

    A non-list ``value`` yields nothing; non-object entries are skipped.
    Use this to read a collection. Use :func:`spdx_object_list` when the
    caller mutates the collection and writes it back.
    """
    if not isinstance(value, list):
        return
    for entry in value:
        if isinstance(entry, dict):
            yield entry


def spdx_object_list(value: Any) -> list[dict[str, Any]]:
    """The object entries of an SPDX collection, as a new list.

    The result is safe to append to and assign back over the original key;
    doing so drops the entries that were not objects, which is the only
    reading of them that lets the document continue to a validator.
    """
    return list(spdx_objects(value))
