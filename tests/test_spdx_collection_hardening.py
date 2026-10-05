"""A malformed SPDX collection must not end the run.

The enrichment and serialization passes read the document the user supplied
*before* the validator gets to it, so ``packages``, ``files``, ``snippets``
and ``@graph`` are whatever the generator wrote there. ``value or []`` covers
only an explicit ``null``; a truthy non-array is still iterated -- character
by character, for a string -- and a scalar entry still raises
``AttributeError`` on the first ``entry.get(...)``, before the validator can
report which key was wrong.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sbomify_action._dependency_expansion.enricher import _count_sbom_packages
from sbomify_action._hash_enrichment.enricher import HashEnricher
from sbomify_action._spdx_collections import spdx_object_list, spdx_objects
from sbomify_action.serialization import sanitize_spdx_json_file

# The collection shapes a generator has actually written where an
# array-of-objects belongs.
MALFORMED_COLLECTIONS: list[Any] = [
    None,
    "SPDXRef-Package-foo",
    {"SPDXID": "SPDXRef-Package-foo"},
    42,
    True,
    ["SPDXRef-Package-foo"],
    [None],
    [["SPDXRef-Package-foo"]],
    [{"name": "ok", "versionInfo": "1.0"}, "stray", None, 7],
]


@pytest.mark.parametrize("collection", MALFORMED_COLLECTIONS)
def test_spdx_objects_yields_only_objects(collection: Any) -> None:
    assert all(isinstance(entry, dict) for entry in spdx_objects(collection))


@pytest.mark.parametrize("collection", MALFORMED_COLLECTIONS)
def test_spdx_object_list_is_an_appendable_list(collection: Any) -> None:
    entries = spdx_object_list(collection)
    assert isinstance(entries, list)
    assert all(isinstance(entry, dict) for entry in entries)
    entries.append({"SPDXID": "SPDXRef-Package-new"})


def test_spdx_objects_keeps_the_valid_entries_of_a_mixed_array() -> None:
    kept = spdx_object_list([{"name": "a"}, "stray", {"name": "b"}, None])
    assert kept == [{"name": "a"}, {"name": "b"}]


def test_spdx_objects_does_not_walk_a_string_by_character() -> None:
    # "abc" or [] is truthy, and iterating it yields "a", "b", "c".
    assert list(spdx_objects("abc")) == []


@pytest.mark.parametrize("collection", MALFORMED_COLLECTIONS)
def test_package_count_survives_a_malformed_collection(collection: Any) -> None:
    count = _count_sbom_packages({"spdxVersion": "SPDX-2.3", "packages": collection})
    assert isinstance(count, int)
    assert count >= 0


@pytest.mark.parametrize("collection", MALFORMED_COLLECTIONS)
def test_enum_fixup_survives_a_malformed_collection(collection: Any, tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.spdx.json"
    sbom.write_text(
        json.dumps({"spdxVersion": "SPDX-2.3", "name": "doc", "packages": collection}),
        encoding="utf-8",
    )
    assert sanitize_spdx_json_file(str(sbom)) >= 0


def test_enum_fixup_still_fixes_the_valid_entries_of_a_mixed_array(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.spdx.json"
    sbom.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "name": "doc",
                "packages": [
                    "stray",
                    {"SPDXID": "SPDXRef-a", "name": "a", "primaryPackagePurpose": "OPERATING_SYSTEM"},
                ],
            }
        ),
        encoding="utf-8",
    )
    # A stray entry ahead of a fixable one must not hide it.
    sanitize_spdx_json_file(str(sbom))
    purposes = [
        p.get("primaryPackagePurpose") for p in json.loads(sbom.read_text()).get("packages") if isinstance(p, dict)
    ]
    assert purposes == ["OPERATING-SYSTEM"]


@pytest.mark.parametrize("collection", MALFORMED_COLLECTIONS)
def test_hash_enrichment_survives_a_malformed_collection(collection: Any, tmp_path: Path) -> None:
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text(
        '[[package]]\nname = "ok"\nversion = "1.0"\n'
        '[[package.wheels]]\nurl = "https://example.com/ok-1.0-py3-none-any.whl"\n'
        'hash = "sha256:' + "0" * 64 + '"\n',
        encoding="utf-8",
    )
    spdx_data = {"spdxVersion": "SPDX-2.3", "name": "doc", "packages": collection}
    stats = HashEnricher().enrich_spdx(spdx_data, lockfile)
    assert stats["sbom_components"] >= 0
