"""Tests for the lockfile hash parsers.

These feed the hash-enrichment step, which stamps `hashes` onto SBOM
components. A parser that silently returns nothing degrades the SBOM without
failing anything, so the assertions here check the decoded hash value rather
than merely that some object came back.

Hashes in the fixtures are computed, not invented, so every assertion is a
real round trip: SRI base64 in, hex out.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from sbomify_action._hash_enrichment.models import (
    HashAlgorithm,
    PackageHash,
    normalize_package_name,
)
from sbomify_action._hash_enrichment.parsers.package_lock import PackageLockParser
from sbomify_action._hash_enrichment.parsers.pnpm_lock import PnpmLockParser
from sbomify_action._hash_enrichment.parsers.poetry_lock import PoetryLockParser
from sbomify_action._hash_enrichment.parsers.yarn_lock import YarnLockParser


def _sri(payload: bytes, algorithm: str = "sha512") -> str:
    """An SRI string of the shape npm/yarn/pnpm actually write."""
    digest = hashlib.new(algorithm, payload).digest()
    return f"{algorithm}-{base64.b64encode(digest).decode()}"


def _hex(payload: bytes, algorithm: str = "sha512") -> str:
    return hashlib.new(algorithm, payload).hexdigest()


def _by_name(hashes: list[PackageHash]) -> dict[str, PackageHash]:
    return {h.name: h for h in hashes}


class TestPackageLockParser:
    """npm's package-lock.json, v1 through v3."""

    def test_supports_only_its_own_file(self):
        parser = PackageLockParser()
        assert parser.supports("package-lock.json") is True
        assert parser.supports("yarn.lock") is False

    def test_v3_packages_including_a_scoped_name(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "root", "version": "1.0.0"},
                        "node_modules/lodash": {"version": "4.17.21", "integrity": _sri(b"lodash")},
                        "node_modules/@babel/core": {"version": "7.24.0", "integrity": _sri(b"babel-core")},
                    },
                }
            )
        )

        found = _by_name(PackageLockParser().parse(lock))

        assert set(found) == {"lodash", "@babel/core"}
        assert found["lodash"].version == "4.17.21"
        assert found["lodash"].value == _hex(b"lodash")
        assert found["lodash"].algorithm is HashAlgorithm.SHA512
        assert found["lodash"].artifact_type == "tarball"
        assert found["@babel/core"].value == _hex(b"babel-core")

    def test_the_root_package_is_not_a_dependency(self, tmp_path: Path):
        """The "" entry describes the project itself and has no integrity."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps({"packages": {"": {"name": "root", "version": "1.0.0", "integrity": _sri(b"root")}}})
        )
        assert PackageLockParser().parse(lock) == []

    def test_a_nested_node_modules_path_yields_the_innermost_name(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "packages": {
                        "node_modules/gulp/node_modules/glob": {
                            "version": "7.2.3",
                            "integrity": _sri(b"glob"),
                        }
                    }
                }
            )
        )
        (found,) = PackageLockParser().parse(lock)
        assert found.name == "glob"
        assert found.value == _hex(b"glob")

    def test_entries_without_integrity_are_skipped(self, tmp_path: Path):
        """Link and workspace entries carry a version but no integrity."""
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "packages": {
                        "node_modules/linked": {"version": "1.0.0", "link": True},
                        "node_modules/real": {"version": "2.0.0", "integrity": _sri(b"real")},
                    }
                }
            )
        )
        (found,) = PackageLockParser().parse(lock)
        assert found.name == "real"

    def test_a_path_outside_node_modules_is_ignored(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps({"packages": {"packages/my-workspace": {"version": "1.0.0", "integrity": _sri(b"ws")}}})
        )
        assert PackageLockParser().parse(lock) == []

    def test_the_same_package_at_two_paths_is_reported_once(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "packages": {
                        "node_modules/ms": {"version": "2.1.3", "integrity": _sri(b"ms")},
                        "node_modules/debug/node_modules/ms": {
                            "version": "2.1.3",
                            "integrity": _sri(b"ms"),
                        },
                    }
                }
            )
        )
        assert len(PackageLockParser().parse(lock)) == 1

    def test_v1_dependencies_are_walked_recursively(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 1,
                    "dependencies": {
                        "express": {
                            "version": "4.19.2",
                            "integrity": _sri(b"express"),
                            "dependencies": {
                                "cookie": {"version": "0.6.0", "integrity": _sri(b"cookie")},
                            },
                        }
                    },
                }
            )
        )

        found = _by_name(PackageLockParser().parse(lock))

        assert set(found) == {"express", "cookie"}
        assert found["cookie"].value == _hex(b"cookie")

    def test_v1_deduplicates_across_nesting_levels(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "dependencies": {
                        "a": {
                            "version": "1.0.0",
                            "integrity": _sri(b"a"),
                            "dependencies": {"ms": {"version": "2.1.3", "integrity": _sri(b"ms")}},
                        },
                        "b": {
                            "version": "1.0.0",
                            "integrity": _sri(b"b"),
                            "dependencies": {"ms": {"version": "2.1.3", "integrity": _sri(b"ms")}},
                        },
                    }
                }
            )
        )
        assert sorted(h.name for h in PackageLockParser().parse(lock)) == ["a", "b", "ms"]

    def test_non_dict_entries_do_not_raise(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({"packages": {"node_modules/weird": "not-an-object"}}))
        assert PackageLockParser().parse(lock) == []


class TestYarnLockParser:
    """yarn.lock, both the v1 text format and the v2+ YAML one."""

    def test_supports_only_its_own_file(self):
        assert YarnLockParser().supports("yarn.lock") is True
        assert YarnLockParser().supports("pnpm-lock.yaml") is False

    def test_v1_entry(self, tmp_path: Path):
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            "# yarn lockfile v1\n"
            "\n"
            "lodash@^4.17.21:\n"
            '  version "4.17.21"\n'
            '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"\n'
            f"  integrity {_sri(b'lodash')}\n"
        )

        (found,) = YarnLockParser().parse(lock)

        assert found.name == "lodash"
        assert found.version == "4.17.21"
        assert found.value == _hex(b"lodash")

    def test_v1_scoped_package_keeps_its_scope(self, tmp_path: Path):
        lock = tmp_path / "yarn.lock"
        lock.write_text(f'"@babel/core@^7.24.0":\n  version "7.24.0"\n  integrity {_sri(b"babel")}\n')
        (found,) = YarnLockParser().parse(lock)
        assert found.name == "@babel/core"

    def test_v1_header_listing_several_ranges(self, tmp_path: Path):
        """One entry can satisfy several specifiers; the name is still one name."""
        lock = tmp_path / "yarn.lock"
        lock.write_text(f'ms@^2.1.1, ms@^2.1.3, ms@~2.1.0:\n  version "2.1.3"\n  integrity {_sri(b"ms")}\n')
        (found,) = YarnLockParser().parse(lock)
        assert found.name == "ms"
        assert found.version == "2.1.3"

    def test_v1_last_entry_is_not_dropped(self, tmp_path: Path):
        """The final package is flushed after the loop, not by the next header."""
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            'first@^1.0.0:\n  version "1.0.0"\n'
            f"  integrity {_sri(b'first')}\n"
            "\n"
            'last@^2.0.0:\n  version "2.0.0"\n'
            f"  integrity {_sri(b'last')}\n"
        )
        found = _by_name(YarnLockParser().parse(lock))
        assert set(found) == {"first", "last"}
        assert found["last"].value == _hex(b"last")

    def test_v1_entry_without_integrity_is_skipped(self, tmp_path: Path):
        lock = tmp_path / "yarn.lock"
        lock.write_text('git-dep@github:owner/repo:\n  version "1.0.0"\n')
        assert YarnLockParser().parse(lock) == []

    def test_berry_format_is_detected_and_parsed(self, tmp_path: Path):
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            '# This file is generated by running "yarn install" inside your project.\n'
            "# Manual changes might be lost - proceed with caution!\n"
            "\n"
            "__metadata:\n"
            "  version: 8\n"
            "\n"
            '"lodash@npm:^4.17.21":\n'
            "  version: 4.17.21\n"
            '  resolution: "lodash@npm:4.17.21"\n'
            f"  checksum: {_sri(b'lodash')}\n"
        )

        (found,) = YarnLockParser().parse(lock)

        assert found.name == "lodash"
        assert found.version == "4.17.21"
        assert found.value == _hex(b"lodash")

    def test_berry_checksum_carrying_a_cache_key_prefix(self, tmp_path: Path):
        """Yarn 4 writes "10/<sri>"; the cache version is not part of the hash."""
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            '# This file is generated by running "yarn install" inside your project.\n'
            "\n"
            '"ms@npm:2.1.3":\n'
            "  version: 2.1.3\n"
            f"  checksum: 10/{_sri(b'ms')}\n"
        )
        (found,) = YarnLockParser().parse(lock)
        assert found.value == _hex(b"ms")

    def test_berry_workspace_entries_are_named_without_the_protocol(self, tmp_path: Path):
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            '# This file is generated by running "yarn install" inside your project.\n'
            "\n"
            '"my-app@workspace:.":\n'
            "  version: 0.0.0-use.local\n"
            '  resolution: "my-app@workspace:."\n'
            "\n"
            '"@scope/pkg@npm:1.0.0":\n'
            "  version: 1.0.0\n"
            f"  checksum: {_sri(b'scoped')}\n"
        )
        found = _by_name(YarnLockParser().parse(lock))
        # The workspace entry has no checksum, so only the real package lands.
        assert set(found) == {"@scope/pkg"}

    def test_berry_checksum_whose_base64_contains_a_slash(self, tmp_path: Path):
        """Regression: stripping the cache key must not cut into the digest.

        Standard base64 uses "/" as an alphabet character, and roughly three
        of every four sha512 digests contain at least one. Splitting on the
        first slash to remove Yarn 4's "10/" prefix therefore truncated the
        hash for most packages, which then failed to decode and were dropped
        silently -- a thinner SBOM, no error anywhere.
        """
        payload = next(p for p in (f"pkg-{i}".encode() for i in range(200)) if "/" in _sri(p).split("-", 1)[1])
        sri = _sri(payload)
        assert "/" in sri.split("-", 1)[1], "fixture must exercise the bug"

        lock = tmp_path / "yarn.lock"
        lock.write_text(
            '# This file is generated by running "yarn install" inside your project.\n'
            "\n"
            '"slashy@npm:1.0.0":\n'
            "  version: 1.0.0\n"
            f"  checksum: {sri}\n"
        )

        (found,) = YarnLockParser().parse(lock)
        assert found.value == _hex(payload)

    def test_berry_cache_key_prefix_is_still_stripped(self, tmp_path: Path):
        """And the prefix it was meant to remove must still go."""
        payload = next(p for p in (f"pkg-{i}".encode() for i in range(200)) if "/" in _sri(p).split("-", 1)[1])
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            '# This file is generated by running "yarn install" inside your project.\n'
            "\n"
            '"both@npm:1.0.0":\n'
            "  version: 1.0.0\n"
            f"  checksum: 10/{_sri(payload)}\n"
        )

        (found,) = YarnLockParser().parse(lock)
        assert found.value == _hex(payload)

    def test_berry_non_string_checksum_is_ignored(self, tmp_path: Path):
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            '# This file is generated by running "yarn install" inside your project.\n'
            "\n"
            '"odd@npm:1.0.0":\n'
            "  version: 1.0.0\n"
            "  checksum: 12345\n"
        )
        assert YarnLockParser().parse(lock) == []

    def test_berry_malformed_yaml_returns_nothing_rather_than_raising(self, tmp_path: Path):
        lock = tmp_path / "yarn.lock"
        lock.write_text(
            '# This file is generated by running "yarn install" inside your project.\n'
            "\n"
            '"unclosed@npm:1.0.0:\n  version: [1.0.0\n'
        )
        assert YarnLockParser().parse(lock) == []


class TestPnpmLockParser:
    """pnpm-lock.yaml, v6-style `packages` and v9-style `snapshots`."""

    def test_supports_only_its_own_file(self):
        assert PnpmLockParser().supports("pnpm-lock.yaml") is True
        assert PnpmLockParser().supports("package-lock.json") is False

    def test_v6_packages_with_leading_slash_keys(self, tmp_path: Path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(
            "lockfileVersion: '6.0'\n"
            "packages:\n"
            "  /lodash@4.17.21:\n"
            f"    resolution: {{integrity: {_sri(b'lodash')}}}\n"
            "  /@babel/core@7.24.0:\n"
            f"    resolution: {{integrity: {_sri(b'babel')}}}\n"
        )

        found = _by_name(PnpmLockParser().parse(lock))

        assert set(found) == {"lodash", "@babel/core"}
        assert found["lodash"].version == "4.17.21"
        assert found["lodash"].value == _hex(b"lodash")
        assert found["@babel/core"].version == "7.24.0"

    def test_a_peer_dependency_suffix_is_not_part_of_the_version(self, tmp_path: Path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(
            f"packages:\n  /react-dom@18.2.0(react@18.2.0):\n    resolution: {{integrity: {_sri(b'react-dom')}}}\n"
        )
        (found,) = PnpmLockParser().parse(lock)
        assert found.name == "react-dom"
        assert found.version == "18.2.0"

    def test_entries_without_integrity_are_skipped(self, tmp_path: Path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(
            "packages:\n"
            "  /tarball-dep@1.0.0:\n"
            "    resolution: {tarball: https://example.invalid/x.tgz}\n"
            "  /real@2.0.0:\n"
            f"    resolution: {{integrity: {_sri(b'real')}}}\n"
        )
        (found,) = PnpmLockParser().parse(lock)
        assert found.name == "real"

    def test_v9_snapshots_take_their_hash_from_the_packages_section(self, tmp_path: Path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(
            "lockfileVersion: '9.0'\n"
            "snapshots:\n"
            "  lodash@4.17.21: {}\n"
            "packages:\n"
            "  lodash@4.17.21:\n"
            f"    resolution: {{integrity: {_sri(b'lodash')}}}\n"
        )

        found = PnpmLockParser().parse(lock)

        # The packages section alone already yields it; the point is that one
        # hash comes back, not two.
        assert len(found) == 1
        assert found[0].name == "lodash"
        assert found[0].value == _hex(b"lodash")

    def test_an_empty_document_is_not_an_error(self, tmp_path: Path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text("")
        assert PnpmLockParser().parse(lock) == []

    def test_a_scalar_document_is_not_an_error(self, tmp_path: Path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text("just-a-string\n")
        assert PnpmLockParser().parse(lock) == []

    def test_a_key_with_no_version_is_skipped(self, tmp_path: Path):
        lock = tmp_path / "pnpm-lock.yaml"
        lock.write_text(f"packages:\n  nameonly:\n    resolution: {{integrity: {_sri(b'x')}}}\n")
        assert PnpmLockParser().parse(lock) == []


class TestPoetryLockParser:
    """poetry.lock, whose files section has had two shapes."""

    def test_supports_only_its_own_file(self):
        assert PoetryLockParser().supports("poetry.lock") is True
        assert PoetryLockParser().supports("uv.lock") is False

    def test_files_array_format(self, tmp_path: Path):
        digest = hashlib.sha256(b"django").hexdigest()
        lock = tmp_path / "poetry.lock"
        lock.write_text(
            "[[package]]\n"
            'name = "django"\n'
            'version = "5.1.1"\n'
            "\n"
            "[[package.files]]\n"
            'file = "django-5.1.1-py3-none-any.whl"\n'
            f'hash = "sha256:{digest}"\n'
        )

        (found,) = PoetryLockParser().parse(lock)

        assert found.name == "django"
        assert found.version == "5.1.1"
        assert found.algorithm is HashAlgorithm.SHA256
        assert found.value == digest
        assert found.artifact_type == "wheel"

    def test_a_universal_wheel_wins_over_a_platform_specific_one(self, tmp_path: Path):
        universal = hashlib.sha256(b"universal").hexdigest()
        platform = hashlib.sha256(b"platform").hexdigest()
        lock = tmp_path / "poetry.lock"
        lock.write_text(
            "[[package]]\n"
            'name = "cryptography"\n'
            'version = "42.0.0"\n'
            "\n"
            "[[package.files]]\n"
            'file = "cryptography-42.0.0-cp39-abi3-manylinux_2_28_x86_64.whl"\n'
            f'hash = "sha256:{platform}"\n'
            "\n"
            "[[package.files]]\n"
            'file = "cryptography-42.0.0-py3-none-any.whl"\n'
            f'hash = "sha256:{universal}"\n'
        )

        (found,) = PoetryLockParser().parse(lock)

        assert found.value == universal, "the portable wheel is the one worth recording"

    def test_a_wheel_wins_over_an_sdist(self, tmp_path: Path):
        wheel = hashlib.sha256(b"wheel").hexdigest()
        sdist = hashlib.sha256(b"sdist").hexdigest()
        lock = tmp_path / "poetry.lock"
        lock.write_text(
            "[[package]]\n"
            'name = "thing"\n'
            'version = "1.0.0"\n'
            "\n"
            "[[package.files]]\n"
            'file = "thing-1.0.0.tar.gz"\n'
            f'hash = "sha256:{sdist}"\n'
            "\n"
            "[[package.files]]\n"
            'file = "thing-1.0.0-cp312-cp312-win_amd64.whl"\n'
            f'hash = "sha256:{wheel}"\n'
        )

        (found,) = PoetryLockParser().parse(lock)

        assert found.value == wheel
        assert found.artifact_type == "wheel"

    def test_an_sdist_only_package_still_yields_a_hash(self, tmp_path: Path):
        sdist = hashlib.sha256(b"sdist-only").hexdigest()
        lock = tmp_path / "poetry.lock"
        lock.write_text(
            "[[package]]\n"
            'name = "legacy"\n'
            'version = "0.1.0"\n'
            "\n"
            "[[package.files]]\n"
            'file = "legacy-0.1.0.tar.gz"\n'
            f'hash = "sha256:{sdist}"\n'
        )

        (found,) = PoetryLockParser().parse(lock)

        assert found.value == sdist
        assert found.artifact_type == "sdist"

    def test_files_table_format(self, tmp_path: Path):
        digest = hashlib.sha256(b"tabular").hexdigest()
        lock = tmp_path / "poetry.lock"
        lock.write_text(
            "[[package]]\n"
            'name = "tabular"\n'
            'version = "2.0.0"\n'
            "\n"
            "[package.files]\n"
            f'"tabular-2.0.0-py3-none-any.whl" = "sha256:{digest}"\n'
        )

        (found,) = PoetryLockParser().parse(lock)

        assert found.value == digest

    def test_a_package_with_no_files_is_skipped(self, tmp_path: Path):
        lock = tmp_path / "poetry.lock"
        lock.write_text('[[package]]\nname = "vcs-dep"\nversion = "1.0.0"\n')
        assert PoetryLockParser().parse(lock) == []

    def test_a_package_missing_its_version_is_skipped(self, tmp_path: Path):
        lock = tmp_path / "poetry.lock"
        lock.write_text('[[package]]\nname = "nameless"\n')
        assert PoetryLockParser().parse(lock) == []

    def test_an_unrecognised_hash_prefix_is_dropped(self, tmp_path: Path):
        lock = tmp_path / "poetry.lock"
        lock.write_text(
            "[[package]]\n"
            'name = "odd"\n'
            'version = "1.0.0"\n'
            "\n"
            "[[package.files]]\n"
            'file = "odd-1.0.0-py3-none-any.whl"\n'
            'hash = "crc32:deadbeef"\n'
        )
        assert PoetryLockParser().parse(lock) == []


class TestPackageHash:
    """The two hash-string formats the parsers hand in."""

    def test_sri_round_trips_to_hex(self):
        pkg = PackageHash.from_sri("x", "1.0", _sri(b"payload"))
        assert pkg is not None
        assert pkg.value == _hex(b"payload")

    def test_sri_with_an_unknown_algorithm_is_rejected(self):
        assert PackageHash.from_sri("x", "1.0", "crc32-AAAA") is None

    def test_sri_without_a_separator_is_rejected(self):
        assert PackageHash.from_sri("x", "1.0", "sha512") is None

    def test_sri_with_undecodable_base64_is_rejected(self):
        assert PackageHash.from_sri("x", "1.0", "sha512-!!!not-base64!!!") is None

    def test_prefixed_requires_a_colon(self):
        assert PackageHash.from_prefixed("x", "1.0", "sha256abc") is None

    def test_prefixed_with_an_unknown_algorithm_is_rejected(self):
        assert PackageHash.from_prefixed("x", "1.0", "crc32:abc") is None

    @pytest.mark.parametrize(
        ("algorithm", "expected"),
        [
            (HashAlgorithm.SHA1, "SHA1"),
            (HashAlgorithm.SHA256, "SHA256"),
            (HashAlgorithm.SHA512, "SHA512"),
            (HashAlgorithm.SHA3_256, "SHA3-256"),
            (HashAlgorithm.BLAKE2B_256, "BLAKE2b-256"),
            (HashAlgorithm.BLAKE3, "BLAKE3"),
        ],
    )
    def test_spdx_names_differ_from_cyclonedx_ones(self, algorithm, expected):
        """SPDX drops the hyphen for SHA-N but keeps it for SHA3-N."""
        assert algorithm.spdx_alg == expected
        assert algorithm.cyclonedx_alg == algorithm.value

    def test_prefix_lookup_is_case_insensitive(self):
        assert HashAlgorithm.from_prefix("SHA256") is HashAlgorithm.SHA256
        assert HashAlgorithm.from_prefix("sha-256") is HashAlgorithm.SHA256

    def test_an_unknown_prefix_is_none(self):
        assert HashAlgorithm.from_prefix("crc32") is None


class TestNameExtractionEdges:
    """The header/key shapes that decide what a package is called."""

    @pytest.mark.parametrize(
        ("header", "expected"),
        [
            ("lodash@^4.17.21:", "lodash"),
            ('"@scope/name@^1.0.0":', "@scope/name"),
            ("a@^1.0.0, a@~1.1.0:", "a"),
            ("@scope/only@npm:1.0.0:", "@scope/only"),
        ],
    )
    def test_v1_headers(self, header, expected):
        assert YarnLockParser._extract_name_from_header(header) == expected

    def test_a_v1_header_with_no_version_separator_has_no_name(self):
        assert YarnLockParser._extract_name_from_header("garbage-with-no-at:") is None

    @pytest.mark.parametrize(
        ("key", "expected"),
        [
            ("lodash@npm:^4.17.21", "lodash"),
            ("@scope/name@npm:^1.0.0", "@scope/name"),
            ("my-app@workspace:.", "my-app"),
            ("thing@patch:thing@npm%3A1.0.0#./p.patch", "thing"),
            ("linked@portal:../linked", "linked"),
            ("other@link:../other", "other"),
            ('"quoted@npm:1.0.0"', "quoted"),
            ("plain@1.0.0", "plain"),
            ("@scope/plain@1.0.0", "@scope/plain"),
        ],
    )
    def test_berry_keys(self, key, expected):
        assert YarnLockParser._extract_name_from_berry_key(key) == expected

    def test_a_berry_key_with_no_at_has_no_name(self):
        assert YarnLockParser._extract_name_from_berry_key("nameonly") is None

    @pytest.mark.parametrize(
        ("key", "expected"),
        [
            ("/lodash@4.17.21", ("lodash", "4.17.21")),
            ("lodash@4.17.21", ("lodash", "4.17.21")),
            ("/@scope/name@1.2.3", ("@scope/name", "1.2.3")),
            ("/react-dom@18.2.0(react@18.2.0)", ("react-dom", "18.2.0")),
        ],
    )
    def test_pnpm_keys(self, key, expected):
        assert PnpmLockParser._parse_package_key(key) == expected

    def test_a_pnpm_key_with_no_at_has_neither_name_nor_version(self):
        assert PnpmLockParser._parse_package_key("/nameonly") == (None, None)


class TestPnpmSnapshotsFallback:
    """pnpm v9 splits resolution (`packages`) from the graph (`snapshots`).

    `parse` only reaches this when the packages section yielded nothing, so
    the method is exercised directly — the branch is a fallback, not the
    usual route through a v9 lockfile.
    """

    def test_a_snapshot_takes_its_hash_from_the_packages_section(self):
        parser = PnpmLockParser()
        data = {
            "packages": {"lodash@4.17.21": {"resolution": {"integrity": _sri(b"lodash")}}},
        }
        (found,) = parser._parse_snapshots({"lodash@4.17.21": {}}, data)
        assert found.name == "lodash"
        assert found.value == _hex(b"lodash")

    def test_the_slash_prefixed_packages_key_is_also_tried(self):
        parser = PnpmLockParser()
        data = {"packages": {"/lodash@4.17.21": {"resolution": {"integrity": _sri(b"lodash")}}}}
        (found,) = parser._parse_snapshots({"lodash@4.17.21": {}}, data)
        assert found.value == _hex(b"lodash")

    def test_a_snapshot_with_no_matching_package_is_skipped(self):
        parser = PnpmLockParser()
        assert parser._parse_snapshots({"absent@1.0.0": {}}, {"packages": {}}) == []

    def test_a_package_without_integrity_is_skipped(self):
        parser = PnpmLockParser()
        data = {"packages": {"x@1.0.0": {"resolution": {"tarball": "https://example.invalid/x.tgz"}}}}
        assert parser._parse_snapshots({"x@1.0.0": {}}, data) == []

    def test_a_non_dict_resolution_is_skipped(self):
        parser = PnpmLockParser()
        data = {"packages": {"x@1.0.0": {"resolution": "not-a-mapping"}}}
        assert parser._parse_snapshots({"x@1.0.0": {}}, data) == []

    def test_an_unparseable_snapshot_key_is_skipped(self):
        parser = PnpmLockParser()
        assert parser._parse_snapshots({"nameonly": {}}, {"packages": {}}) == []

    def test_the_same_snapshot_twice_yields_one_hash(self):
        parser = PnpmLockParser()
        data = {"packages": {"x@1.0.0": {"resolution": {"integrity": _sri(b"x")}}}}
        seen: set[tuple[str, str]] = set()
        first = parser._parse_snapshots({"x@1.0.0": {}}, data, seen)
        second = parser._parse_snapshots({"x@1.0.0": {}}, data, seen)
        assert len(first) == 1
        assert second == []

    def test_a_non_dict_package_entry_is_skipped(self):
        parser = PnpmLockParser()
        assert parser._parse_packages({"x@1.0.0": "not-an-object"}) == []


class TestParserRegistry:
    """Dispatch from a lockfile name to the parser that understands it."""

    def _registry(self):
        from sbomify_action._hash_enrichment.registry import ParserRegistry

        registry = ParserRegistry()
        registry.register(PackageLockParser())
        registry.register(YarnLockParser())
        return registry

    def test_dispatches_to_the_matching_parser(self, tmp_path: Path):
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.21", "integrity": _sri(b"lodash")}}})
        )

        (found,) = self._registry().parse_lockfile(lock)

        assert found.name == "lodash"
        assert found.value == _hex(b"lodash")

    def test_an_unknown_lockfile_yields_nothing(self, tmp_path: Path):
        lock = tmp_path / "Gemfile.lock"
        lock.write_text("GEM\n")
        assert self._registry().parse_lockfile(lock) == []

    def test_get_parser_for_reports_a_miss_as_none(self):
        registry = self._registry()
        assert registry.get_parser_for("package-lock.json") is not None
        assert registry.get_parser_for("Gemfile.lock") is None

    def test_a_parser_that_raises_does_not_take_the_run_down(self, tmp_path: Path, caplog):
        """Hash enrichment is additive; a broken lockfile must not be fatal."""
        lock = tmp_path / "package-lock.json"
        lock.write_text("{ this is not json")

        assert self._registry().parse_lockfile(lock) == []

    def test_it_reports_what_it_knows_about(self):
        registry = self._registry()
        assert registry.registered_parsers == ["npm-package-lock", "yarn-lock"]
        assert registry.supported_files == {"package-lock.json", "yarn.lock"}


class TestNormalizePackageName:
    """Matching lockfile names against SBOM component names."""

    @pytest.mark.parametrize(
        ("name", "ecosystem", "expected"),
        [
            ("Flask-SQLAlchemy", "pypi", "flask_sqlalchemy"),
            ("zope.interface", "pypi", "zope_interface"),
            ("@Scope/Name", "npm", "@scope/name"),
            ("serde-json", "cargo", "serde_json"),
            ("My_Package", "pub", "my_package"),
            ("SomeThing", "unknown-ecosystem", "something"),
        ],
    )
    def test_normalization_per_ecosystem(self, name, ecosystem, expected):
        assert normalize_package_name(name, ecosystem) == expected

    def test_pypi_separators_are_equivalent(self):
        """PEP 503: these three spellings are the same project."""
        forms = {normalize_package_name(n, "pypi") for n in ("a-b.c", "a_b_c", "A.B-C")}
        assert len(forms) == 1
