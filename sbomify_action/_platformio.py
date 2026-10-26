"""Read what PlatformIO installed for a project.

PlatformIO, the usual build system for Arduino and ESP32 firmware, has no lock
file. `platformio.ini` declares `lib_deps` -- often as ranges such as
`bblanchon/ArduinoJson@^7.0.0` -- and `pio pkg install` resolves them into
`.pio/libdeps/<env>/<library>/`. What it resolved is recorded beside each
library in a `.piopm` file the package manager writes at install time:

    {"type": "library", "name": "ArduinoJson", "version": "7.4.3",
     "spec": {"owner": "bblanchon", "id": 64, "name": "ArduinoJson", "uri": null}}

Libraries installed from git keep the same file inside their `.git/`
directory, with the source in `spec.uri` and the commit folded into the
version (`1.2.7+sha.5438181`).

That is the closest thing to a lock file the ecosystem has: the exact version,
the registry owner and the source, written by the resolver rather than by the
library's author. The `library.json` beside it is the author's manifest, which
is why versions are not read from it -- many Arduino libraries ship only
`library.properties`, and a git checkout's `library.json` names the release it
was cut from, not the commit that was installed. It is read for what only
the author knows -- description, licence, authors, repository -- and for the
libraries it depends on, which is all it can say about the graph.

Which installed libraries a build uses is decided the way `pio pkg list`
decides it: from each environment's lib_deps, through each library's
dependencies, to what was installed for them. The platform and framework
packages the environment builds with (Arduino-ESP32, ESP-IDF, the AVR core)
are compiled into the firmware too, and come from PlatformIO's core directory.

`platformio.ini` itself is read the way PlatformIO reads it (see
`ProjectConfig`): `extends`, `[env]` inheritance, `${section.option}`
interpolation, `extra_configs` and the `PLATFORMIO_*_DIR` variables all decide
what a project declares and where it installed it.
"""

from __future__ import annotations

import configparser
import glob
import json
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from packageurl import PackageURL

from sbomify_action.logging_config import logger

PLATFORMIO_INI = "platformio.ini"
METADATA_FILE = ".piopm"
REGISTRY_URL = "https://registry.platformio.org"

#: A registry requirement that names exactly one release. PlatformIO matches
#: with semantic_version's SimpleSpec, where a partial version is a wildcard:
#: `@2.8` accepts 2.8.0 and 2.8.1, and `@1` any 1.x. Only a full
#: MAJOR.MINOR.PATCH, optionally with `=`, pins. A leading `v` is not a
#: version PlatformIO accepts at all.
_EXACT_VERSION = re.compile(r"^=?\s*\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
#: A git ref that is conventionally immutable: a full commit, or a tag that
#: looks like a release. Anything else -- `#develop`, `#main` -- is a branch
#: as far as the syntax can tell, and a branch moves.
_IMMUTABLE_REF = re.compile(r"^([0-9a-f]{40}|v?\d+(\.\d+)*([-+.][0-9A-Za-z.\-+]*)?)$")
_ARCHIVE_SUFFIXES = (".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")

# PlatformIO's own patterns (platformio/project/config.py).
_VARIABLE = re.compile(r"\$\{(?:([^\.\}\()]+)\.)?([^\}]+)\}")
_INLINE_COMMENT = re.compile(r"\s+;.*$")


class _Unresolvable(Exception):
    """An interpolation PlatformIO would resolve from something we cannot see."""


class ProjectConfig:
    """The subset of PlatformIO's ProjectConfig needed to read lib_deps.

    Mirrors platformio/project/config.py in PlatformIO 6.x: the same comment
    handling, the same `extends` walk, the same multi-value splitting and the
    same interpolation rules. Anything it cannot resolve is left as the
    literal `${...}` so callers can treat it as unknown rather than guess.
    """

    _SYSENV_DIRS = {
        "core_dir": "PLATFORMIO_CORE_DIR",
        "platforms_dir": "PLATFORMIO_PLATFORMS_DIR",
        "packages_dir": "PLATFORMIO_PACKAGES_DIR",
        "workspace_dir": "PLATFORMIO_WORKSPACE_DIR",
        "libdeps_dir": "PLATFORMIO_LIBDEPS_DIR",
        "build_dir": "PLATFORMIO_BUILD_DIR",
    }
    _DEFAULTS = {
        ("platformio", "core_dir"): "~/.platformio",
        ("platformio", "platforms_dir"): "${platformio.core_dir}/platforms",
        ("platformio", "packages_dir"): "${platformio.core_dir}/packages",
        ("platformio", "workspace_dir"): "${PROJECT_DIR}/.pio",
        ("platformio", "libdeps_dir"): "${platformio.workspace_dir}/libdeps",
        ("platformio", "build_dir"): "${platformio.workspace_dir}/build",
        ("platformio", "lib_dir"): "${PROJECT_DIR}/lib",
    }

    def __init__(self, ini_path: Path) -> None:
        self.path = ini_path
        self.project_dir = ini_path.resolve().parent
        self._parser = configparser.ConfigParser(inline_comment_prefixes=("#", ";"), interpolation=None, strict=False)
        self._read(ini_path)

    def _read(self, path: Path, seen: set[Path] | None = None) -> None:
        seen = seen if seen is not None else set()
        resolved = path.resolve()
        if resolved in seen:
            return
        seen.add(resolved)
        self._parser.read(path, encoding="utf-8")
        for pattern in self.get_list("platformio", "extra_configs"):
            if "${" in pattern:
                continue
            pattern = os.path.expanduser(pattern)
            if not os.path.isabs(pattern):
                pattern = str(self.project_dir / pattern)
            for item in sorted(glob.glob(pattern, recursive=True)):
                self._read(Path(item), seen)

    @staticmethod
    def parse_multi_values(value: str) -> list[str]:
        items = value.split("\n" if "\n" in value else ", ")
        result = []
        for item in items:
            item = item.strip()
            if not item or item.startswith((";", "#")):
                continue
            if ";" in item:
                item = _INLINE_COMMENT.sub("", item).strip()
            result.append(item)
        return result

    def envs(self) -> list[str]:
        return [section[4:] for section in self._parser.sections() if section.startswith("env:")]

    def _walk(self, root: str) -> Iterable[str]:
        """Sections consulted for an option, in PlatformIO's order."""
        queue = ["env", root] if root.startswith("env:") else [root]
        done: set[str] = set()
        while queue:
            section = queue.pop()
            if section in done:
                continue
            done.add(section)
            if not self._parser.has_section(section):
                continue
            yield section
            if self._parser.has_option(section, "extends"):
                queue.extend(self.parse_multi_values(self._parser.get(section, "extends")))

    def _raw(self, section: str, option: str) -> str | None:
        if section == "platformio" and option in self._SYSENV_DIRS:
            override = os.environ.get(self._SYSENV_DIRS[option])
            if override:
                return override
        for candidate in self._walk(section):
            if self._parser.has_option(candidate, option):
                return self._parser.get(candidate, option)
        return self._DEFAULTS.get((section, option))

    def get(self, section: str, option: str, _depth: int = 0) -> str | None:
        """An option's value with interpolations expanded where possible."""
        value = self._raw(section, option)
        if value is None or "${" not in value:
            return value
        if _depth > 20:
            raise _Unresolvable(f"{section}.{option} recurses")

        def expand(match: re.Match[str]) -> str:
            ref_section, ref_option = match.group(1), match.group(2)
            if ref_section is None:
                if ref_option == "PROJECT_DIR":
                    return str(self.project_dir)
                # Build-time (SCons) variables stay as written.
                return match.group(0)
            if ref_section == "sysenv":
                return os.environ.get(ref_option, "")
            if ref_section == "this":
                if ref_option == "__env__":
                    if not section.startswith("env:"):
                        raise _Unresolvable("${this.__env__} outside an env section")
                    return section[4:]
                ref_section = section
            try:
                nested = self.get(ref_section, ref_option, _depth + 1)
            except _Unresolvable:
                return match.group(0)
            if nested is None:
                return match.group(0)
            return nested

        return _VARIABLE.sub(expand, value)

    def get_list(self, section: str, option: str) -> list[str]:
        try:
            value = self.get(section, option)
        except _Unresolvable:
            value = self._raw(section, option)
        return self.parse_multi_values(value) if value else []

    def get_dir(self, option: str) -> Path | None:
        """A `[platformio]` directory option, or None if it cannot be resolved."""
        try:
            value = self.get("platformio", option)
        except _Unresolvable:
            return None
        if not value or "${" in value:
            return None
        path = Path(os.path.expanduser(value.strip()))
        return path if path.is_absolute() else self.project_dir / path


@dataclass(frozen=True)
class Requirement:
    """One dependency a library's manifest declares, as written there."""

    name: str
    owner: str | None = None
    #: A version requirement, or the URL the dependency is fetched from.
    spec: str | None = None
    #: library.json may restrict a dependency to some platforms or
    #: frameworks; None means all of them.
    platforms: tuple[str, ...] | None = None
    frameworks: tuple[str, ...] | None = None


@dataclass(frozen=True)
class Manifest:
    """What an author's library.json, library.properties or package.json says."""

    description: str | None = None
    license: str | None = None
    authors: tuple[tuple[str, str | None], ...] = ()
    repository: str | None = None
    homepage: str | None = None


@dataclass(frozen=True)
class InstalledLibrary:
    """One library as PlatformIO's package manager recorded it."""

    name: str
    version: str
    owner: str | None = None
    uri: str | None = None
    commit: str | None = None
    #: The name the requirement used, which PlatformIO keeps beside the
    #: library's own (`Adafruit_ADS1X15` for "Adafruit ADS1X15").
    spec_name: str | None = field(default=None, compare=False)
    #: What this library's own manifest says it needs.
    requires: tuple[Requirement, ...] = field(default=(), compare=False)
    #: Descriptive fields from the author's manifest. Never the version:
    #: that comes from what was installed.
    manifest: Manifest = field(default_factory=Manifest, compare=False)

    @property
    def from_registry(self) -> bool:
        return self.uri is None and self.owner is not None

    @property
    def from_git(self) -> bool:
        return bool(self.uri) and _is_git_uri(str(self.uri))

    @property
    def stable_version(self) -> str | None:
        """The version to publish, which must not change between installs.

        PlatformIO gives a library whose manifest has no version
        `0.0.0+<install timestamp>`. That is when it was downloaded, not what
        it is: the same archive installed tomorrow gets a different version.
        The ref in the URL is what identifies it, when there is one.
        """
        if not _INSTALL_TIMESTAMP.match(self.version):
            return self.version
        github = _github_source(self.uri) if self.uri else None
        if github and github[2]:
            return github[2]
        return None

    @property
    def purl(self) -> str:
        """Package URL for this library.

        purl-spec has no `platformio` type, so registry libraries are
        `generic` with the registry named. Anything fetched from GitHub --
        cloned, or downloaded as a source archive or release asset -- is
        `github` at the commit or ref it was fetched at, which is what a
        vulnerability database can look up. Other git hosts keep their
        repository and commit; other archives the URL they came from.
        """
        if self.uri:
            github = _github_source(self.uri)
            if github:
                owner, repo, ref = github
                version = (self.commit if self.from_git else ref) or self.stable_version
                return PackageURL(
                    type="github", namespace=owner, name=repo, version=version, qualifiers=_asset(self.uri)
                ).to_string()
        if self.uri and self.from_git:
            url = _strip_vcs_prefix(self.uri)
            vcs_url = f"git+{url}@{self.commit}" if self.commit else f"git+{url}"
            return PackageURL(
                type="generic", name=self.name, version=self.stable_version, qualifiers={"vcs_url": vcs_url}
            ).to_string()
        if self.uri:
            return PackageURL(
                type="generic", name=self.name, version=self.stable_version, qualifiers={"download_url": self.uri}
            ).to_string()
        if self.owner:
            return PackageURL(
                type="generic",
                namespace=self.owner,
                name=self.name,
                version=self.version,
                qualifiers={"repository_url": REGISTRY_URL},
            ).to_string()
        return PackageURL(type="generic", name=self.name, version=self.version).to_string()

    @property
    def supplier(self) -> str | None:
        """Who publishes it: the registry account, or the GitHub owner."""
        if self.owner:
            return self.owner
        github = _github_source(self.uri) if self.uri else None
        return github[0] if github else None


@dataclass(frozen=True)
class FrameworkPackage:
    """A platform, or a framework package compiled into the firmware."""

    name: str
    version: str
    #: "platform" or "framework" -- the CycloneDX component type.
    kind: str
    owner: str | None = None
    uri: str | None = None
    manifest: Manifest = field(default_factory=Manifest, compare=False)
    #: (product, version) for the NVD CPE of the upstream it packages.
    cpe_product: tuple[str, str] | None = field(default=None, compare=False)
    #: Purls of what this package bundles (the ESP-IDF inside Arduino-ESP32).
    bundles: tuple[str, ...] = field(default=(), compare=False)
    #: (owner, repository, tag) on GitHub, for an upstream known only by
    #: its release rather than by where it was downloaded from.
    github: tuple[str, str, str] | None = None

    @property
    def purl(self) -> str:
        if self.github:
            owner, repo, tag = self.github
            return PackageURL(type="github", namespace=owner, name=repo, version=tag).to_string()
        if self.uri:
            github = _github_source(self.uri)
            if github and github[2]:
                return PackageURL(
                    type="github", namespace=github[0], name=github[1], version=github[2], qualifiers=_asset(self.uri)
                ).to_string()
            return PackageURL(
                type="generic", name=self.name, version=self.version, qualifiers={"download_url": self.uri}
            ).to_string()
        return PackageURL(
            type="generic",
            namespace=self.owner,
            name=self.name,
            version=self.version,
            qualifiers={"repository_url": REGISTRY_URL} if self.owner else None,
        ).to_string()

    @property
    def cpe(self) -> str | None:
        if not self.cpe_product:
            return None
        product, version = self.cpe_product
        return f"cpe:2.3:a:espressif:{product}:{version}:*:*:*:*:*:*:*"


def _is_git_uri(uri: str) -> bool:
    url = uri.split("#", 1)[0]
    if url.lower().endswith(_ARCHIVE_SUFFIXES):
        return False
    return url.startswith(("git+", "git@", "git://")) or url.endswith(".git")


def _strip_vcs_prefix(uri: str) -> str:
    """`git+https://host/repo.git#ref` -> `https://host/repo.git`."""
    url = uri.split("#", 1)[0]
    return url[4:] if url.startswith("git+") else url


_GITHUB_ARCHIVE = re.compile(
    r"^https?://github\.com/([^/]+)/([^/#?]+)/(?:"
    r"archive/(?:refs/(?:tags|heads)/)?(?P<archive>.+?)(?:\.zip|\.tar\.gz|\.tgz)"
    r"|releases/download/(?P<release>[^/]+)/[^/]+"
    r")$"
)
_GITHUB_CODELOAD = re.compile(
    r"^https?://codeload\.github\.com/([^/]+)/([^/]+)/(?:zip|tar\.gz)/(?:refs/(?:tags|heads)/)?(.+)$"
)
_GITHUB_REPO = re.compile(r"^https?://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?$")


def _asset(uri: str) -> dict[str, str] | None:
    """A release asset is one of several files in a release, so name which."""
    return {"download_url": uri} if "/releases/download/" in uri else None


def _github_source(uri: str) -> tuple[str, str, str | None] | None:
    """(owner, repository, ref) for something fetched from GitHub, else None.

    The ref is the commit, tag or branch the URL names, or None for a bare
    repository URL (whose commit is read from the checkout instead).
    """
    url, _, ref = uri.partition("#")
    url = url[4:] if url.startswith("git+") else url
    if match := _GITHUB_ARCHIVE.match(url):
        return match.group(1), match.group(2), match.group("archive") or match.group("release")
    if match := _GITHUB_CODELOAD.match(url):
        return match.group(1), match.group(2), match.group(3)
    if match := _GITHUB_REPO.match(url):
        return match.group(1), match.group(2), ref or None
    return None


def libdeps_dir(ini_path: Path) -> Path | None:
    """Where `pio pkg install` put libraries for this project.

    Resolved the way PlatformIO resolves it: `PLATFORMIO_LIBDEPS_DIR` /
    `PLATFORMIO_WORKSPACE_DIR`, then `[platformio] libdeps_dir` /
    `workspace_dir` with `~` and `${...}` expanded, then `.pio/libdeps`.
    None when the configuration names something that cannot be resolved here.
    """
    return ProjectConfig(ini_path).get_dir("libdeps_dir")


def _git_commit(git_dir: Path) -> str | None:
    """The full commit a git-installed library is checked out at."""
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not head.startswith("ref: "):
        return head if _FULL_SHA.match(head) else None
    ref = head[5:]
    try:
        commit = (git_dir / ref).read_text(encoding="utf-8").strip()
        return commit if _FULL_SHA.match(commit) else None
    except OSError:
        pass
    # After `git gc` the ref lives in packed-refs: "<sha> <ref>" per line.
    try:
        packed = (git_dir / "packed-refs").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in packed.splitlines():
        sha, _, name = line.partition(" ")
        if name.strip() == ref and _FULL_SHA.match(sha):
            return sha
    return None


def _as_tuple(value: object) -> tuple[str, ...] | None:
    """library.json's `platforms` / `frameworks`: a string, a list, or `*`."""
    if value is None:
        return None
    items = value.split(",") if isinstance(value, str) else value if isinstance(value, list) else []
    names = tuple(str(item).strip().lower() for item in items if str(item).strip())
    return None if not names or "*" in names else names


def _authors(value: object) -> tuple[tuple[str, str | None], ...]:
    """library.json `authors` (an object or a list of them), maintainers first."""
    entries = [value] if isinstance(value, dict) else value if isinstance(value, list) else []
    found: list[tuple[bool, str, str | None]] = []
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str) and entry["name"].strip():
            email = entry.get("email") if isinstance(entry.get("email"), str) else None
            found.append((not entry.get("maintainer"), entry["name"].strip(), email or None))
    return tuple((name, email) for _, name, email in sorted(found, key=lambda item: item[0]))


_PERSON = re.compile(r"^\s*([^<]+?)\s*(?:<([^>]+)>)?\s*$")


def _people(value: str) -> tuple[tuple[str, str | None], ...]:
    """library.properties `author` / `maintainer`: "Name <email>, Name"."""
    people = []
    for part in value.split(","):
        if (match := _PERSON.match(part)) and match.group(1):
            people.append((match.group(1), match.group(2)))
    return tuple(people)


def _url(value: object) -> str | None:
    if isinstance(value, dict):
        value = value.get("url")
    return value.strip() if isinstance(value, str) and value.strip().startswith(("http://", "https://")) else None


def _json_manifest(data: dict[str, Any]) -> Manifest:
    licence = data.get("license")
    return Manifest(
        description=data["description"].strip() if isinstance(data.get("description"), str) else None,
        license=licence.strip() if isinstance(licence, str) and licence.strip() else None,
        authors=_authors(data.get("authors") or data.get("author")),
        repository=_url(data.get("repository")),
        homepage=_url(data.get("homepage")),
    )


_LICENCE_FILE = re.compile(r"^(licen[cs]e|copying)(\.(txt|md|rst))?$", re.IGNORECASE)
#: Distinctive clauses of the licence texts Arduino libraries ship, most
#: specific first. GNU licences are named rather than identified: the text
#: alone does not say whether "or any later version" applies, which is
#: exactly the difference between the -only and -or-later SPDX ids.
_LICENCE_TEXTS: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("Apache-2.0", ("apache license", "version 2.0"), ()),
    ("MPL-2.0", ("mozilla public license version 2.0",), ()),
    ("BSD-3-Clause", ("redistribution and use in source and binary forms", "neither the name"), ("advertising",)),
    ("BSD-2-Clause", ("redistribution and use in source and binary forms",), ("neither the name", "advertising")),
    (
        "MIT",
        ("permission is hereby granted, free of charge", "the above copyright notice and this permission notice"),
        (),
    ),
    ("ISC", ("permission to use, copy, modify, and/or distribute this software for any purpose",), ()),
    ("BSL-1.0", ("boost software license - version 1.0",), ()),
    ("Unlicense", ("this is free and unencumbered software released into the public domain",), ()),
)
_GNU_TEXTS = (
    ("gnu lesser general public license", "GNU Lesser General Public License"),
    ("gnu library general public license", "GNU Library General Public License"),
    ("gnu affero general public license", "GNU Affero General Public License"),
    ("gnu general public license", "GNU General Public License"),
)


def _licence_from_file(library_dir: Path) -> str | None:
    """The licence a library ships as a LICENSE / COPYING file, when the text is unmistakable."""
    try:
        candidates = sorted(p for p in library_dir.iterdir() if p.is_file() and _LICENCE_FILE.match(p.name))
    except OSError:
        return None
    for candidate in candidates:
        try:
            text = " ".join(candidate.read_text(encoding="utf-8", errors="replace")[:20000].split()).lower()
        except OSError:
            continue
        for spdx_id, required, excluded in _LICENCE_TEXTS:
            if all(phrase in text for phrase in required) and not any(phrase in text for phrase in excluded):
                return spdx_id
        for phrase, name in _GNU_TEXTS:
            if phrase in text and (version := re.search(r"version (\d(?:\.\d)?)", text)):
                return f"{name} v{version.group(1)}"
    return None


def _read_manifest(library_dir: Path) -> tuple[Manifest, tuple[Requirement, ...]]:
    """Descriptive fields and dependencies, with the licence file as a fallback for the licence."""
    manifest, requirements = _read_manifest_files(library_dir)
    if manifest.license is None and (licence := _licence_from_file(library_dir)):
        manifest = replace(manifest, license=licence)
    return manifest, requirements


def _read_manifest_files(library_dir: Path) -> tuple[Manifest, tuple[Requirement, ...]]:
    """Descriptive fields and dependencies from library.json, else library.properties."""
    manifest = library_dir / "library.json"
    if manifest.is_file():
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if isinstance(data, dict):
            requirements: list[Requirement] = []
            dependencies = data.get("dependencies") or []
            if isinstance(dependencies, dict):
                requirements.extend(
                    Requirement(name=str(name), spec=str(spec) if spec else None) for name, spec in dependencies.items()
                )
            elif isinstance(dependencies, list):
                for dependency in dependencies:
                    if isinstance(dependency, dict) and dependency.get("name"):
                        requirements.append(
                            Requirement(
                                name=str(dependency["name"]),
                                owner=str(dependency["owner"]) if dependency.get("owner") else None,
                                spec=str(dependency["version"]) if dependency.get("version") else None,
                                platforms=_as_tuple(dependency.get("platforms")),
                                frameworks=_as_tuple(dependency.get("frameworks")),
                            )
                        )
                    elif isinstance(dependency, str):
                        requirements.append(_parse_spec(dependency))
            return _json_manifest(data), tuple(requirements)
    properties = library_dir / "library.properties"
    if properties.is_file():
        values: dict[str, str] = {}
        try:
            for line in properties.read_text(encoding="utf-8", errors="replace").splitlines():
                key, sep, value = line.partition("=")
                if sep:
                    values[key.strip()] = value.strip()
        except OSError:
            pass
        # "ArduinoJson (>=6.0.0), Adafruit GFX Library"
        depends = tuple(
            Requirement(name=part.split("(", 1)[0].strip())
            for part in values.get("depends", "").split(",")
            if part.split("(", 1)[0].strip()
        )
        people = _people(values.get("maintainer", "")) + _people(values.get("author", ""))
        return (
            Manifest(
                description=values.get("sentence") or None,
                license=values.get("license") or None,
                authors=tuple(dict.fromkeys(people)),
                homepage=_url(values.get("url")),
            ),
            depends,
        )
    return Manifest(), ()


def _read_metadata(library_dir: Path) -> InstalledLibrary | None:
    for candidate in (library_dir / METADATA_FILE, library_dir / ".git" / METADATA_FILE):
        if candidate.is_file():
            break
    else:
        return None
    try:
        data = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.debug(f"PlatformIO: unreadable {candidate}: {e}")
        return None
    if not isinstance(data, dict) or data.get("type") != "library":
        return None
    name, version = data.get("name"), data.get("version")
    if not (isinstance(name, str) and name and isinstance(version, str) and version):
        return None
    spec = data.get("spec")
    if not isinstance(spec, dict):
        spec = {}
    uri = spec.get("uri") or None
    manifest, requires = _read_manifest(library_dir)
    return InstalledLibrary(
        name=name,
        version=version,
        owner=spec.get("owner") or None,
        uri=uri,
        commit=_git_commit(library_dir / ".git") if uri and _is_git_uri(uri) else None,
        spec_name=spec.get("name") or None,
        requires=requires,
        manifest=manifest,
    )


# --- Matching requirements to what was installed ------------------------------------------------


def _parse_spec(entry: str) -> Requirement:
    """A lib_deps entry, in any of the forms PlatformIO accepts.

    `owner/Name@^1.0`, `Name @ 1.0.0`, `Name`, a URL (`#ref` optional), or
    `Name=URL`, which names a library fetched from somewhere else.
    """
    entry = entry.strip()
    if "=" in entry and "://" in entry.split("=", 1)[1] and "://" not in entry.split("=", 1)[0]:
        name, _, uri = entry.partition("=")
        return Requirement(name=name.strip(), spec=uri.strip())
    if "://" in entry or entry.startswith("git@"):
        github = _github_source(entry)
        name = github[1] if github else _strip_vcs_prefix(entry).rstrip("/").rsplit("/", 1)[-1]
        return Requirement(name=name.removesuffix(".git"), spec=entry)
    spec, _, version = entry.partition("@")
    owner, _, name = spec.strip().rpartition("/")
    return Requirement(name=name.strip(), owner=owner.strip() or None, spec=version.strip() or None)


def _normalise_source(uri: str) -> tuple[str, str]:
    """(repository URL, ref) with the spelling differences PlatformIO ignores removed."""
    url, _, ref = uri.partition("#")
    url = url[4:] if url.startswith("git+") else url
    return url.rstrip("/").removesuffix(".git").lower(), ref.strip()


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version.split("+", 1)[0])[:4])


def _satisfies(version: str, requirement: str | None) -> bool:
    """Whether `version` meets a semver requirement as PlatformIO writes them.

    Covers what manifests use in practice: exact and partial versions,
    `^`, `~`, comparisons and comma-separated combinations. Anything else
    is not ruled out, because the installed library is the better witness.
    """
    if not requirement or requirement.strip() in ("*", ""):
        return True
    have = _version_key(version)
    for clause in requirement.split(","):
        clause = clause.strip()
        match = re.match(r"^(\^|~|>=|<=|>|<|==|=|!=)?\s*v?(\d+(?:\.\d+)*)", clause)
        if not match:
            return True
        operator, wanted = match.group(1) or "", tuple(int(p) for p in match.group(2).split("."))
        padded = have + (0,) * max(0, len(wanted) - len(have))
        if operator in ("", "=", "=="):
            ok = padded[: len(wanted)] == wanted
        elif operator == "^":
            fixed = next((i + 1 for i, part in enumerate(wanted) if part), len(wanted))
            ok = padded >= wanted and padded[:fixed] == wanted[:fixed]
        elif operator == "~":
            # ~1.2.3 and ~1.2 hold MAJOR.MINOR; ~1 holds MAJOR.
            fixed = min(2, len(wanted))
            ok = padded >= wanted and padded[:fixed] == wanted[:fixed]
        else:
            ok = {
                ">=": padded >= wanted,
                "<=": padded[: len(wanted)] <= wanted,
                ">": padded > wanted,
                "<": padded < wanted,
                "!=": padded[: len(wanted)] != wanted,
            }[operator]
        if not ok:
            return False
    return True


def _find(installed: list[InstalledLibrary], requirement: Requirement) -> InstalledLibrary | None:
    """The installed library PlatformIO would use for a requirement.

    By source when the requirement names one, otherwise by name -- the
    library's own or the one it was asked for by -- then owner, then the
    highest version meeting the requirement, as PlatformIO picks.
    """
    spec = requirement.spec or ""
    if "://" in spec or spec.startswith("git@"):
        wanted_url, wanted_ref = _normalise_source(spec)
        same = [library for library in installed if library.uri and _normalise_source(library.uri)[0] == wanted_url]
        exact = [library for library in same if not wanted_ref or _normalise_source(str(library.uri))[1] == wanted_ref]
        if exact or same:
            return (exact or same)[0]
        spec = ""
    name = requirement.name.lower()
    candidates = [
        library for library in installed if library.name.lower() == name or (library.spec_name or "").lower() == name
    ]
    if requirement.owner:
        owned = [library for library in candidates if (library.owner or "").lower() == requirement.owner.lower()]
        candidates = owned or [library for library in candidates if library.owner is None]
    if not candidates:
        return None
    meeting = [library for library in candidates if _satisfies(library.version, spec)] or candidates
    return max(meeting, key=lambda library: _version_key(library.version))


# --- Platforms and frameworks -------------------------------------------------------------------

#: PlatformIO repackages some upstreams under its own version scheme:
#: framework-arduinoespressif32 3.20017.x (and 4.20017.x since platform
#: 7) is Arduino-ESP32 2.0.17, and framework-espidf 3.50301.x is ESP-IDF 5.3.1.
_PIO_ENCODED = re.compile(r"^\d+\.(\d)(\d{2})(\d{2})(?:\.\d+)?(?:\+.*)?$")
#: Packages that are an Espressif upstream, by the product name NVD files
#: their vulnerabilities under.
_CPE_PRODUCTS = {
    "framework-arduinoespressif32": "arduino-esp32",
    "framework-espidf": "esp-idf",
}
#: `esp-idf: v5.5.5 b774170ff46` for a release, or
#: `esp-idf: release/v5.5 f2a3fa2b` for a build from a release branch.
_IDF_LINE = re.compile(r"^esp-idf:\s*(release/)?v?(\d+\.\d+(?:\.\d+)?)\b\s*([0-9a-f]{7,40})?", re.MULTILINE)
_INSTALL_TIMESTAMP = re.compile(r"^0\.0\.0\+\d{14}$")


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _upstream_version(name: str, version: str) -> str:
    """The version the upstream project calls this release."""
    if name in _CPE_PRODUCTS and (match := _PIO_ENCODED.match(version)):
        return f"{int(match.group(1))}.{int(match.group(2))}.{int(match.group(3))}"
    return version.split("+", 1)[0].removeprefix("v")


def _read_package(directory: Path, kind: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """(.piopm, platform.json or package.json) for an installed platform or package."""
    try:
        metadata = json.loads((directory / METADATA_FILE).read_text(encoding="utf-8"))
        manifest = json.loads(
            (directory / ("platform.json" if kind == "platform" else "package.json")).read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return None
    if not (isinstance(metadata, dict) and isinstance(manifest, dict) and isinstance(metadata.get("version"), str)):
        return None
    return metadata, manifest


def _installed(
    root: Path | None, name: str, requirement: str | None, kind: str
) -> tuple[Path, dict[str, Any], dict[str, Any]] | None:
    """The installed copy of a platform or package that meets a requirement.

    A URL requirement is met only by what was downloaded from that URL;
    anything else by name and version, the highest version winning.
    """
    if root is None or not root.is_dir():
        return None
    best: tuple[Path, dict[str, Any], dict[str, Any]] | None = None
    for directory in sorted(root.iterdir()):
        if not directory.is_dir() or not (directory.name == name or directory.name.startswith(f"{name}@")):
            continue
        read = _read_package(directory, kind)
        if read is None:
            continue
        metadata, manifest = read
        spec = _mapping(metadata.get("spec"))
        if requirement and ("://" in requirement or requirement.startswith("git@")):
            if not spec.get("uri") or _normalise_source(spec["uri"]) != _normalise_source(requirement):
                continue
        elif not _satisfies(metadata["version"], requirement):
            continue
        if best is None or _version_key(metadata["version"]) > _version_key(best[1]["version"]):
            best = (directory, metadata, manifest)
    return best


def _bundled_idf(directory: Path) -> tuple[str, str | None, str | None] | None:
    """(version, branch, commit) of the ESP-IDF an Arduino-ESP32 package was built against.

    Arduino-ESP32 ships ESP-IDF precompiled, and records which release in a
    versions.txt (`esp-idf: v5.5.5 b774170ff46`) at its root, under
    tools/sdk or tools/esp32-arduino-libs, or per chip. Forks may build
    from a release branch instead (`esp-idf: release/v5.5 f2a3fa2b`).
    """
    for candidate in (
        [directory / "versions.txt"]
        + sorted(directory.glob("*/versions.txt"))
        + sorted(directory.glob("tools/*/versions.txt"))
        + sorted(directory.glob("tools/*/*/versions.txt"))
    ):
        try:
            if match := _IDF_LINE.search(candidate.read_text(encoding="utf-8", errors="replace")):
                branch = f"release/v{match.group(2)}" if match.group(1) else None
                return match.group(2), branch, match.group(3)
        except OSError:
            continue
    return None


def _framework_package(
    directory: Path, metadata: dict[str, Any], manifest: dict[str, Any], kind: str
) -> list[FrameworkPackage]:
    spec = _mapping(metadata.get("spec"))
    name = str(metadata.get("name") or manifest.get("name") or directory.name.split("@", 1)[0])
    version = str(metadata["version"])
    found: list[FrameworkPackage] = []
    cpe_product = None
    if name in _CPE_PRODUCTS:
        cpe_product = (_CPE_PRODUCTS[name], _upstream_version(name, version))
    idf = _bundled_idf(directory) if kind == "framework" and name != "framework-espidf" else None
    if idf:
        idf_version, branch, commit = idf
        # A branch build is identified by its commit. Its CPE names the
        # branch's release line, so advisories against that line still
        # match -- possibly including some the branch has already fixed.
        found.append(
            FrameworkPackage(
                name="esp-idf",
                version=f"{branch}+{commit}" if branch and commit else branch or idf_version,
                kind="framework",
                github=("espressif", "esp-idf", commit if branch and commit else branch or f"v{idf_version}"),
                manifest=Manifest(
                    description=f"ESP-IDF, precompiled into {name}",
                    license="Apache-2.0",
                    repository="https://github.com/espressif/esp-idf",
                ),
                cpe_product=("esp-idf", idf_version),
            )
        )
    found.insert(
        0,
        FrameworkPackage(
            name=name,
            version=version,
            kind=kind,
            owner=spec.get("owner") or None,
            uri=spec.get("uri") or None,
            manifest=_json_manifest(manifest),
            cpe_product=cpe_product,
            bundles=tuple(package.purl for package in found),
        ),
    )
    return found


def _platform_requirement(value: str) -> tuple[str, str | None]:
    """(platform name, requirement) from an env's `platform` option."""
    value = value.strip()
    if "://" in value or value.startswith("git@"):
        return "", value
    spec, _, version = value.partition("@")
    return spec.strip().rpartition("/")[2], version.strip() or None


def _package_overrides(config: ProjectConfig, section: str, packages_dir: Path | None) -> dict[str, str | None]:
    """An env's `platform_packages`: package name -> the version or URL to use instead.

    `name @ spec` names the package; a bare URL is matched to the package
    that was installed from it.
    """
    overrides: dict[str, str | None] = {}
    for entry in config.get_list(section, "platform_packages"):
        if "${" in entry:
            continue
        head, _, spec = entry.partition("@")
        if "://" not in head and not head.startswith("git"):
            overrides[head.strip().rpartition("/")[2]] = spec.strip() or None
            continue
        if packages_dir is None or not packages_dir.is_dir():
            continue
        for directory in sorted(packages_dir.iterdir()):
            try:
                metadata = json.loads((directory / METADATA_FILE).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            uri = _mapping(_mapping(metadata).get("spec")).get("uri")
            if uri and _normalise_source(str(uri)) == _normalise_source(entry):
                overrides[str(metadata.get("name") or directory.name.split("@", 1)[0])] = entry
    return overrides


def _local_libraries(config: ProjectConfig, section: str) -> set[str]:
    """Names of the project's own libraries, in lib_dir and lib_extra_dirs.

    PlatformIO resolves a lib_deps name to one of these before looking at
    what it installed, so naming one is not a missing dependency.
    """
    roots = [config.get_dir("lib_dir")]
    for extra in config.get_list(section, "lib_extra_dirs"):
        path = Path(os.path.expanduser(extra))
        roots.append(path if path.is_absolute() else config.project_dir / path)
    names: set[str] = set()
    for root in roots:
        if root is None or not root.is_dir():
            continue
        for directory in root.iterdir():
            if directory.is_dir():
                names.add(directory.name.lower())
                try:
                    declared = json.loads((directory / "library.json").read_text(encoding="utf-8")).get("name")
                    if isinstance(declared, str):
                        names.add(declared.lower())
                except (OSError, ValueError, AttributeError):
                    pass
    return names


def _env_frameworks(config: ProjectConfig, env: str) -> tuple[str, list[FrameworkPackage]]:
    """(platform name, [platform, framework packages...]) one environment builds with.

    The platform is found the way PlatformIO finds it, from the env's
    `platform` option. Which framework packages a build uses is the
    platform's to say: its platform.json maps each framework to a package
    and pins a version (or URL) for it. Companion `-libs` packages -- the
    precompiled ESP-IDF that Arduino-ESP32 3.x links -- come along with it.
    """
    section = f"env:{env}"
    try:
        platform_value = config.get(section, "platform") or ""
    except _Unresolvable:
        return "", []
    if not platform_value or "${" in platform_value:
        return "", []
    name, requirement = _platform_requirement(platform_value)
    platforms_dir = config.get_dir("platforms_dir")
    found = None
    if name:
        found = _installed(platforms_dir, name, requirement, "platform")
    elif platforms_dir is not None and platforms_dir.is_dir():
        for directory in sorted(platforms_dir.iterdir()):
            found = _installed(platforms_dir, directory.name.split("@", 1)[0], requirement, "platform")
            if found:
                break
    if found is None:
        logger.info(f"PlatformIO: platform {platform_value} for env:{env} is not installed; it is left out")
        return name, []
    directory, metadata, platform = found
    platform_name = str(metadata.get("name") or platform.get("name") or name)
    packages: list[FrameworkPackage] = _framework_package(directory, metadata, platform, "platform")[:1]
    declared = _mapping(platform.get("packages"))
    frameworks = _mapping(platform.get("frameworks"))
    packages_dir = config.get_dir("packages_dir")
    overrides = _package_overrides(config, section, packages_dir)
    for framework in config.get_list(section, "framework"):
        entry = _mapping(frameworks.get(framework))
        primary = entry.get("package")
        if primary:
            wanted = [primary] + [
                package for package in declared if package.startswith(f"{primary}-") and package.endswith("-libs")
            ]
        else:
            # Some forks leave the package to their build script; the
            # framework packages named for the framework are the candidates.
            token = framework.replace("-", "").lower()
            wanted = [
                package
                for package, options in declared.items()
                if isinstance(options, dict)
                and options.get("type") == "framework"
                and token in package.replace("-", "").lower()
            ]
        for package in wanted:
            options = _mapping(declared.get(package))
            requirement = options.get("version") if isinstance(options.get("version"), str) else None
            requirement = overrides.get(package, requirement)
            installed = _installed(packages_dir, package, requirement, "framework")
            if installed is None:
                logger.debug(f"PlatformIO: {package} for env:{env} is not installed")
                continue
            packages.extend(_framework_package(*installed, "framework"))
    return platform_name, packages


# --- The project as PlatformIO resolved it ------------------------------------------------------


@dataclass
class Resolution:
    """What a project's built environments resolved to, as one graph."""

    libraries: list[InstalledLibrary] = field(default_factory=list)
    frameworks: list[FrameworkPackage] = field(default_factory=list)
    #: Purls the project depends on directly: lib_deps, platform, frameworks.
    direct: list[str] = field(default_factory=list)
    edges: dict[str, list[str]] = field(default_factory=dict)
    #: Environments read, and those whose libraries were declared but missing.
    environments: list[str] = field(default_factory=list)
    uninstalled: list[str] = field(default_factory=list)


def _built_environments(config: ProjectConfig) -> list[str]:
    """Environments `pio pkg install` or `pio run` was run for.

    Each gets a directory under libdeps (if it has libraries) or build.
    When neither exists, `default_envs` names what a bare `pio run`
    builds. Directories for environments no longer in the configuration
    are left over from an earlier build and are not read.
    """
    envs = config.envs()
    seen: list[str] = []
    for option in ("libdeps_dir", "build_dir"):
        root = config.get_dir(option)
        if root is not None and root.is_dir():
            for directory in sorted(p for p in root.iterdir() if p.is_dir()):
                if directory.name in envs and directory.name not in seen:
                    seen.append(directory.name)
                elif directory.name not in envs and option == "libdeps_dir":
                    logger.debug(f"PlatformIO: {directory.name} is not an environment in {config.path.name}, skipping")
    if not seen:
        seen = [env for env in config.get_list("platformio", "default_envs") if env in envs]
    return seen


def _applies(requirement: Requirement, platform: str, frameworks: list[str]) -> bool:
    if requirement.platforms is not None and platform and platform.lower() not in requirement.platforms:
        return False
    if requirement.frameworks is not None and frameworks:
        return any(framework.lower() in requirement.frameworks for framework in frameworks)
    return True


def resolve(ini_path: Path) -> Resolution:
    """The project's dependency graph, the way `pio pkg list` resolves it.

    Per environment: each lib_deps entry is matched to the library installed
    for it, and each library's manifest dependencies -- the ones that apply
    to the env's platform and framework -- to the library installed beside
    it. What is reachable that way is what the build uses. A library on disk
    that nothing reaches (a test framework, or a copy left behind when a
    requirement changed source) is not part of the firmware.

    If an entry cannot be matched to anything installed, what it resolved
    to is unknown; rather than drop a library the firmware may contain,
    everything in that environment that was not otherwise reached is kept.
    """
    config = ProjectConfig(ini_path)
    resolution = Resolution()
    libdeps = config.get_dir("libdeps_dir")
    by_purl: dict[str, InstalledLibrary] = {}
    frameworks_by_purl: dict[str, FrameworkPackage] = {}
    edges: dict[str, set[str]] = {}
    direct: list[str] = []

    def link(source: str, target: str) -> None:
        edges.setdefault(source, set())
        if target != source:
            edges[source].add(target)

    for env in _built_environments(config):
        resolution.environments.append(env)
        section = f"env:{env}"
        platform, packages = _env_frameworks(config, env)
        framework_names = config.get_list(section, "framework")
        for package in packages:
            frameworks_by_purl.setdefault(package.purl, package)
            if package.kind == "platform" or not any(package.purl in p.bundles for p in packages):
                direct.append(package.purl)
            for bundled in package.bundles:
                link(package.purl, bundled)

        env_dir = libdeps / env if libdeps is not None else None
        installed = []
        if env_dir is not None and env_dir.is_dir():
            installed = [
                library
                for directory in sorted(p for p in env_dir.iterdir() if p.is_dir())
                if (library := _read_metadata(directory)) is not None
            ]
        try:
            entries = config.get_list(section, "lib_deps")
        except (OSError, configparser.Error):
            entries = []
        local = _local_libraries(config, section)
        wanted = [
            entry
            for entry in entries
            if not entry.startswith(("file://", "symlink://", "/", "./", "../", "~"))
            and not ("://" not in entry and _parse_spec(entry).name.lower() in local)
        ]
        if wanted and not installed:
            resolution.uninstalled.append(env)
            continue

        reached: list[InstalledLibrary] = []
        unmatched = []
        for entry in wanted:
            library = None if "${" in entry else _find(installed, _parse_spec(entry))
            if library is None:
                unmatched.append(entry)
                continue
            direct.append(library.purl)
            if library not in reached:
                reached.append(library)

        def walk(start: list[InstalledLibrary]) -> None:
            queue = list(start)
            while queue:
                library = queue.pop(0)
                link(library.purl, library.purl)
                for requirement in library.requires:
                    if not _applies(requirement, platform, framework_names):
                        continue
                    target = _find([other for other in installed if other is not library], requirement)
                    if target is None:
                        continue
                    link(library.purl, target.purl)
                    if target not in reached:
                        reached.append(target)
                        queue.append(target)

        walk(reached)
        if unmatched:
            leftover = [library for library in installed if library not in reached]
            logger.warning(
                f"PlatformIO: env:{env} lib_deps {', '.join(unmatched)} could not be matched to an installed "
                f"library; keeping {len(leftover)} installed but unreached libraries rather than guess"
            )
            reached.extend(leftover)
            walk(leftover)
        for library in reached:
            by_purl.setdefault(library.purl, library)

    resolution.libraries = list(by_purl.values())
    resolution.frameworks = list(frameworks_by_purl.values())
    resolution.direct = list(dict.fromkeys(direct))
    resolution.edges = {source: sorted(targets) for source, targets in edges.items()}
    return resolution


def installed_libraries(ini_path: Path) -> list[InstalledLibrary]:
    """The libraries the project's built environments use, once each.

    Each `[env:...]` gets its own copy under `libdeps/<env>/`, so a library
    shared by three environments is on disk three times. It is one
    component, and "the same" means the same purl -- that is the bom-ref.
    """
    return resolve(ini_path).libraries


def _env_lib_deps(config: ProjectConfig) -> list[str]:
    sections = [f"env:{env}" for env in config.envs()] or ["env"]
    entries: list[str] = []
    for section in sections:
        try:
            value = config.get(section, "lib_deps")
        except _Unresolvable:
            value = config._raw(section, "lib_deps")
        for entry in config.parse_multi_values(value or ""):
            if entry not in entries:
                entries.append(entry)
    return entries


def declared_lib_deps(ini_path: Path) -> list[str]:
    """Every `lib_deps` entry the project's environments end up with.

    Each environment's value is resolved through `extends`, `[env]` and
    interpolation exactly as PlatformIO would. An entry that still contains
    `${...}` referred to something not visible here.
    """
    return _env_lib_deps(ProjectConfig(ini_path))


def _entry_is_pinned(entry: str) -> bool:
    # Interpolation that could not be resolved: unknown, so not pinned.
    if "${" in entry:
        return False
    # A local path or symlink is the project's own code, not a resolution.
    if entry.startswith(("file://", "symlink://")) or entry.startswith(("/", "./", "../", "~")):
        return True
    if "://" in entry or entry.startswith("git@"):
        url, _, ref = entry.partition("#")
        if url.lower().endswith(_ARCHIVE_SUFFIXES):
            # An archive URL names one file.
            return True
        # Anything else is cloned. A git source pins only to a commit or a
        # release-shaped tag; a branch name, or none, follows whatever is
        # pushed next.
        return bool(_IMMUTABLE_REF.match(ref.strip()))
    _, sep, requirement = entry.partition("@")
    return bool(sep) and bool(_EXACT_VERSION.match(requirement.strip()))


def lib_deps_are_pinned(ini_path: Path) -> bool:
    """Whether every declared library names exactly one version.

    The installed set records what one build resolved. Whether the next build
    resolves the same thing depends on this. Unreadable or empty counts as
    not pinned, for the same reason as an unreadable requirements.txt.
    """
    try:
        entries = declared_lib_deps(ini_path)
    except (OSError, configparser.Error):
        return False
    return bool(entries) and all(_entry_is_pinned(entry) for entry in entries)
