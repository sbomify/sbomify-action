"""TeamCity provider for VCS augmentation metadata.

This provider detects when running under JetBrains TeamCity and extracts VCS
information. Unlike GitHub Actions / GitLab CI / Bitbucket Pipelines, TeamCity
exposes almost nothing useful as an environment variable -- only these are
automatic on a build agent:

- TEAMCITY_VERSION: Detection (present when running under TeamCity)
- BUILD_VCS_NUMBER: The VCS revision of the primary VCS root
- TEAMCITY_BUILD_PROPERTIES_FILE: Path to the build properties file

The repository URL (``vcsroot.<VCS_root_ID>.url``) and branch
(``teamcity.build.branch``) are TeamCity *configuration parameters*, not
environment variables. They are reachable only by reading the build properties
file and following its ``teamcity.configuration.properties.file`` key to a
second file holding the configuration parameters.

Resolution order (``sbomify.json``, at priority 10, still beats all of it):

1. The build properties file -- zero configuration, works out of the box.
2. ``SBOMIFY_VCS_URL`` / ``SBOMIFY_VCS_REF`` -- for setups where the properties
   file is not readable, most commonly when the action runs inside a container
   that does not have the agent temp directory mounted.

TeamCity is VCS-agnostic: a VCS root may be Subversion, Perforce, TFVC,
Mercurial, or anything a third-party plugin adds. ``BUILD_VCS_NUMBER`` is a
commit hash only under Git. Because the SBOM VCS fields are Git-shaped end to
end (``git+https://...@sha`` locators), this provider is **default-deny**: it
emits nothing unless something positively identifies the root as Git. See
``_looks_like_git_root``.

Most TeamCity build configurations attach a single VCS root, and that is the
path optimised here: with one root TeamCity emits the bare forms
(``vcsroot.url``, ``BUILD_VCS_NUMBER``, ``build.vcs.number``) and every lookup
below resolves on its first tier. The per-root (``vcsroot.<id>.url``,
``BUILD_VCS_NUMBER_<id>``) handling is a fallback for multi-root builds, where
the bare forms are absent entirely -- it never executes for the common case.

Set DISABLE_VCS_AUGMENTATION=true to disable VCS enrichment.
"""

import os
import re
import stat
from typing import Any, Dict, List, Optional, Tuple

from sbomify_action.logging_config import logger

from ..metadata import AugmentationMetadata
from ..utils import (
    is_scp_like_git_url,
    is_vcs_augmentation_disabled,
    normalize_repo_url,
    strip_ref_prefix,
    truncate_sha,
)

# Real TeamCity properties files are 10-200 KB. 4 MiB is generous while still
# bounding a pathological or hostile file.
_MAX_PROPERTIES_BYTES = 4 * 1024 * 1024
_MAX_PROPERTIES_KEYS = 10_000

# Java .properties line splitting. NOT str.splitlines(): that also splits on
# \f, \v, \x1c, \x1d, \x1e, \x85 and  , none of which Java treats as a
# line terminator, so a value containing one would be silently truncated.
_LINE_SPLIT_RE = re.compile(r"\r\n|\n|\r")

# Java's whitespace set for .properties files (notably excludes \v).
_PROP_WS = " \t\f"

_SIMPLE_ESCAPES = {"t": "\t", "n": "\n", "r": "\r", "f": "\f"}

# ``vcsroot.<VCS_root_ID>.url`` -- the documented form. A bare ``vcsroot.url``
# does not match this and is handled separately.
_VCSROOT_URL_RE = re.compile(r"^vcsroot\.(?P<root_id>.+)\.url$")
_VCS_BRANCH_PREFIX = "teamcity.build.vcs.branch."

# A git commit hash is exactly 40 (SHA-1) or 64 (SHA-256) hex characters.
# Anything shorter would admit an SVN revision or a Perforce changelist, which
# are decimal and therefore also valid hex -- SVN repositories routinely pass
# revision 1,000,000, so a "7 to 64 hex chars" rule accepts exactly the values
# it was meant to exclude.
_COMMIT_SHA_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")

# TeamCity's placeholder for a build on the default branch of a VCS root that
# has a branch specification configured. See JetBrains YouTrack TW-23699. With
# no branch specification the parameter is absent instead -- verified on
# 2024.12.3 through 2026.1.3 -- so both shapes have to be handled.
_DEFAULT_BRANCH_PLACEHOLDER = "<default>"


def _decode_properties_bytes(raw: bytes) -> str:
    """
    Decode a Java .properties byte stream.

    The Java specification says ISO-8859-1 with ``\\uXXXX`` escapes, but
    TeamCity writes UTF-8. Try UTF-8 first and fall back to latin-1, which
    decodes any byte sequence and therefore cannot raise -- a stray non-UTF-8
    byte in an unrelated parameter must never cost us the whole file.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _merge_surrogates(chars: List[str]) -> str:
    """
    Combine ``\\uD83D\\uDE00`` surrogate pairs and drop unpaired surrogates.

    ``chr(0xD800)`` is a legal element of a Python str but cannot be encoded to
    UTF-8, so leaving one in a value would raise much later during SBOM
    serialization. Normalize here, at the parsing boundary.
    """
    out: List[str] = []
    i = 0
    while i < len(chars):
        code = ord(chars[i])
        if 0xD800 <= code <= 0xDBFF and i + 1 < len(chars) and 0xDC00 <= ord(chars[i + 1]) <= 0xDFFF:
            out.append(chr(0x10000 + ((code - 0xD800) << 10) + (ord(chars[i + 1]) - 0xDC00)))
            i += 2
            continue
        if 0xD800 <= code <= 0xDFFF:
            i += 1  # unpaired surrogate -> drop
            continue
        out.append(chars[i])
        i += 1
    return "".join(out)


def _unescape(text: str) -> str:
    """
    Apply Java .properties escape rules to a key or value fragment.

    ``\\t \\n \\r \\f`` become control characters, ``\\uXXXX`` becomes a code
    point, and any other backslash pair drops the backslash (``\\:`` -> ``:``,
    ``\\=`` -> ``=``, ``\\\\`` -> ``\\``). A trailing lone backslash is dropped.

    Deviation from ``java.util.Properties``: a malformed ``\\uXY`` degrades to
    the literal ``u`` rather than throwing, so one bad parameter cannot cost us
    the file.
    """
    out: List[str] = []
    i, n = 0, len(text)
    saw_surrogate = False
    while i < n:
        char = text[i]
        if char != "\\":
            out.append(char)
            i += 1
            continue
        i += 1
        if i >= n:
            break  # trailing lone backslash
        esc = text[i]
        i += 1
        if esc == "u":
            digits = text[i : i + 4]
            if len(digits) == 4 and all(d in "0123456789abcdefABCDEF" for d in digits):
                code = int(digits, 16)
                i += 4
                if 0xD800 <= code <= 0xDFFF:
                    saw_surrogate = True
                out.append(chr(code))
            else:
                out.append("u")
        else:
            out.append(_SIMPLE_ESCAPES.get(esc, esc))
    return _merge_surrogates(out) if saw_surrogate else "".join(out)


def _split_key_value(logical_line: str) -> Tuple[str, str]:
    """
    Split one logical line into ``(key, value)`` per the Java rules.

    The key ends at the first *unescaped* ``=``, ``:`` or whitespace run. If a
    whitespace run is followed by ``=`` or ``:``, that character is the
    separator and the surrounding whitespace is discarded. Whitespace after the
    separator is discarded; trailing whitespace in the value is preserved, as
    Java does.
    """
    i, n = 0, len(logical_line)
    key: List[str] = []
    while i < n:
        char = logical_line[i]
        if char == "\\":
            # Keep the escape pair intact so _unescape sees it.
            key.append(char)
            if i + 1 < n:
                key.append(logical_line[i + 1])
                i += 2
            else:
                i += 1
            continue
        if char in "=:":
            i += 1
            break
        if char in _PROP_WS:
            j = i
            while j < n and logical_line[j] in _PROP_WS:
                j += 1
            if j < n and logical_line[j] in "=:":
                j += 1
            i = j
            break
        key.append(char)
        i += 1
    while i < n and logical_line[i] in _PROP_WS:
        i += 1
    return _unescape("".join(key)), _unescape(logical_line[i:])


def _parse_java_properties(text: str, max_keys: int = _MAX_PROPERTIES_KEYS) -> Dict[str, str]:
    """
    Parse Java .properties text into a dict.

    Implements ``java.util.Properties.load`` semantics: ``#``/``!`` comments,
    ``=``/``:``/whitespace separators, backslash line continuations (an odd
    number of trailing backslashes), leading-whitespace trimming, and escapes.
    Later duplicate keys win, matching Java.

    Deviation: a blank continuation line terminates the logical line, where
    Java's LineReader keeps reading. This does not occur in TeamCity-generated
    files.

    Never logs the parsed content -- these files contain plaintext passwords
    for unrelated build parameters on many TeamCity versions.
    """
    props: Dict[str, str] = {}
    buffer: List[str] = []
    for raw_line in _LINE_SPLIT_RE.split(text):
        line = raw_line.lstrip(_PROP_WS)
        if not buffer:
            # Comment detection applies only to the first natural line of a
            # logical line; a comment ending in '\' does NOT continue.
            if not line or line[0] in "#!":
                continue
        trailing_backslashes = len(line) - len(line.rstrip("\\"))
        if trailing_backslashes % 2 == 1:
            buffer.append(line[:-1])
            continue
        buffer.append(line)
        logical = "".join(buffer)
        buffer = []
        if not logical:
            continue
        key, value = _split_key_value(logical)
        if key:
            props[key] = value
            if len(props) >= max_keys:
                logger.warning(f"TeamCity properties file exceeded {max_keys} keys; stopping parse")
                return props
    if buffer:  # file ended mid-continuation
        logical = "".join(buffer)
        if logical:
            key, value = _split_key_value(logical)
            if key:
                props[key] = value
    return props


def _read_properties_file(path: str, label: str = "build") -> Dict[str, str]:
    """
    Read and parse a TeamCity properties file, degrading to ``{}`` on any problem.

    Opened with ``O_NONBLOCK`` and checked with ``fstat``/``S_ISREG`` before
    reading: ``open()`` on a FIFO with no writer blocks forever, which would
    hang the build. Doing the stat on the descriptor rather than the path also
    closes the stat/open TOCTOU window.

    Symlinks are deliberately followed -- the agent temp directory is
    legitimately symlinked on macOS (``/var`` -> ``/private/var``) and inside
    Docker mounts, so ``O_NOFOLLOW`` would break real setups. The ``S_ISREG``
    check on the resolved target is the meaningful guard.
    """
    fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            logger.debug(f"TeamCity {label} properties path is not a regular file; ignoring")
            return {}
        if file_stat.st_size > _MAX_PROPERTIES_BYTES:
            # Refuse the whole file rather than parse a truncated tail, which
            # could yield a corrupted URL.
            logger.warning(
                f"TeamCity {label} properties file is {file_stat.st_size} bytes (cap {_MAX_PROPERTIES_BYTES}); ignoring"
            )
            return {}
        with os.fdopen(fd, "rb", closefd=True) as handle:
            fd = -1
            raw = handle.read(_MAX_PROPERTIES_BYTES + 1)
    except (OSError, ValueError):
        # Missing, unreadable, or a path we cannot open. A container build
        # without the agent temp dir mounted is a normal setup, not an error.
        logger.debug(f"Could not read TeamCity {label} properties file")
        return {}
    finally:
        if fd != -1:
            os.close(fd)

    if len(raw) > _MAX_PROPERTIES_BYTES:
        logger.warning(f"TeamCity {label} properties file exceeded size cap while reading; ignoring")
        return {}
    return _parse_java_properties(_decode_properties_bytes(raw))


def _load_teamcity_properties() -> Dict[str, str]:
    """
    Load the build properties, overlaid with the configuration parameters.

    ``TEAMCITY_BUILD_PROPERTIES_FILE`` holds the build system properties. The
    configuration parameters we actually need (``vcsroot.*``,
    ``teamcity.build.branch``) live in a second file named by the
    ``teamcity.configuration.properties.file`` key inside it. Exactly one hop
    is followed; further references are never chased.

    Note on the threat model: whoever controls the first file could already set
    ``vcsroot.url`` directly, so following the chained reference grants no new
    capability. The guards in :func:`_read_properties_file` are about
    availability and disclosure, not path confinement.
    """
    build_path = os.getenv("TEAMCITY_BUILD_PROPERTIES_FILE")
    if not build_path:
        return {}

    props = _read_properties_file(build_path, label="build")
    config_path = props.get("teamcity.configuration.properties.file")
    if not config_path or not os.path.isabs(config_path):
        return props

    try:
        if os.path.realpath(config_path) == os.path.realpath(build_path):
            return props  # self-referential file is a non-event
    except OSError:
        return props

    config_props = _read_properties_file(config_path, label="configuration")
    # Configuration parameters win: vcsroot.* and teamcity.build.branch are
    # configuration parameters, not system properties.
    return {**props, **config_props}


def _select_repo_url(props: Dict[str, str]) -> Tuple[Optional[str], Optional[str], bool]:
    """
    Choose the VCS root URL from the properties.

    Returns ``(root_id, raw_url, ambiguous)``. ``root_id`` is None when the bare
    ``vcsroot.url`` form was used. ``ambiguous`` is True when the build has
    several VCS roots and one was picked arbitrarily -- callers must then refuse
    any revision or branch that is not scoped to that same root, or they would
    pin one repository's URL to another's commit.

    The documented form is ``vcsroot.<VCS_root_ID>.url``, so the multi-root
    scan is the main path rather than an edge case. A bare ``vcsroot.url`` is
    checked first opportunistically but is undocumented, so nothing depends on
    it.
    """
    if bare := props.get("vcsroot.url"):
        return None, bare, False

    candidates: List[Tuple[str, str]] = []
    for key, value in props.items():
        if not value:
            continue
        if match := _VCSROOT_URL_RE.match(key):
            candidates.append((match.group("root_id"), value))

    if not candidates:
        return None, None, False

    # Deterministic regardless of dict ordering.
    candidates.sort(key=lambda item: (item[0].lower(), item[0]))
    root_id, url = candidates[0]
    if len(candidates) > 1:
        logger.warning(
            f"TeamCity build has {len(candidates)} VCS roots; using '{root_id}'. "
            f"Set vcs_url in sbomify.json or SBOMIFY_VCS_URL to choose explicitly."
        )
    return root_id, url, len(candidates) > 1


def _select_ref(props: Dict[str, str], root_id: Optional[str], ambiguous: bool = False) -> Optional[str]:
    """
    Choose the branch/ref from the properties.

    ``teamcity.build.branch`` is preferred, but on the default branch it never
    carries the real name: with a branch specification configured TeamCity sets
    it to the literal ``<default>`` (YouTrack TW-23699), and with none
    configured it is absent altogether. Either way the real ref is usually
    still in ``teamcity.build.vcs.branch.<VCS_root_ID>``, which the next tier
    reads -- the placeholder is rejected here so that it falls through to it.
    """
    branch = props.get("teamcity.build.branch")
    if branch and branch != _DEFAULT_BRANCH_PLACEHOLDER:
        return branch

    if root_id and (scoped := props.get(f"{_VCS_BRANCH_PREFIX}{root_id}")):
        return scoped

    if ambiguous:
        # Several roots: a lone teamcity.build.vcs.branch.* almost certainly
        # belongs to a different root than the URL we chose.
        return None

    vcs_branches = [value for key, value in props.items() if key.startswith(_VCS_BRANCH_PREFIX) and value]
    if len(vcs_branches) == 1:
        return vcs_branches[0]
    return None


def _normalize_root_id_for_env(root_id: str) -> str:
    """Upper/underscored form of a VCS root ID.

    Kept only as a defensive fallback. Measured behaviour on TeamCity
    2024.12-2026.1 is that the suffix is the VERBATIM root id
    (``BUILD_VCS_NUMBER_ProbeRoot``), so the verbatim lookup is tried first.
    """
    return re.sub(r"[^A-Z0-9]", "_", root_id.upper())


def _select_commit_sha(props: Dict[str, str], root_id: Optional[str], ambiguous: bool = False) -> Optional[str]:
    """
    Choose the commit SHA, or None when it cannot be established unambiguously.

    Measured on TeamCity 2024.12-2026.1: in a single-root build the bare
    ``BUILD_VCS_NUMBER`` exists; in a multi-root build it does NOT, and only
    ``BUILD_VCS_NUMBER_<root id>`` is exported -- using the **verbatim** root
    id, e.g. ``BUILD_VCS_NUMBER_ProbeRoot``. The same holds for the
    ``build.vcs.number[.<id>]`` configuration parameters.

    Never guesses between multiple roots: pinning the wrong repository's
    revision is worse than recording no revision at all.

    The result is validated as exactly 40 or 64 hex characters. Under a non-Git
    VCS this variable holds a revision number, changelist, or timestamp -- an
    SVN revision such as "1234567" is valid hex and would pass a looser rule.
    """
    # When several roots exist the bare BUILD_VCS_NUMBER is the *primary*
    # root's revision, which need not be the root we picked, so it is only
    # trusted for an unambiguous choice.
    candidate = None if ambiguous else os.getenv("BUILD_VCS_NUMBER")

    if not candidate and root_id:
        # Verbatim first: this is what TeamCity actually exports.
        candidate = os.getenv(f"BUILD_VCS_NUMBER_{root_id}") or os.getenv(
            f"BUILD_VCS_NUMBER_{_normalize_root_id_for_env(root_id)}"
        )
        if not candidate:
            candidate = props.get(f"build.vcs.number.{root_id}")

    if not candidate and not ambiguous:
        candidate = props.get("build.vcs.number")

    if not candidate and ambiguous:
        logger.warning(
            "TeamCity build has several VCS roots and no revision scoped to the chosen "
            "root; omitting the commit SHA rather than pinning another repository's "
            "revision. Set vcs_commit_sha in sbomify.json to record it explicitly."
        )
        return None

    if not candidate:
        scoped = {key: value for key, value in os.environ.items() if key.startswith("BUILD_VCS_NUMBER_") and value}
        if len(scoped) == 1:
            candidate = next(iter(scoped.values()))
        elif len(scoped) > 1:
            logger.warning(
                "TeamCity exposes several BUILD_VCS_NUMBER_* values and none matches the "
                "chosen VCS root; omitting the commit SHA. Set vcs_commit_sha in sbomify.json "
                "to record it explicitly."
            )
            return None

    if not candidate:
        return None

    candidate = candidate.strip()
    if not _COMMIT_SHA_RE.match(candidate):
        logger.debug("TeamCity VCS revision is not a git commit hash; omitting the commit SHA")
        return None
    return candidate


def _url_looks_like_git(raw_url: str, normalized_url: Optional[str]) -> bool:
    """Check whether the URL itself positively identifies a Git remote.

    Callers must only treat this as confirmation when ``normalized_url`` is
    also set: a URL we cannot normalize gives us nothing to attest, so claiming
    Git for it would emit a record with a revision and no repository.
    """
    candidate = raw_url.strip().rstrip("/")
    if candidate.lower().endswith(".git"):
        return True
    lowered = candidate.lower()
    # Explicit transports only. A bare "git+" prefix would also match
    # git+svn:// and git+file://, which are not Git -- and which
    # normalize_repo_url rejects, so accepting them here would leave the
    # provider "confirmed Git" with no URL to attest.
    if lowered.startswith(("ssh://", "git://", "git+ssh://", "git+https://", "git+http://")):
        return True
    # scp shorthand (git@host:org/repo) is a git-specific convention. Uses the
    # same predicate as the normalizer, so the two cannot disagree -- otherwise
    # a string accepted here but rejected there leaves the provider "confirmed
    # Git" with no URL.
    if is_scp_like_git_url(candidate):
        return True

    if normalized_url:
        try:
            from sbomify_action._enrichment.sanitization import _is_known_git_host

            if _is_known_git_host(normalized_url):
                return True
        except ImportError:  # pragma: no cover - defensive
            return False
    return False


def _looks_like_git_root(raw_url: Optional[str], normalized_url: Optional[str]) -> bool:
    """
    Decide whether the chosen VCS root is positively identifiable as Git.

    TeamCity's VCS support is plugin-extensible, so the set of non-Git types is
    open-ended and cannot be enumerated for rejection. The only sound posture is
    default-deny: emit nothing unless something says "this is Git".

    **TeamCity exposes no VCS-type information whatsoever.** Verified on
    2024.12.3, 2025.03.3, 2025.07.3, 2025.11.7 and 2026.1.3 with a real Git
    checkout: there is no ``vcsroot.<id>.type`` parameter, and a root created
    with only url+branch exposes *only* ``vcsroot.<id>.url`` and
    ``vcsroot.<id>.branch`` -- git-plugin properties such as ``usernameStyle``
    appear only when explicitly configured, so their presence cannot be used as
    a marker either.

    That is why this function takes only the URL: there is nothing else in the
    build properties for it to consult. A revision's
    *shape* is deliberately not a signal: Fossil and Monotone also produce
    40/64-hex content hashes, so hex length narrows the field without ever
    proving Git. It gates the SHA only, in :func:`_select_commit_sha`.

    Consequence, documented in the README: a self-hosted Git server whose URL
    has no ``.git`` suffix and is not on a known host cannot be auto-detected;
    those users set ``SBOMIFY_VCS_URL`` or ``sbomify.json``.
    """
    # normalized_url is required: Git is only confirmed for a URL we can
    # actually record. Without it there is nothing to attest, and a bogus
    # confirmation would emit a commit SHA attached to no repository.
    if raw_url and normalized_url and _url_looks_like_git(raw_url, normalized_url):
        return True
    return False


class TeamCityProvider:
    """
    Provider that extracts VCS metadata from a TeamCity build.

    This provider has priority 20, which is lower than sbomify.json (10),
    allowing local config to override auto-detected values.
    """

    name: str = "teamcity"
    priority: int = 20

    def fetch(
        self,
        component_id: Optional[str] = None,
        api_base_url: Optional[str] = None,
        token: Optional[str] = None,
        config_path: Optional[str] = None,
        **kwargs: Any,
    ) -> Optional[AugmentationMetadata]:
        """
        Extract VCS metadata from the TeamCity build environment.

        Args:
            component_id: Ignored (not needed for CI provider)
            api_base_url: Ignored (not needed for CI provider)
            token: Ignored (not needed for CI provider)
            config_path: Ignored (not needed for CI provider)
            **kwargs: Additional arguments (ignored)

        Returns:
            AugmentationMetadata with VCS info if running under TeamCity against
            a Git VCS root, None otherwise
        """
        if is_vcs_augmentation_disabled():
            logger.debug("VCS augmentation disabled, skipping TeamCity provider")
            return None

        # Presence check, like Bitbucket's BITBUCKET_PIPELINE_UUID -- TeamCity
        # has no "true"-valued flag of its own. Tested with ``is None`` rather
        # than truthiness so that this agrees with ``console.IS_TEAMCITY``,
        # which gates traceback locals: one environment must not be TeamCity
        # for the logger and not-TeamCity for the provider.
        if os.getenv("TEAMCITY_VERSION") is None:
            return None

        props = _load_teamcity_properties()

        root_id, raw_url, ambiguous = _select_repo_url(props)
        vcs_url = normalize_repo_url(raw_url) if raw_url else None
        git_confirmed = _looks_like_git_root(raw_url, vcs_url)

        if not git_confirmed:
            # Fallback tier. An explicitly configured URL is an operator
            # assertion and is honoured without a Git signal, exactly as
            # sbomify.json is. This must trigger whenever Git could not be
            # confirmed -- not merely when no URL was found -- because the
            # documented case is a self-hosted root such as
            # https://git.example.com/team/app, which normalizes perfectly well
            # yet cannot be recognised as Git.
            if operator_url := normalize_repo_url(os.getenv("SBOMIFY_VCS_URL")):
                vcs_url = operator_url
                git_confirmed = True

        if not git_confirmed:
            logger.debug(
                "TeamCity detected but the VCS root is not identifiable as Git; "
                "skipping VCS augmentation. Set vcs_url in sbomify.json or "
                "SBOMIFY_VCS_URL to record it explicitly."
            )
            return None

        ref = strip_ref_prefix(_select_ref(props, root_id, ambiguous) or os.getenv("SBOMIFY_VCS_REF"))
        commit_sha = _select_commit_sha(props, root_id, ambiguous)

        # Past the gate a URL is guaranteed: Git is confirmed either from a
        # root URL that normalized cleanly, or from an operator-supplied one.
        logger.info(f"Detected TeamCity: {vcs_url} @ {truncate_sha(commit_sha)}")

        # vcs_commit_url is deliberately None: TeamCity is host-agnostic, so the
        # commit path shape (/commit/, /-/commit/, /commits/) is unknowable here
        # and guessing wrong is worse than omitting.
        #
        # Default to ``pre-build`` -- see GitHubActionsProvider for the full
        # CycloneDX 1.7 schema rationale. The docker-image augmentation
        # overrides to ``post-build`` for built artifacts, and ``json_config``
        # (priority 10) beats this provider for operator overrides.
        return AugmentationMetadata(
            source=self.name,
            vcs_url=vcs_url,
            vcs_commit_sha=commit_sha,
            vcs_ref=ref,
            vcs_commit_url=None,
            lifecycle_phase="pre-build",
        )
