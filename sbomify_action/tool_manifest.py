"""Read the pinned external-tool manifest.

``tools.toml`` is the only place that records what version of an external
tool we depend on, where it comes from, and what it must hash to. Everything
else -- the runtime fetcher, the version auditor, the SBOM package lists and
the Dockerfile consistency test -- reads from here.

The ``stage`` field is what makes this more than tidiness. Once some tools
ship in the image and others are fetched on first use, the build SBOM and the
runtime SBOM legitimately describe different sets of software, and the split
has to be recorded somewhere that both can agree on.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_MANIFEST = Path(__file__).with_name("tools.toml")

#: Where the bundles come from. Only the release moves; the file names inside
#: it follow from the bundle and the architecture.
_BUNDLE_BASE = "https://github.com/sbomify/sbom-tools/releases/download"
_ARCH_SLUGS = {"amd64": "linux-amd64", "arm64": "linux-arm64"}

#: Where our own tool builds are published. Master replaces the assets on this
#: rolling pre-release on every push; the image build stamps a release tag in
#: its place, so a cut release fetches the binaries it was built against.
TOOLS_RELEASE = "tools-rolling"
_TOOLS_RELEASE_BASE = "https://github.com/sbomify/sbomify-action/releases/download"
_ARCH_SLUGS = {"amd64": "linux-amd64", "arm64": "linux-arm64"}


def _built_assets(name: str, release: str) -> dict[str, list[ToolAsset]]:
    """Derive where to fetch a tool we compile ourselves.

    build-tools.yml emits one bare binary per architecture under a fixed name,
    so the URL follows from the tool and the release and there is nothing to
    restate. Repeating our own URLs and digests here is exactly the
    duplication this manifest exists to remove.

    Carrying no digest is not a weakening. The Sigstore bundle holds the
    subject digest inside the signed statement, so verifying the bundle
    against the file checks a digest that was *signed*, rather than one typed
    into this file and trusted because it is written down.
    """
    return {
        arch: [
            ToolAsset(
                url=f"{_TOOLS_RELEASE_BASE}/{release}/{name}-{slug}",
                algorithm="none",
                digest="",
                attestation=f"{_TOOLS_RELEASE_BASE}/{release}/{name}-{slug}.sigstore.json",
            )
        ]
        for arch, slug in _ARCH_SLUGS.items()
    }


_REPO_ROOT = Path(__file__).resolve().parent.parent


def _version_from_go_mod(path: Path, module: str) -> str:
    """Read a module's pinned version out of go.mod.

    Parsed rather than shelled out to `go list` so this works in the published
    image, which has no Go toolchain.
    """
    pattern = re.compile(rf"^\s*{re.escape(module)}\s+(v\S+)", re.M)
    match = pattern.search(path.read_text())
    if not match:
        raise ManifestError(f"{module} not found in {path}")
    return match.group(1).lstrip("v")


def _version_from_go_toolchain(path: Path) -> str:
    """Read the Go toolchain version out of go.mod.

    The ``toolchain`` directive, not ``go``: the latter is the *minimum* the
    module graph builds with, so following it would pin us to the oldest Go
    that works rather than the one we build with. Go's own resolution order is
    followed -- ``toolchain`` when present, ``go`` otherwise.
    """
    text = path.read_text()
    for pattern in (r"^toolchain\s+go(\S+)", r"^go\s+(\S+)"):
        if match := re.search(pattern, text, re.M):
            return match.group(1)
    raise ManifestError(f"{path} has neither a toolchain nor a go directive")


def _version_from_gradle(path: Path, coordinate: str) -> str:
    """Read a pinned classpath coordinate out of a build.gradle.

    Matched rather than parsed: evaluating Groovy to read one version would
    mean shipping Gradle to do it. The line is a literal by construction --
    it has to be, or Dependabot could not rewrite it either.
    """
    pattern = re.compile(rf"""["']{re.escape(coordinate)}:([^"':]+)["']""")
    match = pattern.search(path.read_text())
    if not match:
        raise ManifestError(f"{coordinate} not found in {path}")
    return match.group(1)


def _version_from_toml_lock(path: Path, package: str) -> str:
    """Read a package's pinned version out of Cargo.lock or uv.lock.

    Both are TOML with the same ``[[package]] name/version`` shape.
    """
    data = tomllib.loads(path.read_text())
    for entry in data.get("package", []):
        if entry.get("name") == package:
            return str(entry["version"])
    raise ManifestError(f"{package} not found in {path}")


def _version_from_rust_toolchain(path: Path) -> str:
    """Read the toolchain version out of rust-toolchain.toml."""
    channel = str((tomllib.loads(path.read_text()).get("toolchain") or {}).get("channel", ""))
    if not channel:
        raise ManifestError(f"{path} has no [toolchain] channel")
    if not re.fullmatch(r"\d+\.\d+(\.\d+)?", channel):
        # "stable" resolves to a different toolchain over time, so the image
        # would stop matching the version its own SBOM claims.
        raise ManifestError(f"{path}: channel must be an exact version, got {channel!r}")
    return channel


def _version_from_bun_lock(path: Path, package: str) -> str:
    """Read a package's pinned version out of bun.lock.

    Matched rather than parsed: bun.lock is JSONC, which tomllib and json both
    reject. Entries look like

        "@cyclonedx/cdxgen": ["@cyclonedx/cdxgen@12.8.2", "", {...}, "sha512-..."],

    A specifier that is not a released version is refused. cdxgen was tracked
    as ``github:cyclonedx/cdxgen#cc0c694`` -- a moving branch -- while the
    manifest advertised ``pkg:npm/%40cyclonedx/cdxgen@12.8.2``, so the PURL
    named a release nobody was running.
    """
    pattern = re.compile(rf'"{re.escape(package)}":\s*\[\s*"{re.escape(package)}@([^"]+)"')
    match = pattern.search(path.read_text())
    if not match:
        raise ManifestError(f"{package} not found in {path}")
    version = match.group(1)
    if not re.fullmatch(r"\d[\w.+-]*", version):
        raise ManifestError(
            f"{package} in {path} resolves to {version!r}, which is not a released version. "
            "Pin a published release, or the PURL will name something we do not ship."
        )
    return version


def _version_from_pom(path: Path, artifact: str) -> str:
    """Read a dependency's pinned version out of a pom.xml.

    Prefers defusedxml, but falls back to the stdlib parser: this module is
    imported by scripts that CI runs outside the project virtualenv, and a
    missing hardening library must not stop the build. The fallback is
    acceptable here specifically -- the file is tools/pom.xml from our own
    repository, and ElementTree does not expand external entities at all.
    """
    try:
        from defusedxml import ElementTree
    except ModuleNotFoundError:  # pragma: no cover - depends on the environment
        from xml.etree import ElementTree  # type: ignore[no-redef]  # noqa: S405

    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    root = ElementTree.parse(path).getroot()
    if root is None:
        raise ManifestError(f"{path} has no root element")
    for dep in root.findall(".//m:dependency", ns):
        found = dep.find("m:artifactId", ns)
        version = dep.find("m:version", ns)
        if found is not None and found.text == artifact and version is not None and version.text:
            return version.text
    raise ManifestError(f"{artifact} not found in {path}")


#: How to read a version out of each lockfile we understand, keyed by file
#: name. Dispatching on the file rather than on which key the entry happens to
#: carry keeps this unambiguous now that "package" means something in three
#: different formats.
_LOCKFILE_READERS: dict[str, Callable[[Path, dict[str, object]], str]] = {
    # A go.mod entry naming a module pins that tool; naming none pins the
    # toolchain itself.
    "go.mod": lambda p, s: (
        _version_from_go_mod(p, str(s["module"])) if "module" in s else _version_from_go_toolchain(p)
    ),
    "Cargo.lock": lambda p, s: _version_from_toml_lock(p, str(s["package"])),
    "uv.lock": lambda p, s: _version_from_toml_lock(p, str(s["package"])),
    "bun.lock": lambda p, s: _version_from_bun_lock(p, str(s["package"])),
    "pom.xml": lambda p, s: _version_from_pom(p, str(s["artifact"])),
    "build.gradle": lambda p, s: _version_from_gradle(p, str(s["coordinate"])),
    "rust-toolchain.toml": lambda p, _s: _version_from_rust_toolchain(p),
}


def plugin_version(name: str) -> str:
    """The pinned version of a build-system plugin.

    The JVM plugins are not tools we install: Maven, Gradle and sbt fetch them
    themselves, so they have no bundle. They still have to be pinned where a
    bot can see them, which is tools/pom.xml and tools/build.gradle --
    restating them as literals in Python would put them out of Dependabot's
    reach, the same drift this manifest exists to stop.

    Those files are not part of the Python package, so reading them directly
    worked from a checkout and raised inside the image, where the path
    resolves under site-packages. They go through [plugin.*] in tools.toml for
    the same reason [tool.*] entries do: the image build freezes them into
    literals before the wheel is built, and the shipped manifest carries the
    versions the release was built against.
    """
    try:
        raw = tomllib.loads(_MANIFEST.read_text())
    except FileNotFoundError as exc:  # pragma: no cover - packaging error
        raise ManifestError(f"Tool manifest not found at {_MANIFEST}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"Tool manifest is not valid TOML: {exc}") from exc
    plugins = raw.get("plugin") or {}
    assert isinstance(plugins, dict)
    body = plugins.get(name)
    if body is None:
        raise ManifestError(f"unknown plugin {name!r}; known: {', '.join(sorted(plugins))}")
    assert isinstance(body, dict)
    return _resolve_version(name, body)


def _resolve_version(name: str, body: dict[str, object]) -> str:
    """Take the version from the ecosystem's own lockfile where one owns it.

    Restating versions in this file would put them out of Dependabot's reach
    and create a second place to bump -- which is exactly the drift this
    manifest exists to stop. Only tools with no native manifest carry a
    literal `version` here, and the JDK is the last of them: Temurin is not
    published to Maven Central or anywhere else a lockfile can reach.
    """
    if "version" in body:
        return str(body["version"])

    source = body.get("version_from")
    assert source is None or isinstance(source, dict)
    if not source:
        raise ManifestError(f"{name}: needs either version or version_from")

    path = _REPO_ROOT / source["file"]
    if not path.exists():
        raise ManifestError(f"{name}: {source['file']} not found (looked in {path})")

    reader = _LOCKFILE_READERS.get(path.name)
    if reader is None:
        raise ManifestError(f"{name}: no reader for {path.name}; known: {', '.join(sorted(_LOCKFILE_READERS))}")
    try:
        return reader(path, source)
    except KeyError as exc:
        raise ManifestError(f"{name}: version_from for {path.name} is missing {exc}") from exc


#: Tools baked into the published container image.
STAGE_IMAGE = "image"
#: Tools fetched on first use and verified against a pinned digest.
STAGE_RUNTIME = "runtime"
#: Tools used to build the image but not shipped inside it.
STAGE_BUILD = "build"

_STAGES = (STAGE_IMAGE, STAGE_RUNTIME, STAGE_BUILD)


#: Digest algorithms we accept, in the order we prefer them. Vendors differ:
#: Adoptium and go.dev publish sha256, Apache publishes only sha512. Taking
#: whichever the vendor actually signs beats re-hashing a download ourselves
#: and asking everyone to trust our arithmetic.
DIGEST_ALGORITHMS = ("sha256", "sha512")


@dataclass(frozen=True)
class ToolAsset:
    """A downloadable artifact and the digest it must have."""

    url: str
    algorithm: str
    digest: str
    #: Sigstore bundle proving this artifact was built by our own workflow.
    #: Only our builds have one; upstream vendor downloads do not. Carries no
    #: digest of its own on purpose -- its integrity is established by the
    #: signature and certificate chain, and pinning it would break the
    #: rolling pre-release, whose bundle changes on every build.
    attestation: str | None = None

    @property
    def sha256(self) -> str | None:
        return self.digest if self.algorithm == "sha256" else None


@dataclass(frozen=True)
class Tool:
    """One pinned external dependency."""

    name: str
    version: str
    stage: str
    purl: str
    github_repo: str | None = None
    dockerfile_arg: str | None = None
    kind: str = "raw"
    member: str | None = None
    #: Archives that wrap everything in a single versioned top-level directory
    #: (jdk-21.0.12+8/, apache-maven-3.9.9/, go/). Stripping it gives a stable
    #: prefix whose bin/ can go on PATH without the caller knowing the version.
    strip_container: bool = False
    bin_subdir: str = ""
    #: Environment the tool needs, with "{prefix}" substituted at fetch time.
    env: dict[str, str] = field(default_factory=dict)
    #: Rust ships cargo and rustc as separate tarballs that unpack into one
    #: prefix, so an arch can carry more than one artifact.
    rust_dist: bool = False
    #: Compiled by us from a lockfile rather than downloaded from a vendor.
    built: bool = False
    assets: dict[str, list[ToolAsset]] | None = None

    @property
    def package_url(self) -> str:
        """The PURL for this tool at its pinned version."""
        return self.purl.format(version=self.version)

    @property
    def is_fetched_at_runtime(self) -> bool:
        return self.stage == STAGE_RUNTIME

    @property
    def ships_in_image(self) -> bool:
        """Whether a pull of the image contains this tool.

        Build-stage tools do not, which is why they are excluded from the
        image's own SBOM even though they are pinned here.
        """
        return self.stage == STAGE_IMAGE


@dataclass(frozen=True)
class Bundle:
    """One relocatable ecosystem bundle published by sbomify/sbom-tools.

    Carries no digest. A bundle is verified by its Sigstore attestation,
    whose signed statement contains the subject digest -- signed, rather than
    transcribed into tools.toml and trusted because it is written down. That
    is also what makes the rolling release usable, since its bytes change on
    every push to master.
    """

    name: str
    release: str
    #: Tool names this bundle can satisfy. Only used to decide what to
    #: download; the bundle describes its own contents once unpacked.
    provides: tuple[str, ...]
    purl: str

    def archive_url(self, arch: str) -> str:
        return f"{_BUNDLE_BASE}/{self.release}/{self.name}-{_ARCH_SLUGS[arch]}.tar.gz"

    def attestation_url(self, arch: str) -> str:
        return self.archive_url(arch) + ".sigstore.json"

    @property
    def package_url(self) -> str:
        return self.purl.format(release=self.release)


class ManifestError(ValueError):
    """The manifest is missing or internally inconsistent."""


@lru_cache(maxsize=1)
def load_tools() -> dict[str, Tool]:
    """Parse and validate tools.toml.

    Raises:
        ManifestError: if the file is unreadable, a stage is unknown, or a
            runtime tool is missing the assets it would need to be fetched.
    """
    try:
        raw = tomllib.loads(_MANIFEST.read_text())
    except FileNotFoundError as exc:  # pragma: no cover - packaging error
        raise ManifestError(f"Tool manifest not found at {_MANIFEST}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"Tool manifest is not valid TOML: {exc}") from exc

    raw_root = raw
    tools: dict[str, Tool] = {}
    for name, body in (raw.get("tool") or {}).items():
        stage = body.get("stage")
        if stage not in _STAGES:
            raise ManifestError(f"{name}: stage must be one of {_STAGES}, got {stage!r}")

        assets = None
        if raw_assets := body.get("assets"):
            assets = {}
            for arch, raw in raw_assets.items():
                # One table, or an array of them when a tool needs several
                # artifacts unpacked into the same prefix.
                entries = raw if isinstance(raw, list) else [raw]
                built = []
                for a in entries:
                    found = [alg for alg in DIGEST_ALGORITHMS if alg in a]
                    if len(found) != 1:
                        raise ManifestError(
                            f"{name}/{arch}: give exactly one of {', '.join(DIGEST_ALGORITHMS)}, got {found or 'none'}"
                        )
                    built.append(
                        ToolAsset(
                            url=a["url"],
                            algorithm=found[0],
                            digest=a[found[0]],
                            attestation=a.get("attestation"),
                        )
                    )
                assets[arch] = built

        is_built = bool(body.get("built", False))
        if is_built:
            if assets:
                raise ManifestError(f"{name}: a tool we build must not also pin a vendor download")
            assets = _built_assets(name, str(raw_root.get("tools_release") or TOOLS_RELEASE))

        if stage == STAGE_RUNTIME:
            # A runtime tool with no assets cannot be fetched, and the failure
            # would only surface on the first machine that needed it.
            if not assets:
                raise ManifestError(f"{name}: runtime tools need per-architecture assets")
            missing = {"amd64", "arm64"} - set(assets)
            if missing:
                raise ManifestError(f"{name}: no asset for {', '.join(sorted(missing))}")
            expected_length = {"sha256": 64, "sha512": 128}
            for arch, arch_assets in assets.items():
                for asset in arch_assets:
                    if is_built:
                        # Anchored by the attestation's signed digest instead.
                        if not asset.attestation:
                            raise ManifestError(f"{name}/{arch}: a tool we build must have an attestation")
                        continue
                    if len(asset.digest) != expected_length[asset.algorithm]:
                        raise ManifestError(
                            f"{name}/{arch}: {asset.algorithm} must be "
                            f"{expected_length[asset.algorithm]} hex characters"
                        )
                    if not asset.url.startswith("https://"):
                        raise ManifestError(f"{name}/{arch}: url must be https")

        tools[name] = Tool(
            name=name,
            version=_resolve_version(name, body),
            stage=stage,
            purl=body["purl"],
            github_repo=body.get("github_repo"),
            dockerfile_arg=body.get("dockerfile_arg"),
            kind=body.get("kind", "raw"),
            member=body.get("member"),
            strip_container=bool(body.get("strip_container", False)),
            rust_dist=bool(body.get("rust_dist", False)),
            built=is_built,
            env=dict(body.get("env") or {}),
            # An explicit bin_subdir always wins, including an empty one:
            # cargo-cyclonedx wraps a bare binary in a versioned directory, so
            # once that is stripped the payload sits at the prefix root. Testing
            # truthiness here instead of presence silently rewrote "" to "bin"
            # and put the tool on a path that does not exist.
            bin_subdir=str(
                body["bin_subdir"]
                if "bin_subdir" in body
                else ("bin" if body.get("strip_container") or body.get("rust_dist") else "")
            ),
            assets=assets,
        )

    if not tools:
        raise ManifestError("Tool manifest defines no tools")
    return tools


@lru_cache(maxsize=1)
def load_bundles() -> dict[str, Bundle]:
    """Parse the bundle section of tools.toml."""
    raw = tomllib.loads(_MANIFEST.read_text())
    release = str(raw.get("tools_release") or "tools-rolling")
    bundles: dict[str, Bundle] = {}
    for name, body in (raw.get("bundle") or {}).items():
        provides = tuple(body.get("provides") or ())
        if not provides:
            raise ManifestError(f"bundle {name}: provides nothing, so nothing would ever fetch it")
        bundles[name] = Bundle(name=name, release=release, provides=provides, purl=body["purl"])

    seen: dict[str, str] = {}
    for bundle in bundles.values():
        for tool in bundle.provides:
            if tool in seen:
                raise ManifestError(f"{tool} is provided by both {seen[tool]} and {bundle.name}")
            seen[tool] = bundle.name
    return bundles


@lru_cache(maxsize=1)
def _provider_index() -> dict[str, str]:
    return {tool: b.name for b in load_bundles().values() for tool in b.provides}


def bundle_for(tool: str) -> Bundle | None:
    """Which bundle serves this tool, if any."""
    name = _provider_index().get(tool)
    return load_bundles()[name] if name else None


def bundle_package_urls() -> list[str]:
    """PURLs for the bundles this release may fetch."""
    return sorted(b.package_url for b in load_bundles().values())


def tools_for_stage(*stages: str) -> dict[str, Tool]:
    """Return the tools belonging to the given stage(s)."""
    for stage in stages:
        if stage not in _STAGES:
            raise ManifestError(f"Unknown stage {stage!r}")
    return {n: t for n, t in load_tools().items() if t.stage in stages}


def image_package_urls() -> list[str]:
    """PURLs for the tools a pull of the image actually contains.

    This is the build-time set. Runtime tools are deliberately absent: the
    image does not contain them, and listing them would overstate what was
    shipped.
    """
    return sorted(t.package_url for t in tools_for_stage(STAGE_IMAGE).values())


def runtime_package_urls() -> list[str]:
    """PURLs for the tools that may be fetched while the action runs."""
    return sorted(t.package_url for t in tools_for_stage(STAGE_RUNTIME).values())
