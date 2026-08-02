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
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import tomllib

_MANIFEST = Path(__file__).with_name("tools.toml")
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


def _version_from_cargo_lock(path: Path, package: str) -> str:
    """Read a crate's pinned version out of Cargo.lock."""
    data = tomllib.loads(path.read_text())
    for entry in data.get("package", []):
        if entry.get("name") == package:
            return str(entry["version"])
    raise ManifestError(f"{package} not found in {path}")


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


def _resolve_version(name: str, body: dict[str, object]) -> str:
    """Take the version from the ecosystem's own lockfile where one owns it.

    Restating versions in this file would put them out of Dependabot's reach
    and create a second place to bump -- which is exactly the drift this
    manifest exists to stop. Only tools with no native manifest carry a
    literal `version` here.
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

    if "module" in source:
        return _version_from_go_mod(path, source["module"])
    if "package" in source:
        return _version_from_cargo_lock(path, source["package"])
    if "artifact" in source:
        return _version_from_pom(path, str(source["artifact"]))
    raise ManifestError(f"{name}: version_from needs a module (go.mod), package (Cargo.lock) or artifact (pom.xml)")


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
    assets: dict[str, ToolAsset] | None = None

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

    tools: dict[str, Tool] = {}
    for name, body in (raw.get("tool") or {}).items():
        stage = body.get("stage")
        if stage not in _STAGES:
            raise ManifestError(f"{name}: stage must be one of {_STAGES}, got {stage!r}")

        assets = None
        if raw_assets := body.get("assets"):
            assets = {}
            for arch, a in raw_assets.items():
                found = [alg for alg in DIGEST_ALGORITHMS if alg in a]
                if len(found) != 1:
                    raise ManifestError(
                        f"{name}/{arch}: give exactly one of {', '.join(DIGEST_ALGORITHMS)}, got {found or 'none'}"
                    )
                assets[arch] = ToolAsset(url=a["url"], algorithm=found[0], digest=a[found[0]])

        if stage == STAGE_RUNTIME:
            # A runtime tool with no assets cannot be fetched, and the failure
            # would only surface on the first machine that needed it.
            if not assets:
                raise ManifestError(f"{name}: runtime tools need per-architecture assets")
            missing = {"amd64", "arm64"} - set(assets)
            if missing:
                raise ManifestError(f"{name}: no asset for {', '.join(sorted(missing))}")
            expected_length = {"sha256": 64, "sha512": 128}
            for arch, asset in assets.items():
                if len(asset.digest) != expected_length[asset.algorithm]:
                    raise ManifestError(
                        f"{name}/{arch}: {asset.algorithm} must be {expected_length[asset.algorithm]} hex characters"
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
            env=dict(body.get("env") or {}),
            bin_subdir=str(body.get("bin_subdir", "bin") if body.get("strip_container") else ""),
            assets=assets,
        )

    if not tools:
        raise ManifestError("Tool manifest defines no tools")
    return tools


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
