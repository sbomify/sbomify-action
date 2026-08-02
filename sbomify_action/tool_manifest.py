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

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import tomllib

_MANIFEST = Path(__file__).with_name("tools.toml")

#: Tools baked into the published container image.
STAGE_IMAGE = "image"
#: Tools fetched on first use and verified against a pinned digest.
STAGE_RUNTIME = "runtime"
#: Tools used to build the image but not shipped inside it.
STAGE_BUILD = "build"

_STAGES = (STAGE_IMAGE, STAGE_RUNTIME, STAGE_BUILD)


@dataclass(frozen=True)
class ToolAsset:
    """A downloadable artifact and the digest it must have."""

    url: str
    sha256: str


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
            assets = {arch: ToolAsset(url=a["url"], sha256=a["sha256"]) for arch, a in raw_assets.items()}

        if stage == STAGE_RUNTIME:
            # A runtime tool with no assets cannot be fetched, and the failure
            # would only surface on the first machine that needed it.
            if not assets:
                raise ManifestError(f"{name}: runtime tools need per-architecture assets")
            missing = {"amd64", "arm64"} - set(assets)
            if missing:
                raise ManifestError(f"{name}: no asset for {', '.join(sorted(missing))}")
            for arch, asset in assets.items():
                if len(asset.sha256) != 64:
                    raise ManifestError(f"{name}/{arch}: sha256 must be 64 hex characters")
                if not asset.url.startswith("https://"):
                    raise ManifestError(f"{name}/{arch}: url must be https")

        tools[name] = Tool(
            name=name,
            version=body["version"],
            stage=stage,
            purl=body["purl"],
            github_repo=body.get("github_repo"),
            dockerfile_arg=body.get("dockerfile_arg"),
            kind=body.get("kind", "raw"),
            member=body.get("member"),
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
