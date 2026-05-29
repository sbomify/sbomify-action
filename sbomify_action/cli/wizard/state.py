"""State model for the wizard.

The model is deliberately split into three pieces:

  - ``RepoFacts`` — read-only observations of the working tree (immutable
    for the session).
  - ``WorkspaceSnapshot`` — what we learned by talking to sbomify after
    the user authenticated.
  - ``Plan`` — the staged set of mutations the user has agreed to.

Phases 1–4 of the wizard only mutate the ``Plan``. The apply phase is
the only place that performs writes or API mutations, so ``Ctrl-C`` and
``--dry-run`` are trivially safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from sbomify_action.sbomify_api import SbomifyApiClient


AugmentationStrategy = Literal["profile", "skip"]
"""How the emitted workflow should source component metadata.

- ``profile`` — set ``AUGMENT: 'true'`` so the action fetches the contact
  profile + lifecycle fields from sbomify at run time.
- ``skip`` — set ``AUGMENT: 'false'``; the user will manage metadata
  out-of-band.
"""

ReleaseStrategy = Literal["trunk", "tag", "manual"]
"""How the emitted workflow's ``on:`` block fires.

- ``trunk`` — push to the default branch (every push is a "release").
- ``tag`` — push of a ``v*`` tag (tag-driven releases).
- ``manual`` — ``workflow_dispatch`` only.
"""

CredentialMode = Literal["oidc", "token"]
"""Credential strategy embedded in the emitted workflow.

- ``oidc`` — wizard's default. Emits ``permissions: id-token: write`` and
  no ``TOKEN`` secret.
- ``token`` — backwards-compatible. Emits ``TOKEN: ${{ secrets.SBOMIFY_TOKEN }}``.
"""

SbomFormat = Literal["cyclonedx", "spdx"]
"""One of the two SBOM formats sbomify-action emits.

Each format becomes its own matrix entry per lockfile — a single
component publishing in both formats produces two artifacts.
"""


@dataclass(frozen=True)
class DiscoveredLockfile:
    """One lockfile the wizard found in the repo."""

    path: Path
    rel_path: Path
    ecosystem: str
    suggested_name: str


@dataclass(frozen=True)
class RepoFacts:
    """Snapshot of the repo at wizard start.

    Populated once during ``App.__init__`` and never mutated. Includes
    just enough git/filesystem context for screens to render accurate
    defaults (suggested component names, OIDC binding instructions,
    release-strategy default).
    """

    repo_root: Path
    is_git: bool
    remote_url: str | None
    suggested_repo_name: str | None
    default_branch: str
    current_branch: str | None
    has_release_tags: bool
    owner_repo_slug: str | None
    """``"owner/repo"`` parsed from the git remote, or None when unknown.
    Used to render the OIDC binding instructions on the Done screen."""
    visibility: Literal["public", "private", "unknown"] = "unknown"
    """Detected GitHub visibility — ``public`` if the unauthenticated
    GitHub API returned 200 with ``private: false``, ``private`` if it
    returned 404 (meaning the repo is not visible to anonymous callers,
    which on github.com effectively means private/internal). Anything
    else — non-GitHub remote, no remote, rate-limited, no network —
    falls back to ``unknown``. Used to gate the attestation warning
    on the configure screen and surface the visibility line on the
    welcome screen."""


@dataclass
class WorkspaceSnapshot:
    """What we learned from sbomify after authenticate succeeded."""

    products: list[dict[str, Any]] = field(default_factory=list)
    components: list[dict[str, Any]] = field(default_factory=list)
    contact_profiles: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PlannedComponent:
    """One component the user wants the wizard to create or reuse."""

    lockfile: DiscoveredLockfile
    name: str
    existing_id: str | None = None
    """If set, an existing component matching the name was found in the
    workspace and the wizard will reuse it instead of creating one."""


@dataclass
class Plan:
    """Everything the apply phase needs to commit to disk + sbomify."""

    create_product: str | None = None
    """Name of a new product to create (mutually exclusive with use_product_id)."""

    use_product_id: str | None = None
    """ID of an existing product to attach components to."""

    create_components: list[PlannedComponent] = field(default_factory=list)

    release_strategy: ReleaseStrategy = "trunk"
    credential_mode: CredentialMode = "oidc"
    augmentation: AugmentationStrategy = "skip"
    sbom_formats: list[SbomFormat] = field(default_factory=lambda: ["cyclonedx"])
    """Which formats to emit per lockfile. One matrix entry per (lockfile, format)."""
    enrich: bool = True
    """When True, the action calls external metadata sources (PyPI, deps.dev,
    Repology, etc.) to fill in package licenses, descriptions, and lifecycle
    fields the lockfile itself doesn't carry. On by default — there's almost
    no scenario where you want a less informative SBOM."""
    attestation: bool = False
    """When True, the workflow appends an ``actions/attest-build-provenance``
    step after each SBOM upload to produce a signed build attestation."""


@dataclass
class WizardState:
    """All wizard state, shared across screens via the Textual App."""

    facts: RepoFacts

    # Set by the authenticate screen once the user's token is validated.
    # Screens after authenticate should call ``require_api()`` rather than
    # touching this directly.
    api: "SbomifyApiClient | None" = None
    workspace: WorkspaceSnapshot | None = None

    # Lockfiles discovered at startup. Discovery is a one-shot — the
    # discover screen presents this list for multi-select.
    discovered: list[DiscoveredLockfile] = field(default_factory=list)
    selected: list[DiscoveredLockfile] = field(default_factory=list)

    plan: Plan = field(default_factory=Plan)

    # Populated by apply.apply_plan as a side-effect log + result map.
    applied: list[str] = field(default_factory=list)
    created_product_id: str | None = None
    component_ids: dict[Path, str] = field(default_factory=dict)
    written_files: list[Path] = field(default_factory=list)
    # IDs of components that were reused (either pre-picked on the Components
    # screen, or recovered from a DUPLICATE_NAME error during apply). The done
    # screen reads this to differentiate created-vs-reused in the summary so
    # re-running the wizard doesn't falsely report every component as new.
    reused_component_ids: set[str] = field(default_factory=set)
    # Set when component-to-product attach fails — done screen surfaces this
    # so success isn't claimed when components are floating unlinked. Empty
    # string when no failure has happened.
    attach_error: str | None = None

    # True if a sentinel-tagged sboms.yml already exists at apply time.
    # Set by the welcome / discover phase; used by review to surface
    # "will overwrite (.bak created)" rather than "will create".
    workflow_exists: bool = False

    def require_api(self) -> "SbomifyApiClient":
        """Return the API client, raising if authenticate hasn't run yet."""
        if self.api is None:
            raise RuntimeError("WizardState.api accessed before authenticate screen ran")
        return self.api

    def __repr__(self) -> str:
        return (
            f"WizardState(facts={self.facts!r}, "
            f"api={'<set>' if self.api else None}, "
            f"workspace={'<set>' if self.workspace else None}, "
            f"selected={len(self.selected)} lockfiles, "
            f"plan={self.plan!r}, "
            f"applied={len(self.applied)} steps)"
        )
