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


AugmentationStrategy = Literal["profile", "skip", "json_config"]
"""How the emitted workflow should source component metadata.

- ``profile`` — set ``AUGMENT: 'true'`` so the action fetches the
  contact profile + lifecycle fields from sbomify at run time. The
  contact profile is bound to every component during apply.
- ``json_config`` — set ``AUGMENT: 'true'``; metadata comes from a
  ``sbomify.json`` file in the repo root that apply writes from the
  fields the user fills in on the Configure (sbomify.json) screen.
  The action's ``json_config`` provider reads it at workflow run time.
- ``skip`` — set ``AUGMENT: 'false'``; the user will manage metadata
  out-of-band (or accept blank organisational fields).
"""

ReleaseStrategy = Literal["trunk", "tag", "manual"]
"""How the emitted workflow's ``on:`` block fires.

- ``trunk`` — push to the default branch (every push is a "release").
- ``tag`` — push of a version tag, ``v*`` or bare-numeric like CalVer
  (tag-driven releases).
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
    has_sbomify_json: bool = False
    """True iff a ``sbomify.json`` already exists in the repo root at
    wizard start. When set, the Configure (sbomify.json) screen pre-fills
    its form from the existing file instead of opening blank, and the
    apply phase treats a hand-authored (non-wizard) file as the source of
    truth rather than dead-ending on the ownership check."""


@dataclass
class WorkspaceSnapshot:
    """What we learned from sbomify after authenticate succeeded."""

    products: list[dict[str, Any]] = field(default_factory=list)
    components: list[dict[str, Any]] = field(default_factory=list)
    contact_profiles: list[dict[str, Any]] = field(default_factory=list)
    team_key: str | None = None
    """Workspace identifier returned by ``GET /api/v1/workspaces/``.
    Required to scope endpoints like contact-profiles which the backend
    nests under ``/api/v1/workspaces/{team_key}/``. ``None`` when the
    token couldn't enumerate any workspace. (The legacy ``team_key``
    field name is preserved for backward compatibility — the route
    moved from ``/teams/`` to ``/workspaces/`` in the backend rename
    but the URL parameter still uses the old name.)"""
    display_name: str | None = None
    """Human-readable name of the picked workspace. Surfaced on the
    auth-success status line so the user can spot a misdirection — the
    workspace picker uses ``is_default_team`` which is wrong for scoped
    tokens bound to a non-default workspace, and there's no
    programmatic way to disambiguate today."""


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
    contact_profile_id: str | None = None
    """ID of the contact profile to bind to every applied component when
    ``augmentation == 'profile'``. ``None`` when augmentation is ``'skip'``
    or when no profile was selected. apply.py patches each component with
    ``contact_profile_id=<this>`` so AUGMENT=true at workflow run time
    actually has something to look up — without this, the action sets
    AUGMENT=true but the component has no profile bound on the backend
    and augmentation silently no-ops."""
    sbomify_json_data: dict[str, Any] | None = None
    """JSON payload written to ``<repo_root>/sbomify.json`` when
    ``augmentation == 'json_config'``. Populated by
    ConfigureSbomifyJsonScreen with the supplier / manufacturer /
    authors / lifecycle fields the action's ``json_config`` provider
    expects."""
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


@dataclass(frozen=True)
class PublishOutcome:
    """Result of one local generate-and-upload run from the Publish step.

    One outcome per (lockfile, format) matrix row — mirrors the rows the
    emitted workflow would run in CI. ``error`` carries a short
    human-readable reason when ``ok`` is False; the full subprocess
    output already streamed to the Publish screen's log.
    """

    rel_path: str
    sbom_format: str
    output_file: Path
    ok: bool
    error: str | None = None


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

    # OIDC trusted-publisher auto-registration outcome (oidc credential mode).
    # apply.apply_plan tries to register a binding per applied component so the
    # user doesn't have to create one by hand in the UI. The done screen reads
    # these to show either a "✓ done" confirmation or fall back to manual
    # instructions.
    oidc_bindings_registered: int = 0
    """Count of components a trusted-publisher binding exists for after apply
    — the sum of fresh 201s and idempotent 409s ("already bound"). 0 when
    auto-registration didn't run or every call failed. Done renders the
    success panel only when this > 0 AND there are no failed components."""
    oidc_newly_registered: int = 0
    """Count of components where apply created a fresh binding (HTTP 201).
    Reported in the Done success message so a re-run that hit only 409s
    isn't misreported as "registered N new bindings"."""
    oidc_failed_components: dict[Path, str] = field(default_factory=dict)
    """``{rel_path: error_message}`` for components where create_oidc_binding
    raised. Used by the Done screen's manual-fallback panel to list ONLY the
    failed components instead of every applied one — re-binding successful
    components would just produce 409 noise. Empty when every binding
    succeeded (or no auto-registration was attempted)."""
    oidc_binding_note: str | None = None
    """Set when auto-registration was skipped wholesale (no GitHub slug,
    network failure before the loop) OR is a per-component failure message
    that bubbles to the panel header. When non-None AND
    ``oidc_failed_components`` is empty, the slug-missing case applies and
    Done falls back to listing every component for manual setup."""

    # True if a sentinel-tagged sboms.yml already exists at apply time.
    # Set by the welcome / discover phase; used by review to surface
    # "will overwrite" rather than "will create". No .bak is written —
    # the workflow file lives under .github/workflows/ where git holds
    # the prior version (see write_workflow in cli/wizard/io.py).
    workflow_exists: bool = False

    is_dry_run: bool = False
    """True when the active apply pass is the dry-run simulation
    (``_apply_plan_dry_run``). The Done screen reads this to label
    "would write" rows correctly, render a preview-mode OIDC panel
    instead of claiming a real binding, and disable the
    "copy first URL to clipboard" action whose synthetic
    ``<dry-run:component:...>`` IDs would produce a 404 URL."""

    # Populated by publish.run_publish (the Publish screen's worker).
    publish_outcomes: list[PublishOutcome] = field(default_factory=list)
    """One entry per attempted (lockfile, format) run, in run order.
    Empty when the user skipped the Publish step (or hasn't reached it).
    The Done screen renders a published-SBOMs panel from this."""
    publish_output_dir: Path | None = None
    """Directory the local publish runs wrote their SBOM files (and audit
    trails) into — a session temp dir, kept after the wizard exits so the
    user can inspect what was uploaded."""

    def require_api(self) -> "SbomifyApiClient":
        """Return the API client, raising if authenticate hasn't run yet."""
        if self.api is None:
            raise RuntimeError("WizardState.api accessed before authenticate screen ran")
        return self.api

    def reset_apply_artifacts(self) -> None:
        """Clear every field apply_plan writes, so a Back→Apply retry starts clean.

        Without this, a prior partial-fail's ``oidc_binding_note`` survives a
        successful retry and routes Done to the manual-fallback panel; or
        repeated runs accumulate duplicate ``"wrote X"`` lines in
        ``applied``. We deliberately leave ``facts``, ``api``, ``workspace``,
        ``discovered``, ``selected``, ``plan``, and ``workflow_exists`` alone
        — those are inputs to apply, not outputs of it.
        """
        self.applied = []
        self.created_product_id = None
        self.component_ids = {}
        self.written_files = []
        self.reused_component_ids = set()
        self.attach_error = None
        self.oidc_bindings_registered = 0
        self.oidc_newly_registered = 0
        self.oidc_failed_components = {}
        self.oidc_binding_note = None
        self.is_dry_run = False
        # Publish runs against the component IDs a specific apply produced;
        # re-applying invalidates them, so a stale outcome list must not leak
        # into the Done summary of the new pass.
        self.publish_outcomes = []
        self.publish_output_dir = None

    def __repr__(self) -> str:
        return (
            f"WizardState(facts={self.facts!r}, "
            f"api={'<set>' if self.api else None}, "
            f"workspace={'<set>' if self.workspace else None}, "
            f"selected={len(self.selected)} lockfiles, "
            f"plan={self.plan!r}, "
            f"applied={len(self.applied)} steps)"
        )
