"""State dataclasses for the sbomify-action wizard.

The state model is split into observed facts (read-only inputs to the
wizard) and a Plan (the staged set of mutations the user has agreed to).
Phases 1-4 only mutate the Plan; Phase 6 is the only place that performs
writes. This keeps Ctrl-C and --dry-run trivially safe.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from sbomify_action.cli.wizard.client import SbomifyClient


AugmentationStrategy = Literal["profile", "local", "skip"]
ReleaseStrategy = Literal["latest", "tag", "manual", "none"]
ComponentVisibility = Literal["public", "private", "gated"]
WorkflowFileAction = Literal["write", "skip", "write_new"]


@dataclass(frozen=True)
class DiscoveredLockfile:
    path: Path
    rel_path: Path
    ecosystem: str
    suggested_name: str


@dataclass(frozen=True)
class RepoFacts:
    repo_root: Path
    is_git: bool
    remote_url: str | None
    suggested_repo_name: str | None
    default_branch: str
    current_branch: str | None
    has_release_tags: bool


@dataclass
class WorkspaceSnapshot:
    user: dict[str, Any]
    products: list[dict[str, Any]] = field(default_factory=list)
    components: list[dict[str, Any]] = field(default_factory=list)
    contact_profiles: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PlannedComponent:
    lockfile: DiscoveredLockfile
    name: str
    existing_id: str | None = None
    visibility: ComponentVisibility = "private"
    lifecycle_phase: str = "build"
    licenses: list[str] = field(default_factory=list)
    augmentation: AugmentationStrategy = "skip"
    profile_id: str | None = None
    sbomify_json: dict[str, Any] | None = None
    release_strategy: ReleaseStrategy = "latest"


@dataclass
class Plan:
    create_product: str | None = None
    use_product_id: str | None = None
    create_components: list[PlannedComponent] = field(default_factory=list)
    create_initial_release: bool = False
    workflow_files: list[tuple[Path, str, WorkflowFileAction]] = field(default_factory=list)
    sbomify_json_files: list[tuple[Path, dict[str, Any]]] = field(default_factory=list)


@dataclass
class WizardState:
    facts: RepoFacts
    # `api` is set by the authenticate screen once the user's token is
    # validated. Screens that need it (anything past authenticate) should
    # assert it isn't None at use-time.
    api: "SbomifyClient | None" = None
    workspace: WorkspaceSnapshot | None = None
    selected: list[DiscoveredLockfile] = field(default_factory=list)
    plan: Plan = field(default_factory=Plan)
    applied: list[str] = field(default_factory=list)
    # Populated by apply_plan so the generate phase can talk to sbomify.
    created_product_id: str | None = None
    component_ids: dict[Path, str] = field(default_factory=dict)
    # Files that apply_plan wrote — used by the PR phase to know exactly what
    # to stage. Avoids `git add -A` so we never sweep up unrelated changes.
    written_files: list[Path] = field(default_factory=list)

    def require_api(self) -> "SbomifyClient":
        """Return the API client, raising if the auth screen hasn't run yet."""
        if self.api is None:
            raise RuntimeError("WizardState.api accessed before authenticate screen ran")
        return self.api

    def __repr__(self) -> str:
        return (
            f"WizardState(facts={self.facts!r}, "
            f"api={'<set>' if self.api else None}, "
            f"workspace={'<set>' if self.workspace else None}, "
            f"selected={len(self.selected)} lockfiles, plan={self.plan!r}, "
            f"applied={len(self.applied)} steps)"
        )
