"""Top-level orchestrator for the `sbomify-action wizard` flow.

The wizard is structured as discrete phases. Phases 0-4 only mutate
``state.plan``; Phase 6 (``apply_plan``) is the only place that writes
files or calls mutating API endpoints. Ctrl-C anywhere before Phase 6 is
a no-op.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.status import Status

from sbomify_action.cli.wizard import ci_emitter, discovery, mapping
from sbomify_action.cli.wizard.client import (
    SbomifyAPIError,
    SbomifyAuthError,
    SbomifyClient,
)
from sbomify_action.cli.wizard.io import write_config
from sbomify_action.cli.wizard.prompts import (
    GoBack,
    ask_checkbox,
    ask_confirm,
    ask_select,
    ask_text,
    print_info,
    print_section_header,
    print_success,
    print_warning,
)
from sbomify_action.cli.wizard.state import (
    Plan,
    PlannedComponent,
    RepoFacts,
    WizardState,
    WorkflowFileAction,
    WorkspaceSnapshot,
)
from sbomify_action.console import console
from sbomify_action.logging_config import logger

DEFAULT_API_BASE_URL = "https://app.sbomify.com"


@dataclass
class WizardOptions:
    token: str | None
    api_base_url: str
    repo_root: Path
    output_dir: Path
    dry_run: bool


# ----------------------------------------------------------------------
# Phase 0 — pre-flight


def _gather_repo_facts(repo_root: Path) -> RepoFacts:
    repo_root = repo_root.resolve()
    is_git = _git_check(["rev-parse", "--is-inside-work-tree"], cwd=repo_root) == "true"
    remote_url: str | None = None
    suggested_repo_name: str | None = None
    default_branch = "main"
    current_branch: str | None = None
    has_release_tags = False

    if is_git:
        remote_url = _git_check(["config", "--get", "remote.origin.url"], cwd=repo_root) or None
        if remote_url:
            suggested_repo_name = _parse_repo_name(remote_url)
        head_ref = _git_check(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"], cwd=repo_root)
        if head_ref and "/" in head_ref:
            default_branch = head_ref.split("/", 1)[1]
        current_branch = _git_check(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root) or None
        tags = _git_check(["tag", "--list", "v*"], cwd=repo_root)
        has_release_tags = bool(tags)

    if not suggested_repo_name:
        suggested_repo_name = repo_root.name

    return RepoFacts(
        repo_root=repo_root,
        is_git=is_git,
        remote_url=remote_url,
        suggested_repo_name=suggested_repo_name,
        default_branch=default_branch,
        current_branch=current_branch,
        has_release_tags=has_release_tags,
    )


def _git_check(args: list[str], *, cwd: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _parse_repo_name(remote_url: str) -> str | None:
    """Pull the repo name out of a typical git remote URL."""
    cleaned = remote_url.strip()
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    match = re.search(r"[:/]([^:/]+/[^:/]+)$", cleaned)
    if match:
        slug = match.group(1).split("/")[-1]
        return slug or None
    return cleaned.rsplit("/", 1)[-1] or None


def _print_welcome(facts: RepoFacts) -> None:
    body = (
        "Set up SBOM generation for this repository.\n\n"
        "This wizard will:\n"
        "  1. Find your lockfiles\n"
        "  2. Authenticate to sbomify\n"
        "  3. Pick or create a Product\n"
        "  4. Configure each component (name, details, release)\n"
        "  5. Show you everything before applying\n"
        "  6. Generate one GitHub Actions workflow per component\n\n"
        "~2-5 min for a single-lockfile repo.\n"
        "Esc = back · Ctrl-C = exit (nothing is saved until step 6)."
    )
    console.print()
    console.print(Panel(body, title="sbomify wizard"))
    console.print()
    if not facts.is_git:
        print_warning(
            "This directory is not a git repository. Discovery falls back to a tree walk; "
            "release-strategy heuristics and gitignore awareness will be limited."
        )


# ----------------------------------------------------------------------
# Phase 1 — discovery


def _phase_discover(facts: RepoFacts) -> list:
    print_section_header("Step 1 of 6 — Discover lockfiles")
    found = discovery.discover(facts.repo_root)
    if not found:
        print_warning(f"No lockfiles found under {facts.repo_root}. Are you running this from the repo root?")
        return []

    from questionary import Choice

    choices = [
        Choice(
            f"{lf.rel_path}  ({lf.ecosystem})",
            value=str(lf.rel_path),
            checked=True,
        )
        for lf in found
    ]
    selected_paths = ask_checkbox(
        f"Found {len(found)} lockfile(s). Deselect any you don't want to track:",
        choices=choices,
    )

    selected_set = set(selected_paths)
    return [lf for lf in found if str(lf.rel_path) in selected_set]


# ----------------------------------------------------------------------
# Phase 2 — authentication


def _resolve_token(opt_token: str | None) -> str | None:
    if opt_token:
        return opt_token
    return os.environ.get("SBOMIFY_TOKEN") or os.environ.get("TOKEN") or None


def _phase_authenticate(opts: WizardOptions) -> SbomifyClient:
    print_section_header("Step 2 of 6 — Authenticate")

    token = _resolve_token(opts.token)
    api_base = opts.api_base_url.rstrip("/")

    attempts = 0
    while attempts < 3:
        if not token:
            print_info(f"Generate an API token at: {api_base}/settings/tokens")
            token = ask_text(
                "API token (input is masked, paste with Ctrl-V):",
                validate=lambda value: bool(value.strip()) or "Token is required",
                allow_back=False,
            ).strip()

        client = SbomifyClient(api_base, token)
        try:
            client.whoami()
            print_success("Authenticated.")
            return client
        except SbomifyAuthError:
            print_warning("Token rejected. Generate a new one and try again.")
            token = None
            attempts += 1
        except SbomifyAPIError as e:
            raise RuntimeError(f"Could not reach {api_base}: {e}")

    raise RuntimeError("Authentication failed after 3 attempts.")


def _prefetch_workspace(client: SbomifyClient) -> WorkspaceSnapshot:
    snapshot = WorkspaceSnapshot(user={"authenticated": True})
    with Status("Loading workspace…", console=console):
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                "products": pool.submit(client.list_products),
                "components": pool.submit(client.list_components),
                "contact_profiles": pool.submit(client.list_contact_profiles),
            }
            for name, future in futures.items():
                try:
                    setattr(snapshot, name, future.result())
                except SbomifyAPIError as e:
                    logger.warning(f"Could not load {name}: {e}")
                    setattr(snapshot, name, [])
    return snapshot


# ----------------------------------------------------------------------
# Phase 5 — review


def _resolve_product_summary(state: WizardState) -> str:
    if state.plan.create_product:
        return f"Create product   {state.plan.create_product}"
    assert state.plan.use_product_id is not None
    assert state.workspace is not None
    name = next(
        (
            str(p.get("name") or "")
            for p in state.workspace.products
            if str(p.get("id") or "") == state.plan.use_product_id
        ),
        state.plan.use_product_id,
    )
    return f"Use product      {name}"


def _format_component_row(planned: PlannedComponent) -> str:
    augmentation_label = {
        "profile": f"contact profile {planned.profile_id}",
        "local": "sbomify.json",
        "skip": "(no metadata)",
    }[planned.augmentation]
    return f"  - {planned.name:<30} {augmentation_label:<28} releases: {planned.release_strategy}"


def _phase_review(state: WizardState, opts: WizardOptions) -> bool:
    print_section_header("Step 5 of 6 — Review")

    product_label = _resolve_product_summary(state)
    component_lines = [_format_component_row(c) for c in state.plan.create_components]
    body_lines: list[str] = [
        f"sbomify · {opts.api_base_url}",
        f"  - {product_label}",
        f"  - Create {len(state.plan.create_components)} component(s) attached to the product",
        *component_lines,
        "  All components apply defaults: visibility=private · lifecycle=build · licenses=[]",
        "  (edit on sbomify after the wizard finishes if you want to tune them)",
    ]
    if state.plan.create_initial_release:
        body_lines.append("  - Pre-create release v0.0.0 (prerelease) for tag-strategy components")
    body_lines.append("")
    body_lines.append(
        "  Note: a hidden helper project '<product>-default' will be created/reused on sbomify "
        "as a temporary workaround until direct product->component linking ships."
    )
    body_lines.append("")
    body_lines.append("Filesystem")

    plan_files = ci_emitter.plan_workflow_files(
        plan=state.plan,
        output_dir=opts.output_dir,
        api_base_url=opts.api_base_url,
        default_branch=state.facts.default_branch,
        product_id=state.plan.use_product_id or "<product-id>",
    )

    # Surface workflow-file collisions inline with overwrite/skip/.new choice.
    resolved_files: list[tuple[Path, str, WorkflowFileAction]] = []
    for path, content, action in plan_files:
        if action == "skip":
            choice = ask_select(
                f"{path} already exists. What should the wizard do?",
                choices=[
                    f"Skip (keep existing) — recommended for {path.name}",
                    "Overwrite",
                    "Write to .new alongside",
                ],
            )
            if choice == "Overwrite":
                resolved_action: WorkflowFileAction = "write"
            elif choice == "Write to .new alongside":
                resolved_action = "write_new"
            else:
                resolved_action = "skip"
        else:
            resolved_action = action
        resolved_files.append((path, content, resolved_action))

    state.plan.workflow_files = resolved_files

    for path, _content, action in resolved_files:
        verb = {"write": "Write", "skip": "Skip ", "write_new": "Write"}[action]
        target = path if action != "write_new" else path.with_name(path.name + ".new")
        body_lines.append(f"  - {verb} {target}")

    for lf_path, _ in state.plan.sbomify_json_files:
        body_lines.append(f"  - Write {lf_path}")

    console.print()
    console.print(Panel("\n".join(body_lines), title="About to apply"))
    console.print()

    if opts.dry_run:
        print_info("Dry run — exiting without applying.")
        return False

    return ask_confirm("Apply these changes?", default=True, allow_back=False)


# ----------------------------------------------------------------------
# Phase 6 — apply


def apply_plan(state: WizardState, opts: WizardOptions) -> None:
    """Single mutation point. Idempotent where possible, fail-fast otherwise."""
    assert state.workspace is not None

    # 1. Resolve / create the product.
    if state.plan.create_product:
        product = state.api.create_product(state.plan.create_product)
        state.applied.append(f"created product {product.get('name')}")
    else:
        assert state.plan.use_product_id is not None
        product = next(
            (p for p in state.workspace.products if str(p.get("id")) == state.plan.use_product_id),
            None,
        )
        if product is None:
            raise RuntimeError(f"Selected product {state.plan.use_product_id} not in workspace snapshot.")

    state.created_product_id = str(product.get("id") or "")
    print_success(f"Product ready: {product.get('name')} ({product.get('id')})")

    # 2. Ensure the helper project exists (transparent to the user).
    project = state.api.ensure_default_project(product)
    state.applied.append(f"helper project {project.get('name')}")
    print_info(f"Helper project: {project.get('name')} ({project.get('id')})")

    # 3. Create each component, link to product, attach metadata.
    component_ids: dict[Path, str] = {}
    for planned in state.plan.create_components:
        component = state.api.create_component(planned.name, component_type="bom")
        component_id = str(component["id"])
        component_ids[planned.lockfile.rel_path] = component_id
        state.applied.append(f"created component {planned.name}")
        print_success(f"Component: {planned.name} ({component_id})")

        # Apply silent defaults that aren't part of the create payload.
        patch_fields: dict[str, Any] = {
            "visibility": planned.visibility,
            "lifecycle_phase": planned.lifecycle_phase,
        }
        if planned.licenses:
            patch_fields["licenses"] = planned.licenses
        if planned.augmentation == "profile" and planned.profile_id:
            patch_fields["contact_profile_id"] = planned.profile_id
        try:
            state.api.patch_component(component_id, **patch_fields)
        except SbomifyAPIError as e:
            print_warning(f"Could not patch component {planned.name}: {e}")

        try:
            state.api.attach_component_to_product(product, component_id)
            state.applied.append(f"attached {planned.name}")
        except SbomifyAPIError as e:
            print_warning(f"Could not attach {planned.name} to product: {e}")

        if planned.augmentation == "local" and planned.sbomify_json:
            target = planned.lockfile.path.parent / "sbomify.json"
            state.plan.sbomify_json_files.append((target, planned.sbomify_json))

    # 4. Optional initial release for tag-strategy components.
    if state.plan.create_initial_release:
        try:
            release = state.api.create_release(
                str(product["id"]),
                "v0.0.0",
                version="v0.0.0",
                is_prerelease=True,
            )
            state.applied.append(f"created release {release.get('name')}")
            print_success(f"Release: {release.get('name')}")
        except SbomifyAPIError as e:
            print_warning(f"Could not create initial release: {e}")

    # 5. Write sbomify.json files.
    for path, payload in state.plan.sbomify_json_files:
        if write_config(payload, path, backup=path.exists()):
            state.applied.append(f"wrote {path}")
            state.written_files.append(path)
            print_success(f"Wrote {path}")

    # 6. Re-render workflow files with real component IDs and write them.
    plan_files = ci_emitter.plan_workflow_files(
        plan=state.plan,
        output_dir=opts.output_dir,
        api_base_url=opts.api_base_url,
        default_branch=state.facts.default_branch,
        product_id=str(product["id"]),
        component_ids=component_ids,
    )
    # Carry over the user's collision decisions from Phase 5.
    decisions = {path: action for path, _, action in state.plan.workflow_files}
    plan_files = [(path, content, decisions.get(path, action)) for path, content, action in plan_files]
    written = ci_emitter.write_workflow_files(plan_files)
    for path in written:
        state.applied.append(f"wrote {path}")
        state.written_files.append(path)
        print_success(f"Wrote {path}")

    state.component_ids = component_ids


# ----------------------------------------------------------------------
# Phase 6.5 — optional local SBOM generation


def _git_short_sha(repo_root: Path) -> str | None:
    sha = _git_check(["rev-parse", "--short", "HEAD"], cwd=repo_root)
    return sha or None


def _phase_generate_sboms(state: WizardState, opts: WizardOptions) -> int:
    """Optional: generate (and upload) one SBOM per component locally.

    Returns the number of failures so the caller can adjust the exit code.
    """
    if opts.dry_run or not state.component_ids:
        return 0

    if not ask_confirm(
        "Generate an SBOM for each component now to confirm everything works?",
        default=True,
        allow_back=False,
    ):
        return 0

    # Lazy import to keep the wizard's startup time low — `cli.main` pulls in
    # the entire pipeline (cyclonedx, sentry, etc.).
    from sbomify_action.cli.main import build_config, run_pipeline

    token = getattr(state.api, "token", None) or ""
    version = _git_short_sha(state.facts.repo_root) or "0.0.0-local"
    successes = 0
    failures = 0

    for planned in state.plan.create_components:
        component_id = state.component_ids.get(planned.lockfile.rel_path)
        if not component_id:
            continue
        print_info(f"Generating SBOM for {planned.name} ({planned.lockfile.rel_path})…")
        try:
            config = build_config(
                token=token,
                component_id=component_id,
                lock_file=str(planned.lockfile.path),
                upload=True,
                augment=planned.augmentation != "skip",
                enrich=True,
                component_version=version,
                api_base_url=opts.api_base_url,
                sbom_format="cyclonedx",
            )
            run_pipeline(config)
            print_success(f"Uploaded SBOM for {planned.name}.")
            successes += 1
        except Exception as e:  # pragma: no cover - exercised via integration tests
            print_warning(f"SBOM generation for {planned.name} failed: {e}")
            failures += 1

    if successes:
        print_info(f"Generated {successes} SBOM(s) successfully.")
    if failures:
        print_warning(f"{failures} component(s) did not generate locally; CI will retry on the next push.")
    return failures


# ----------------------------------------------------------------------
# Phase 6.7 — open a PR


_PR_TITLE = "Configure sbomify SBOM generation"
_PR_BODY = (
    "Generated by `sbomify-action wizard`.\n\n"
    "This PR adds GitHub Actions workflow files that run `sbomify-action` on push, "
    "uploading SBOMs to sbomify.\n\n"
    "**Before merging**, add the `SBOMIFY_TOKEN` secret to this repository:\n\n"
    "```\n"
    "gh secret set SBOMIFY_TOKEN\n"
    "```\n\n"
    "(Once OIDC support lands, the secret becomes unnecessary — see the TODO in each workflow.)\n"
)


def _run_subprocess(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )


def _gh_authenticated() -> bool:
    try:
        subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def _has_unrelated_dirty_files(repo_root: Path, written: list[Path]) -> bool:
    """Return True if the working tree has uncommitted changes outside `written`."""
    porcelain = _git_check(["status", "--porcelain"], cwd=repo_root)
    if not porcelain:
        return False
    written_rel = {str(p.resolve().relative_to(repo_root.resolve())) for p in written if p.exists()}
    for line in porcelain.splitlines():
        # porcelain lines are " M path" or "?? path" — strip the 2-char status.
        if len(line) < 4:
            continue
        path = line[3:].strip()
        if path not in written_rel:
            return True
    return False


def _phase_open_pr(state: WizardState, opts: WizardOptions) -> None:
    if opts.dry_run or not state.written_files:
        return

    if not state.facts.is_git or not state.facts.remote_url:
        print_info("No git remote — skipping PR. Commit and push the new files manually.")
        return

    if not _gh_authenticated():
        print_info(
            "`gh` CLI is not installed or not authenticated. "
            "Run `gh auth login` and re-run the wizard if you want it to open a PR for you."
        )
        return

    if _has_unrelated_dirty_files(state.facts.repo_root, state.written_files):
        print_warning(
            "Your working tree has uncommitted changes other than the wizard's files. "
            "Skipping PR creation so we don't bundle unrelated work."
        )
        return

    target = state.facts.default_branch
    if not ask_confirm(
        f"Open a PR with these changes targeting `{target}`?",
        default=True,
        allow_back=False,
    ):
        return

    branch = ask_text(
        "Branch name for the PR:",
        default="sbomify-setup",
        validate=lambda v: bool(v.strip()) or "Branch name is required",
        allow_back=False,
    ).strip()

    if branch == target:
        print_warning(f"Cannot push directly to `{target}`. Pick a different branch name.")
        return

    repo_root = state.facts.repo_root
    try:
        _run_subprocess(["git", "checkout", "-b", branch], cwd=repo_root)
        for path in state.written_files:
            _run_subprocess(["git", "add", "--", str(path)], cwd=repo_root)
        _run_subprocess(
            ["git", "commit", "-m", _PR_TITLE],
            cwd=repo_root,
        )
        _run_subprocess(["git", "push", "-u", "origin", branch], cwd=repo_root)
        result = _run_subprocess(
            [
                "gh",
                "pr",
                "create",
                "--base",
                target,
                "--head",
                branch,
                "--title",
                _PR_TITLE,
                "--body",
                _PR_BODY,
            ],
            cwd=repo_root,
        )
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        print_warning(f"Could not open PR: {stderr or e}")
        print_info(f"Branch `{branch}` may have been created locally — check with `git branch`.")
        return

    url = (result.stdout or "").strip().splitlines()[-1] if result.stdout else ""
    if url:
        print_success(f"Opened PR: {url}")
    else:
        print_success("Opened PR.")


# ----------------------------------------------------------------------
# Phase 7 — done


def _print_done(state: WizardState, opts: WizardOptions) -> None:
    console.print()
    console.print(
        Panel(
            f"All set. {len(state.plan.create_components)} component(s) configured.\n\n"
            "Next steps:\n"
            "  1. Add the SBOMIFY_TOKEN secret to this repo:\n"
            "       gh secret set SBOMIFY_TOKEN\n"
            "  2. Commit the new files:\n"
            "       git add .github/workflows/sbomify-*.yml\n"
            "       git commit -m 'Add sbomify SBOM generation'\n"
            "  3. Push to main (or a v* tag, for tag-strategy components) to trigger\n"
            "     your first SBOM upload.\n\n"
            f"Visit {opts.api_base_url} to view your components.",
            title="Done",
        )
    )


# ----------------------------------------------------------------------
# Top-level orchestrator


def run_wizard_flow(opts: WizardOptions) -> int:
    if not sys.stdout.isatty():
        print_warning("The wizard is interactive — re-run from a terminal.")
        return 1

    facts = _gather_repo_facts(opts.repo_root)
    _print_welcome(facts)

    try:
        if not ask_confirm("Continue?", default=True, allow_back=False):
            print_info("Cancelled.")
            return 1

        selected = _phase_discover(facts)
        if not selected:
            return 1

        client = _phase_authenticate(opts)
        workspace = _prefetch_workspace(client)

        state = WizardState(facts=facts, api=client, workspace=workspace, selected=selected)
        state.plan = Plan()

        try:
            mapping.pick_or_create_product(state)
            mapping.configure_components(state)
        except GoBack:
            print_info("Cancelled.")
            return 1

        if not _phase_review(state, opts):
            return 0 if opts.dry_run else 1

        print_section_header("Step 6 of 6 — Applying…")
        try:
            apply_plan(state, opts)
        except SbomifyAPIError as e:
            print_warning(f"Apply failed: {e}")
            if state.applied:
                print_info("Partially-applied changes (clean up via the sbomify UI if needed):")
                for entry in state.applied:
                    print_info(f"  · {entry}")
            return 1

        _phase_generate_sboms(state, opts)
        _phase_open_pr(state, opts)
        _print_done(state, opts)
        return 0

    except KeyboardInterrupt:
        console.print()
        print_info("Cancelled.")
        return 1
    except GoBack:
        # Top-level GoBack: treat as cancellation in v1.
        console.print()
        print_info("Cancelled.")
        return 1
