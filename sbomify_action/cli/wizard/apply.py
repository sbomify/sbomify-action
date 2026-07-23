"""``apply_plan`` — the single mutation point of the wizard.

Everything before this is read-only / staging. The apply screen drives
this function from a worker thread; it streams progress via a callback
so the UI stays decoupled from the side effects.

Order matters: we create / reuse the product first, then components,
then attach components to the product, then write the workflow file
last. That way a failed component-create never leaves a half-written
workflow on disk.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Literal

from sbomify_action.cli.wizard import ci_emitter
from sbomify_action.cli.wizard.existing import workflow_path
from sbomify_action.cli.wizard.io import (
    SbomifyJsonOwnershipError,
    WorkflowOwnershipError,
    write_sbomify_json,
    write_workflow,
)
from sbomify_action.cli.wizard.options import WizardOptions
from sbomify_action.cli.wizard.state import WizardState
from sbomify_action.exceptions import APIError
from sbomify_action.sbomify_api import SbomifyApiClient

LogKind = Literal["info", "success", "warning", "error"]
LogFn = Callable[[LogKind, str], None]

# Bound on per-component HTTP fan-out (profile binding + OIDC binding).
# A small pool keeps the backend from being stampeded by a monorepo
# with dozens of lockfiles while still cutting latency by ~Nx for
# typical 2-10 component runs. requests.Session is not thread-safe, so
# each worker constructs its own SbomifyApiClient.
_MAX_PER_COMPONENT_WORKERS = 8


def _noop(_kind: LogKind, _message: str) -> None:
    """Default log sink — used when no UI is attached (eg. tests, --dry-run)."""


def apply_plan(state: WizardState, opts: WizardOptions, *, log: LogFn = _noop) -> None:
    """Execute every staged mutation in ``state.plan``.

    Idempotent where possible (component create uses get-or-create
    semantics; attach is a set-union; the workflow write is sentinel-guarded
    — overwrites a wizard-owned file, refuses a hand-authored one, and writes
    no ``.bak`` since git holds the prior version) and fail-fast otherwise.
    Populates ``state.applied``,
    ``state.created_product_id``, ``state.component_ids``, and
    ``state.written_files`` as side effects so the done screen can show
    what happened.

    When ``opts.dry_run`` is set, short-circuits to ``_apply_plan_dry_run``
    which simulates every step (populating the same state fields with
    synthetic markers) without touching the API or the filesystem. That
    keeps the ``--dry-run`` contract honest — read-only auth + workspace
    prefetch already happened on the Authenticate screen, but apply
    makes zero further calls.
    """
    if state.workspace is None:
        raise RuntimeError("apply_plan called before workspace prefetch")
    plan = state.plan

    # Clear any prior apply attempt's artifacts. The Apply screen lets a user
    # press Back after a failure and retry — without this reset, a previous
    # run's oidc_binding_note survives a successful retry and routes Done to
    # the manual-fallback panel, and state.applied accumulates duplicate
    # "wrote X" lines.
    state.reset_apply_artifacts()

    if opts.dry_run:
        _apply_plan_dry_run(state, opts, log)
        return

    api = state.require_api()

    # 1. Resolve or create the product.
    product = _resolve_product(state, log)

    # 2. Resolve component IDs. If the user picked an existing component
    # on the Components screen, `existing_id` is set and we use it
    # directly — no API call needed. Otherwise we get-or-create by name
    # (recovers from DUPLICATE_NAME on the backend).
    # Shared get-or-create cache so two lockfiles that resolve to the same
    # component name hit the API once and reuse the second call. Without it,
    # the second iteration paid a wasted DUPLICATE_NAME round-trip.
    component_ids: dict[str, str] = {}
    create_cache: dict[str, str] = {}
    for planned in plan.create_components:
        if planned.existing_id is not None:
            comp_id = planned.existing_id
            component_ids[str(planned.lockfile.rel_path)] = comp_id
            state.component_ids[planned.lockfile.rel_path] = comp_id
            state.reused_component_ids.add(comp_id)
            state.applied.append(f"reused existing component {planned.name}")
            log("info", f"Reused existing component {planned.name} ({comp_id})")
            continue

        # Pass component_type='bom' explicitly — the wizard onboards
        # code-repo SBOMs, which are BOM-typed components on the backend
        # (the ComponentType enum is {bom, document}; there is no "sbom").
        comp_id, was_created = api.get_or_create_component(planned.name, create_cache, component_type="bom")
        component_ids[str(planned.lockfile.rel_path)] = comp_id
        state.component_ids[planned.lockfile.rel_path] = comp_id
        if not was_created:
            # DUPLICATE_NAME-recovered: an existing component matched the
            # name, so the user didn't actually create anything. Mark it
            # reused so the Done summary classifies it correctly.
            state.reused_component_ids.add(comp_id)
        verb = "Created" if was_created else "Reused"
        state.applied.append(f"{verb.lower()} component {planned.name}")
        log("success" if was_created else "info", f"{verb} component {planned.name} ({comp_id})")

    # 3. Attach components to the product (single PATCH with the union set).
    if product is not None and component_ids:
        try:
            api.attach_components_to_product(str(product["id"]), list(component_ids.values()))
            state.applied.append("attached components to product")
            log("info", f"Attached {len(component_ids)} component(s) to product")
        except APIError as e:
            # Attach failure leaves components floating unlinked from the
            # product. We DON'T raise — the workflow file still gets written
            # so the user can retry attach manually — but we record on state
            # so the Done screen surfaces the problem instead of claiming
            # success.
            state.attach_error = str(e)
            log("error", f"Could not attach components to product: {e}")

    # 4. Bind the chosen contact profile to every applied component.
    # The emitted workflow sets AUGMENT=true at run time and the action
    # reads ``component.contact_profile_id`` off the backend — without
    # the binding here the augmentation silently no-ops in CI. Per-
    # component patch failures are surfaced as warnings (one bad PATCH
    # shouldn't sink the whole apply); skip the loop entirely when the
    # plan didn't pick a profile.
    if plan.augmentation == "profile" and plan.contact_profile_id and component_ids:
        profile_id = plan.contact_profile_id

        def _bind_profile(client: SbomifyApiClient, _rel: Path, comp_id: str) -> bool:
            client.patch_component(comp_id, contact_profile_id=profile_id)
            return True

        bound, profile_failures = _per_component_best_effort(
            api,
            component_ids,
            _bind_profile,
            "bind profile",
            log,
        )
        if bound:
            state.applied.append(f"bound contact profile to {bound} component(s)")
            log("success", f"Bound contact profile {profile_id} to {bound} component(s)")
        # Profile-binding failures are logged but not surfaced on Done — there's
        # no per-step retry UI for it today (unlike OIDC which routes to a
        # manual-fallback panel). Re-running the wizard rebinds.
        del profile_failures

    # 5. Register OIDC trusted-publisher bindings (oidc credential mode only).
    # The emitted workflow authenticates via OIDC; without a binding on the
    # backend the first publish 403s. Auto-register one per component so the
    # user doesn't have to create it by hand in the UI — the single most
    # common reason a first OIDC run fails. Best-effort: every failure path is
    # a warning + a done-screen fallback to manual instructions, never fatal.
    if plan.credential_mode == "oidc" and component_ids:
        _register_oidc_bindings(state, component_ids, log)

    # 6. Write sbomify.json when the user chose the json_config
    # augmentation strategy. The action's json_config provider reads
    # this file at workflow run time (AUGMENT=true triggers it) and
    # injects the supplier / manufacturer / authors / lifecycle fields
    # into every SBOM the matrix generates.
    #
    # write_sbomify_json applies the same ownership check that
    # write_workflow uses for the YAML file: it refuses to overwrite a
    # pre-existing sbomify.json that lacks the wizard sentinel key, so
    # a hand-authored config (carrying fields the wizard form doesn't
    # surface — eg licenses, multi-entity suppliers, vcs_* overrides)
    # is never silently clobbered.
    if plan.augmentation == "json_config" and plan.sbomify_json_data is not None:
        # Dry-run paths short-circuit at the top of apply_plan, so by
        # the time we get here we're definitely doing a real write.
        json_path = opts.repo_root / "sbomify.json"
        try:
            write_sbomify_json(json_path, plan.sbomify_json_data)
        except SbomifyJsonOwnershipError:
            # A hand-authored sbomify.json already lives here (no wizard
            # sentinel). Don't clobber it — but don't dead-end the whole
            # apply over it either. The action's json_config provider reads
            # whatever sbomify.json exists at run time, so the existing file
            # is already doing its job; skip the write and keep going so the
            # workflow + components still get created. The user can delete
            # the file (or add the '__sbomify_wizard__' key) to hand it over
            # to the wizard on a later run.
            log(
                "warning",
                f"{json_path} already exists and wasn't created by the wizard — "
                "keeping it as-is (the action reads it at run time). Any values you "
                "entered in the wizard were NOT written to it. To let the wizard "
                "manage this file, delete it (or add the '__sbomify_wizard__' key) "
                "and re-run.",
            )
            # Surface the unwritten payload so the user can copy it into the
            # file by hand instead of re-running the whole wizard to
            # reproduce what they typed.
            log(
                "info",
                "Values you entered (copy into sbomify.json manually if wanted):\n"
                + json.dumps(plan.sbomify_json_data, indent=2, sort_keys=True),
            )
        except OSError as e:
            log("error", f"Could not write {json_path}: {e}")
            raise
        else:
            state.written_files.append(json_path)
            state.applied.append(f"wrote {json_path}")
            log("success", f"Wrote {json_path}")

    # 7. Emit the workflow file. Last step so an API failure above never
    # leaves a broken .yml on disk that points at non-existent components.
    # Dry-run paths short-circuit at the top of apply_plan, so this is
    # always a real write.
    rendered = ci_emitter.emit_workflow(
        plan,
        facts=state.facts,
        api_base_url=opts.api_base_url,
        component_ids=component_ids,
        # Pin the action step to a GitHub-resolved commit SHA (or a tag
        # offline). Resolved here, at the authoritative write.
        action_ref=ci_emitter.resolve_action_ref(),
        # Pass state.created_product_id (set by _resolve_product for both
        # create-new and use-existing paths). Without this, tag-strategy
        # workflows for users who picked "create new product" silently
        # drop PRODUCT_RELEASE because plan.use_product_id stays None on
        # the create path.
        product_id=state.created_product_id,
    )
    target = workflow_path(opts.repo_root)
    try:
        write_workflow(target, rendered)
    except WorkflowOwnershipError as e:
        # Unlike the sbomify.json ownership conflict above (which we soften to
        # a warning and skip), a hand-authored workflow IS fatal: sboms.yml is
        # wizard-owned CI infrastructure with no value if half-written, and
        # there's no run-time fallback that reads "whatever is there". Failing
        # loud forces the user to resolve the conflict rather than silently
        # shipping a workflow that doesn't match the plan.
        log("error", str(e))
        raise
    state.written_files.append(target)
    state.applied.append(f"wrote {target}")
    log("success", f"Wrote {target}")


def _apply_plan_dry_run(state: WizardState, opts: WizardOptions, log: LogFn) -> None:
    """Simulate apply_plan without touching the API or the filesystem.

    Populates the same state fields a real apply would (so the Done
    screen can still render meaningfully) but every mutation is logged
    as ``[dry-run] Would …`` and no network or disk writes happen.
    Synthetic IDs (``<dry-run:component:foo>``) replace the IDs the
    real flow would have learned from API responses — they're
    obviously placeholder so the user can't accidentally treat them
    as real handles, and Done reads ``state.is_dry_run`` to skip the
    "open this URL" affordances that would otherwise resolve to a 404.

    Read-only auth + workspace prefetch already happened on the
    Authenticate screen before the user reached Apply; this function
    is responsible for the no-mutation contract from apply onward.
    """
    plan = state.plan
    assert state.workspace is not None  # narrowed by caller
    state.is_dry_run = True

    log("info", "Dry-run mode — no API mutations, no file writes.")
    log("info", "")

    # 1. Product
    if plan.create_product:
        synth_pid = f"<dry-run:product:{plan.create_product}>"
        state.created_product_id = synth_pid
        state.applied.append(f"would create product {plan.create_product}")
        log("info", f"[dry-run] Would create product {plan.create_product}")
    elif plan.use_product_id:
        match = next(
            (p for p in state.workspace.products if str(p.get("id")) == plan.use_product_id),
            None,
        )
        product_name = match.get("name") if isinstance(match, dict) else plan.use_product_id
        state.created_product_id = plan.use_product_id
        log("info", f"[dry-run] Would use existing product {product_name}")
    else:
        log("warning", "[dry-run] No product selected — components would not be attached")

    # 2. Components
    component_ids: dict[str, str] = {}
    for planned in plan.create_components:
        if planned.existing_id is not None:
            comp_id = planned.existing_id
            component_ids[str(planned.lockfile.rel_path)] = comp_id
            state.component_ids[planned.lockfile.rel_path] = comp_id
            state.reused_component_ids.add(comp_id)
            state.applied.append(f"would reuse existing component {planned.name}")
            log("info", f"[dry-run] Would reuse existing component {planned.name} ({comp_id})")
        else:
            synth_cid = f"<dry-run:component:{planned.name}>"
            component_ids[str(planned.lockfile.rel_path)] = synth_cid
            state.component_ids[planned.lockfile.rel_path] = synth_cid
            state.applied.append(f"would create component {planned.name}")
            log("info", f"[dry-run] Would create component {planned.name}")

    # 3. Attach
    if state.created_product_id and component_ids:
        state.applied.append("would attach components to product")
        log("info", f"[dry-run] Would attach {len(component_ids)} component(s) to product")

    # 4. Profile binding
    if plan.augmentation == "profile" and plan.contact_profile_id and component_ids:
        state.applied.append(f"would bind contact profile to {len(component_ids)} component(s)")
        log(
            "info",
            f"[dry-run] Would bind contact profile {plan.contact_profile_id} to {len(component_ids)} component(s)",
        )

    # 5. OIDC bindings — preview without claiming success. Leave
    # oidc_bindings_registered=0 so the Done screen renders a preview
    # panel rather than the "✓ Registered" success card; the dry-run
    # note carries the preview text. The slug-missing branch sets the
    # same note the real path would so the manual-fallback panel
    # preview is accurate too.
    if plan.credential_mode == "oidc" and component_ids:
        slug = state.facts.owner_repo_slug
        if slug:
            state.applied.append(f"would register trusted publisher ({slug}) for {len(component_ids)} component(s)")
            state.oidc_binding_note = (
                f"[dry-run] Would register trusted publisher {slug} for "
                f"{len(component_ids)} component(s) — re-run without --dry-run to apply."
            )
            log(
                "info",
                f"[dry-run] Would register trusted publisher {slug} for {len(component_ids)} component(s)",
            )
        else:
            state.oidc_binding_note = (
                "Couldn't detect a GitHub 'owner/repo' from the git remote, so the "
                "trusted publisher would need to be registered manually."
            )
            log("warning", f"[dry-run] {state.oidc_binding_note}")

    # 6. sbomify.json — flag a hand-authored file the real apply would
    # refuse so the user sees the warning before the real run.
    if plan.augmentation == "json_config" and plan.sbomify_json_data is not None:
        from sbomify_action.cli.wizard.io import sbomify_json_has_wizard_sentinel

        json_path = opts.repo_root / "sbomify.json"
        if json_path.exists() and not sbomify_json_has_wizard_sentinel(json_path):
            log(
                "warning",
                f"[dry-run] {json_path} already exists and isn't wizard-stamped — "
                "the real apply would keep it as-is and your form values wouldn't "
                "be written.",
            )
        else:
            state.applied.append(f"would write {json_path}")
            # Track the path so Done's Wrote/would-write summary mentions the
            # file (it iterates state.written_files). is_dry_run drives the
            # label glyph.
            state.written_files.append(json_path)
            log("info", f"[dry-run] Would write {json_path}")

    # 7. Workflow file
    target = workflow_path(opts.repo_root)
    state.applied.append(f"would write {target}")
    state.written_files.append(target)
    log("info", f"[dry-run] Would write {target}")

    log("info", "")
    log("info", "Re-run without --dry-run to actually apply these changes.")


def _per_component_best_effort(
    api: SbomifyApiClient,
    component_ids: dict[str, str],
    action: Callable[[SbomifyApiClient, Path, str], Any],
    label: str,
    log: LogFn,
) -> tuple[int, dict[Path, str]]:
    """Run ``action`` against every applied component in parallel.

    The shared ``api`` client is safe to use across workers because the
    requests.Session under it carries only bearer-auth headers (no
    cookie state mutated per request), and the action's POST/PATCH
    calls are idempotent enough that concurrent dispatch from a bounded
    pool doesn't race. Tests stub ``state.api`` with a MagicMock and
    assert call counts; sharing one client across threads keeps that
    pattern intact.

    Returns ``(success_count, failures)`` where ``failures`` maps
    relative-path to error message. Catches only ``APIError`` (which is
    the parent of ``AuthError`` per exceptions.py and includes the
    ConnectionError/Timeout shims in sbomify_api._request); anything
    else escapes and aborts the apply, which is the right behavior for
    programming errors. ``label`` is interpolated into per-failure
    warning messages ("Could not {label} for foo (cid): …").
    """
    rels = list(component_ids.items())

    def _one(item: tuple[str, str]) -> tuple[Path, str | None]:
        rel_str, comp_id = item
        rel_path = Path(rel_str)
        try:
            action(api, rel_path, comp_id)
            return rel_path, None
        except APIError as exc:
            return rel_path, str(exc) or exc.__class__.__name__

    max_workers = min(_MAX_PER_COMPONENT_WORKERS, max(len(rels), 1))
    if max_workers == 1:
        # Single component — skip pool overhead and keep the stack trace
        # straightforward for the common solo-lockfile case.
        results = [_one(rels[0])] if rels else []
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            results = list(pool.map(_one, rels))

    successes = 0
    failures: dict[Path, str] = {}
    for rel_path, error in results:
        comp_id = component_ids[str(rel_path)]
        if error is None:
            successes += 1
        else:
            failures[rel_path] = error
            log("warning", f"Could not {label} for {rel_path} ({comp_id}): {error}")
    return successes, failures


def _register_oidc_bindings(
    state: WizardState,
    component_ids: dict[str, str],
    log: LogFn,
) -> None:
    """Auto-register a GitHub trusted-publisher binding per applied component.

    Mirrors the UI's manual "Trusted Publishing → Add binding" step so OIDC
    publishing works on the very first run. Records the outcome on
    ``state.oidc_bindings_registered`` / ``state.oidc_newly_registered`` /
    ``state.oidc_failed_components`` / ``state.oidc_binding_note`` for the
    done screen. Never raises — every failure path lands on the Done manual
    fallback instead of aborting the apply.
    """
    slug = state.facts.owner_repo_slug
    if not slug:
        state.oidc_binding_note = (
            "Couldn't detect a GitHub 'owner/repo' from the git remote, so the "
            "trusted publisher must be registered manually."
        )
        log("warning", state.oidc_binding_note)
        return

    # Send only the repo name — identical for public and private repos (no
    # GitHub token needed). The backend resolves the immutable IDs for public
    # repos at create time and defers to the first OIDC publish for private
    # ones (pin-on-first-use); see the deferred-pinning change in the main app.
    #
    # create_oidc_binding returns True for fresh 201s, False for idempotent
    # 409s ("already bound"). Track both separately so the Done success
    # message can say "registered N (M already present)" instead of falsely
    # claiming N fresh bindings on a re-run.
    newly_registered = 0

    def _bind_oidc(client: SbomifyApiClient, _rel: Path, comp_id: str) -> bool:
        nonlocal newly_registered
        created = client.create_oidc_binding(comp_id, slug)
        if created:
            newly_registered += 1
        return created

    api = state.require_api()
    successes, failures = _per_component_best_effort(
        api,
        component_ids,
        _bind_oidc,
        "register trusted publisher",
        log,
    )

    # nonlocal mutation from worker threads needs a barrier — _per_component_best_effort
    # already joined every future before returning, so newly_registered is settled.
    state.oidc_bindings_registered = successes
    state.oidc_newly_registered = newly_registered
    state.oidc_failed_components = failures
    already_bound = successes - newly_registered

    if successes and not failures:
        if newly_registered and already_bound:
            summary = (
                f"registered trusted publisher ({slug}) for {newly_registered} new "
                f"component(s); {already_bound} already had a binding"
            )
            log_msg = (
                f"Trusted publisher for {slug}: registered {newly_registered} new, {already_bound} already present"
            )
        elif newly_registered:
            summary = f"registered trusted publisher ({slug}) for {newly_registered} component(s)"
            log_msg = f"Registered trusted publisher {slug} for {newly_registered} component(s)"
        else:
            # All 409s — every binding already existed. Don't claim "registered"
            # in either the Applied panel line or the success log; it would
            # falsely suggest fresh registrations on a no-op re-run.
            summary = f"trusted publisher ({slug}) already set for {already_bound} component(s)"
            log_msg = f"Trusted publisher {slug} was already set for {already_bound} component(s)"
        state.applied.append(summary)
        log("success", log_msg)
    elif successes:
        # Partial success — surface BOTH the count of bound components on the
        # Applied panel (so user knows what auto-succeeded) AND a failure note
        # so Done routes to the manual-fallback panel for the failed ones.
        state.applied.append(f"registered trusted publisher ({slug}) for {successes}/{len(component_ids)} component(s)")
        first_failure = next(iter(failures.values()), None)
        state.oidc_binding_note = (
            first_failure
            or "Some trusted-publisher registrations didn't complete; register the failed components manually."
        )
    else:
        # Zero successes — leave a note so Done shows manual instructions for
        # every component (failures dict carries the per-component errors).
        first_failure = next(iter(failures.values()), None)
        state.oidc_binding_note = (
            first_failure or "Trusted-publisher registration didn't complete; register it manually."
        )


def _resolve_product(state: WizardState, log: LogFn) -> dict[str, Any] | None:
    """Create or look up the product the plan points at.

    Returns the product dict, or ``None`` if the plan didn't request
    any product (a degenerate but valid case — components are still
    created, just not attached).
    """
    api = state.require_api()
    plan = state.plan
    assert state.workspace is not None  # narrowed by caller

    if plan.create_product:
        product, was_created = api.create_product(plan.create_product)
        state.created_product_id = str(product.get("id") or "")
        verb = "Created" if was_created else "Reused existing"
        state.applied.append(f"{verb.lower()} product {product.get('name')}")
        log("success" if was_created else "info", f"{verb} product {product.get('name')}")
        return product

    if plan.use_product_id:
        match: dict[str, Any] | None = next(
            (p for p in state.workspace.products if str(p.get("id")) == plan.use_product_id),
            None,
        )
        if match is None:
            # Not in the snapshot — fetch fresh.
            match = api.get_product(plan.use_product_id)
        state.created_product_id = str(match.get("id") or plan.use_product_id)
        log("info", f"Using existing product {match.get('name')}")
        return match

    log("warning", "No product selected — components will not be attached")
    return None
