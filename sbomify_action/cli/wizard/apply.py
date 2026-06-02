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

LogKind = Literal["info", "success", "warning", "error"]
LogFn = Callable[[LogKind, str], None]


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
        bound = 0
        for rel, comp_id in component_ids.items():
            try:
                api.patch_component(comp_id, contact_profile_id=plan.contact_profile_id)
                bound += 1
            except APIError as e:
                log("warning", f"Could not bind profile to {rel} ({comp_id}): {e}")
        if bound:
            state.applied.append(f"bound contact profile to {bound} component(s)")
            log("success", f"Bound contact profile {plan.contact_profile_id} to {bound} component(s)")

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
    as real handles.

    Read-only auth + workspace prefetch already happened on the
    Authenticate screen before the user reached Apply; this function
    is responsible for the no-mutation contract from apply onward.
    """
    plan = state.plan
    assert state.workspace is not None  # narrowed by caller

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

    # 5. OIDC bindings — same gating logic as the real path so the Done
    # screen's auto-vs-manual branching is preview-accurate.
    if plan.credential_mode == "oidc" and component_ids:
        slug = state.facts.owner_repo_slug
        if slug:
            state.oidc_bindings_registered = len(component_ids)
            state.applied.append(f"would register trusted publisher ({slug}) for {len(component_ids)} component(s)")
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
            log("info", f"[dry-run] Would write {json_path}")

    # 7. Workflow file
    target = workflow_path(opts.repo_root)
    state.applied.append(f"would write {target}")
    log("info", f"[dry-run] Would write {target}")

    log("info", "")
    log("info", "Re-run without --dry-run to actually apply these changes.")


def _register_oidc_bindings(state: WizardState, component_ids: dict[str, str], log: LogFn) -> None:
    """Auto-register a GitHub trusted-publisher binding per applied component.

    Mirrors the UI's manual "Trusted Publishing → Add binding" step so OIDC
    publishing works on the very first run. Records the outcome on
    ``state.oidc_bindings_registered`` / ``state.oidc_binding_note`` for the
    done screen. Never raises — every failure is a warning plus a note that
    makes the done screen fall back to manual instructions.
    """
    api = state.require_api()
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
    registered = 0
    last_error: str | None = None
    for rel, comp_id in component_ids.items():
        try:
            api.create_oidc_binding(comp_id, slug)
            registered += 1
        except APIError as exc:
            last_error = str(exc)
            log("warning", f"Could not register trusted publisher for {rel} ({comp_id}): {exc}")

    state.oidc_bindings_registered = registered
    if registered and last_error is None:
        state.applied.append(f"registered trusted publisher ({slug}) for {registered} component(s)")
        log("success", f"Registered trusted publisher {slug} for {registered} component(s)")
    else:
        # A failure (or zero successes) — leave a note so the done screen shows
        # manual instructions. Any partial-success count is preserved above.
        state.oidc_binding_note = last_error or "Trusted-publisher registration didn't complete; register it manually."


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
        product = api.create_product(plan.create_product)
        state.created_product_id = str(product.get("id") or "")
        state.applied.append(f"created product {product.get('name')}")
        log("success", f"Created product {product.get('name')}")
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
