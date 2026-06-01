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
    """
    if state.workspace is None:
        raise RuntimeError("apply_plan called before workspace prefetch")
    api = state.require_api()
    plan = state.plan

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

    # 5. Write sbomify.json when the user chose the json_config
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
        if opts.dry_run:
            log("info", "Dry-run: skipping sbomify.json write")
        else:
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

    # 6. Emit the workflow file. Last step so an API failure above never
    # leaves a broken .yml on disk that points at non-existent components.
    if opts.dry_run:
        log("info", "Dry-run: skipping workflow write")
        return

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
