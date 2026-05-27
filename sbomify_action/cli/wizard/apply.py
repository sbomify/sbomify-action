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

from typing import Any, Callable, Literal

from sbomify_action.cli.wizard import ci_emitter
from sbomify_action.cli.wizard.existing import workflow_path
from sbomify_action.cli.wizard.io import WorkflowOwnershipError, write_workflow
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
    semantics; attach is a set-union; workflow write backs up to .bak)
    and fail-fast otherwise. Populates ``state.applied``,
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

    # 2. Create components (get-or-create) and remember their IDs.
    component_ids: dict[str, str] = {}
    for planned in plan.create_components:
        comp_id, was_created = api.get_or_create_component(planned.name, cache={})
        component_ids[str(planned.lockfile.rel_path)] = comp_id
        state.component_ids[planned.lockfile.rel_path] = comp_id
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
            log("warning", f"Could not attach components to product: {e}")

    # 4. Emit the workflow file. Last step so an API failure above never
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
        backup = write_workflow(target, rendered)
    except WorkflowOwnershipError as e:
        log("error", str(e))
        raise
    state.written_files.append(target)
    state.applied.append(f"wrote {target}")
    if backup is not None:
        log("success", f"Wrote {target} (backup: {backup.name})")
    else:
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
