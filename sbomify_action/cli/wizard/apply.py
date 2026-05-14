"""`apply_plan` — the single mutation point of the wizard.

Extracted from the old questionary-based runner so the Textual `ApplyScreen`
can drive it from a worker thread. The function is UI-agnostic: it emits
log lines via the `log` callback (kind, message) and never touches stdout
directly. The Textual screen renders these into a `RichLog`; a future
non-interactive caller could collect them however it wants.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Literal

from sbomify_action.cli.wizard import ci_emitter
from sbomify_action.cli.wizard.client import SbomifyAPIError
from sbomify_action.cli.wizard.io import write_config
from sbomify_action.cli.wizard.options import WizardOptions
from sbomify_action.cli.wizard.state import WizardState

LogKind = Literal["info", "success", "warning", "error"]
LogFn = Callable[[LogKind, str], None]


def _noop(_kind: LogKind, _message: str) -> None:
    """Default log sink — silently discards messages."""


def apply_plan(state: WizardState, opts: WizardOptions, *, log: LogFn = _noop) -> None:
    """Execute every staged mutation in `state.plan`. Single mutation point.

    The function is idempotent where possible and fail-fast otherwise. It
    populates `state.applied`, `state.created_product_id`,
    `state.component_ids`, and `state.written_files` as side effects.
    """
    assert state.workspace is not None, "apply_plan called before workspace prefetch"
    api = state.require_api()

    # 1. Resolve / create the product.
    if state.plan.create_product:
        product = api.create_product(state.plan.create_product)
        state.applied.append(f"created product {product.get('name')}")
        log("success", f"Created product {product.get('name')}")
    else:
        assert state.plan.use_product_id is not None
        product_match: dict[str, Any] | None = next(
            (p for p in state.workspace.products if str(p.get("id")) == state.plan.use_product_id),
            None,
        )
        if product_match is None:
            raise RuntimeError(f"Selected product {state.plan.use_product_id} not in workspace snapshot.")
        product = product_match
        log("info", f"Using existing product {product.get('name')}")

    state.created_product_id = str(product.get("id") or "")

    # 2. Ensure the helper project exists (transparent to the user).
    project = api.ensure_default_project(product)
    state.applied.append(f"helper project {project.get('name')}")
    log("info", f"Helper project ready: {project.get('name')}")

    # 3. Create each component, link to product, attach metadata.
    component_ids: dict[Path, str] = {}
    for planned in state.plan.create_components:
        component = api.create_component(planned.name, component_type="bom")
        component_id = str(component["id"])
        component_ids[planned.lockfile.rel_path] = component_id
        state.applied.append(f"created component {planned.name}")
        log("success", f"Component created: {planned.name} ({component_id})")

        patch_fields: dict[str, Any] = {
            "visibility": planned.visibility,
            "lifecycle_phase": planned.lifecycle_phase,
        }
        if planned.licenses:
            patch_fields["licenses"] = planned.licenses
        if planned.augmentation == "profile" and planned.profile_id:
            patch_fields["contact_profile_id"] = planned.profile_id
        try:
            api.patch_component(component_id, **patch_fields)
        except SbomifyAPIError as e:
            log("warning", f"Could not patch component {planned.name}: {e}")

        try:
            api.attach_component_to_product(product, component_id)
            state.applied.append(f"attached {planned.name}")
        except SbomifyAPIError as e:
            log("warning", f"Could not attach {planned.name} to product: {e}")

    # 4. Optional initial release for tag-strategy components.
    if state.plan.create_initial_release:
        try:
            release = api.create_release(
                str(product["id"]),
                "v0.0.0",
                version="v0.0.0",
                is_prerelease=True,
            )
            state.applied.append(f"created release {release.get('name')}")
            log("success", f"Release created: {release.get('name')}")
        except SbomifyAPIError as e:
            log("warning", f"Could not create initial release: {e}")

    # 5. Write sbomify.json files.
    for path, payload in state.plan.sbomify_json_files:
        if write_config(payload, path, backup=path.exists()):
            state.applied.append(f"wrote {path}")
            state.written_files.append(path)
            log("success", f"Wrote {path}")

    # 6. Re-render workflow files with real component IDs and write them.
    plan_files = ci_emitter.plan_workflow_files(
        plan=state.plan,
        output_dir=opts.output_dir,
        api_base_url=opts.api_base_url,
        default_branch=state.facts.default_branch,
        product_id=str(product["id"]),
        component_ids=component_ids,
    )
    decisions = {path: action for path, _, action in state.plan.workflow_files}
    plan_files = [(path, content, decisions.get(path, action)) for path, content, action in plan_files]
    written = ci_emitter.write_workflow_files(plan_files)
    for path in written:
        state.applied.append(f"wrote {path}")
        state.written_files.append(path)
        log("success", f"Wrote {path}")

    state.component_ids = component_ids
