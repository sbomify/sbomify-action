"""Edit a single existing workflow — modify settings and re-emit the file.

Reached from `EditExistingScreen` after the user picks a row. Shows a
form with every setting the wizard tracks: component, product, lockfile
path, release strategy, augmentation. Saving re-runs the emitter so the
workflow gets the current template (which doubles as a migration path
for older / hand-edited files).

The file path is preserved on save — even if the resolved component
name would slugify to a different filename, we overwrite in place so
the user's git history stays clean.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, OptionList, RadioButton, RadioSet, Static
from textual.widgets.option_list import Option

from sbomify_action.cli.wizard.ci_emitter import render_workflow
from sbomify_action.cli.wizard.existing import ExistingWorkflow
from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import ReleaseStrategy


class EditWorkflowScreen(WizardScreen):
    """Phase 3.2 (edit flow) — modify one workflow's settings + re-emit."""

    step_index = 5
    step_title = "Edit workflow"

    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def __init__(self, workflow: ExistingWorkflow) -> None:
        super().__init__()
        self.workflow = workflow
        self.step_subtitle = f"{workflow.path.name}"

    # ------------------------------------------------------------------ layout

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="wizard-panel"):
            yield Static(f"[b #8A7DFF]Editing {self.workflow.path.name}[/]", classes="wizard-title")
            yield Static(
                "[#CBCCCE]Save re-emits the workflow with the current template — any "
                "deprecated patterns get cleaned up automatically.[/]",
                classes="wizard-muted",
            )

            yield Label("Component:")
            yield Input(placeholder="Type to filter components…", id="component-filter")
            yield OptionList(id="component-list", classes="wizard-options")

            yield Label("Product (used for tag-strategy releases):")
            yield Input(placeholder="Type to filter products…", id="product-filter")
            yield OptionList(id="product-list", classes="wizard-options")

            yield Label("Lockfile path (relative to repo root):")
            yield Input(value=str(self.workflow.lockfile_rel_path or ""), id="lockfile")

            yield Label("Release tracking:")
            with RadioSet(id="release"):
                strategy = self.workflow.release_strategy
                yield RadioButton("Latest only", id="rel-latest", value=strategy == "latest")
                yield RadioButton("Git tags  (v*)", id="rel-tag", value=strategy == "tag")
                yield RadioButton("Manual  (workflow_dispatch)", id="rel-manual", value=strategy == "manual")
                if strategy not in {"latest", "tag", "manual"}:
                    # Existing strategy was ambiguous — default to "latest".
                    self.query_one("#rel-latest")  # no-op: keeps lookup sane below

            yield Label("Metadata / contacts:")
            with RadioSet(id="augmentation"):
                augment_on = bool(self.workflow.augment)
                yield RadioButton("Augment metadata (use saved profile)", id="aug-on", value=augment_on)
                yield RadioButton("Skip — leave metadata blank", id="aug-off", value=not augment_on)

            yield Static("", id="edit-status", markup=True)
        with Horizontal(classes="button-row"):
            yield Button("◂ Cancel", id="cancel")
            yield Button("Save  ▸", id="save", variant="primary")

    def on_mount(self) -> None:
        self._populate_components("")
        self._populate_products("")
        # Default focus on the component filter so the most common edit
        # path (point at a different component) is one keystroke away.
        self.query_one("#component-filter", Input).focus()

    # ----------------------------------------------------------- workspace data

    @property
    def _components(self) -> list[dict[str, Any]]:
        ws = self.wizard.state.workspace
        return list(ws.components) if ws else []

    @property
    def _products(self) -> list[dict[str, Any]]:
        ws = self.wizard.state.workspace
        return list(ws.products) if ws else []

    def _populate_components(self, query: str) -> None:
        option_list = self.query_one("#component-list", OptionList)
        option_list.clear_options()
        default_id = self.workflow.component_id
        default_idx = 0
        matches = [c for c in self._components if not query or query in str(c.get("name") or "").lower()]
        for i, comp in enumerate(matches):
            label = f"[b]{comp.get('name') or '(unnamed)'}[/]  [#5E5E5E]·[/] [#CBCCCE]{comp.get('id')}[/]"
            option_list.add_option(Option(label, id=str(comp["id"])))
            if default_id and str(comp.get("id")) == default_id:
                default_idx = i
        if matches:
            option_list.highlighted = default_idx

    def _populate_products(self, query: str) -> None:
        option_list = self.query_one("#product-list", OptionList)
        option_list.clear_options()
        default_id = _parse_product_id_from_workflow(self.workflow.path)
        default_idx = 0
        matches = [p for p in self._products if not query or query in str(p.get("name") or "").lower()]
        for i, prod in enumerate(matches):
            label = f"[b]{prod.get('name') or '(unnamed)'}[/]  [#5E5E5E]·[/] [#CBCCCE]{prod.get('id')}[/]"
            option_list.add_option(Option(label, id=str(prod["id"])))
            if default_id and str(prod.get("id")) == default_id:
                default_idx = i
        if matches:
            option_list.highlighted = default_idx

    # ----------------------------------------------------------- event handlers

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "component-filter":
            self._populate_components(event.value.strip().lower())
        elif event.input.id == "product-filter":
            self._populate_products(event.value.strip().lower())

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "component-filter":
            self.query_one("#component-list", OptionList).focus()
        elif event.input.id == "product-filter":
            self.query_one("#product-list", OptionList).focus()
        elif event.input.id == "lockfile":
            self._save()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.app.pop_screen()
        elif event.button.id == "save":
            self._save()

    def action_save(self) -> None:
        self._save()

    # ------------------------------------------------------------------ save

    def _save(self) -> None:
        # Read fields
        component_id = self._selected_option_id("#component-list")
        product_id = self._selected_option_id("#product-list")
        lockfile = self.query_one("#lockfile", Input).value.strip()

        strategy: ReleaseStrategy = "latest"
        for radio_id, value in (
            ("rel-latest", "latest"),
            ("rel-tag", "tag"),
            ("rel-manual", "manual"),
        ):
            if self.query_one(f"#{radio_id}", RadioButton).value:
                strategy = value  # type: ignore[assignment]
                break
        augment = self.query_one("#aug-on", RadioButton).value

        # Validate
        if not component_id:
            self._set_status("[#F87171]Pick a component.[/]")
            return
        if not lockfile:
            self._set_status("[#F87171]Lockfile path is required.[/]")
            return
        if strategy == "tag" and not product_id:
            self._set_status("[#F87171]Tag-strategy workflows need a Product (used in the release identifier).[/]")
            return

        # Resolve the human-readable component name from the workspace
        # snapshot so the emitter can render `name: sbomify - <name>`.
        component_name = self._lookup_component_name(component_id) or component_id

        yaml = render_workflow(
            component_name=component_name,
            component_id=component_id,
            product_id=product_id or "",  # only used by the tag template
            lock_file_rel=lockfile,
            api_base_url=self.wizard.opts.api_base_url,
            release_strategy=strategy,
            augment=augment,
            default_branch=self.wizard.state.facts.default_branch,
        )

        try:
            self.workflow.path.write_text(yaml, encoding="utf-8")
        except OSError as e:
            self._set_status(f"[#F87171]Could not write {self.workflow.path.name}: {e}[/]")
            return

        self.wizard.state.applied.append(f"updated {self.workflow.path}")
        self.wizard.state.written_files.append(self.workflow.path)
        # Re-detect so the EditExistingScreen behind us refreshes if revisited.
        from sbomify_action.cli.wizard.existing import detect_existing_workflows

        self.wizard.state.existing_workflows = detect_existing_workflows(self.wizard.opts.repo_root)
        self._set_status(f"[#4ADE80]Saved.[/] [#CBCCCE]Wrote {self.workflow.path.name}.[/]")
        # Pop back so the user can edit another workflow or exit.
        self.app.pop_screen()

    # ------------------------------------------------------------------ helpers

    def _selected_option_id(self, selector: str) -> str | None:
        option_list = self.query_one(selector, OptionList)
        idx = option_list.highlighted
        if idx is None or option_list.option_count == 0:
            return None
        option = option_list.get_option_at_index(idx)
        return option.id if option.id else None

    def _lookup_component_name(self, component_id: str) -> str | None:
        for c in self._components:
            if str(c.get("id")) == component_id:
                return str(c.get("name") or "")
        return None

    def _set_status(self, markup: str) -> None:
        self.query_one("#edit-status", Static).update(markup)


# Regex against the existing tag-strategy workflow's `ver` step to recover
# the product_id that was baked in at emit time. The emitter writes:
#
#   echo 'release=["<product_id>:'"${GITHUB_REF_NAME}"'"]' >> "$GITHUB_OUTPUT"
#
# A best-effort recover — if the workflow has been hand-edited we just
# fall back to None and the user picks a product manually.
_PRODUCT_RELEASE_RX = re.compile(r"release=\[\"([^:\"]+):")


def _parse_product_id_from_workflow(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    match = _PRODUCT_RELEASE_RX.search(text)
    return match.group(1) if match else None
