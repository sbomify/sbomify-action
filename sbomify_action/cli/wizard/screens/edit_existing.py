"""Edit-existing landing screen — pick which workflow to modify.

Reached from the welcome screen's "Edit existing" button when at least
one sbomify workflow is detected on disk. Lists every detected workflow
in a DataTable with its current settings; selecting a row + Enter (or
pressing "Edit") pushes EditWorkflowScreen for that workflow.

This screen runs *after* authenticate so the workspace snapshot is
available — we use it to resolve `COMPONENT_ID` values into human
component names.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen

if TYPE_CHECKING:
    from sbomify_action.cli.wizard.existing import ExistingWorkflow


class EditExistingScreen(WizardScreen):
    """Phase 3.1 (edit flow) — pick which workflow to edit."""

    step_index = 4
    step_title = "Edit existing workflows"
    step_subtitle = "Pick a workflow to modify. Saving any change re-emits the file with current templates."

    BINDINGS = [
        Binding("enter", "edit_selected", "Edit", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="wizard-panel"):
            yield Static("[b #8A7DFF]Existing sbomify workflows[/]", classes="wizard-title")
            yield Static(
                "[#CBCCCE]Saving any change re-emits the workflow with the current template, "
                "so this also doubles as a one-step way to migrate older workflows to the "
                "latest format.[/]",
                classes="wizard-muted",
            )
            yield DataTable(id="workflow-table", cursor_type="row", zebra_stripes=True)
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Edit  ▸", id="edit", variant="primary")

    def on_mount(self) -> None:
        table = self.query_one("#workflow-table", DataTable)
        table.add_columns("File", "Lockfile", "Component", "Release", "Augment")
        workspace = self.wizard.state.workspace
        components_by_id: dict[str, str] = {}
        if workspace:
            for c in workspace.components:
                cid = c.get("id")
                if cid is not None:
                    components_by_id[str(cid)] = str(c.get("name") or "(unnamed)")

        for wf in self.wizard.state.existing_workflows:
            table.add_row(
                wf.path.name,
                str(wf.lockfile_rel_path) if wf.lockfile_rel_path else "[#5E5E5E]?[/]",
                self._format_component(wf, components_by_id),
                self._format_release(wf.release_strategy),
                self._format_augment(wf.augment),
            )
        table.focus()

    @staticmethod
    def _format_component(wf: "ExistingWorkflow", names: dict[str, str]) -> str:
        if wf.component_id is None:
            return "[#F87171](missing COMPONENT_ID)[/]"
        resolved = names.get(wf.component_id)
        if resolved:
            return f"{resolved}  [#5E5E5E]·[/] [#CBCCCE]{wf.component_id}[/]"
        return f"[#F4B57F]?[/] [#CBCCCE]{wf.component_id}[/]"

    @staticmethod
    def _format_release(strategy: str | None) -> str:
        if strategy is None:
            return "[#F4B57F]?[/]"
        return {
            "latest": "[#8A7DFF]latest[/]",
            "tag": "[#CC58BB]tag[/]",
            "manual": "[#F4B57F]manual[/]",
            "none": "[#5E5E5E]none[/]",
        }.get(strategy, strategy)

    @staticmethod
    def _format_augment(augment: bool | None) -> str:
        if augment is None:
            return "[#5E5E5E]?[/]"
        return "[#4ADE80]on[/]" if augment else "[#5E5E5E]off[/]"

    def action_edit_selected(self) -> None:
        self._edit_selected()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "edit":
            self._edit_selected()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        # Enter on a DataTable row fires RowSelected. Treat that as Edit.
        self._edit_selected()

    def _edit_selected(self) -> None:
        table = self.query_one("#workflow-table", DataTable)
        row_idx = table.cursor_row
        workflows = self.wizard.state.existing_workflows
        if row_idx is None or not (0 <= row_idx < len(workflows)):
            self.app.bell()
            return
        from sbomify_action.cli.wizard.screens.edit_workflow import EditWorkflowScreen

        self.wizard.push_screen(EditWorkflowScreen(workflows[row_idx]))
