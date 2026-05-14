"""Review screen — DataTable of every planned change + apply confirmation."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Label, RadioButton, RadioSet, Static

from sbomify_action.cli.wizard import ci_emitter
from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import WorkflowFileAction


class ReviewScreen(WizardScreen):
    """Phase 5 — show the plan, resolve any file conflicts, then apply."""

    step_index = 6
    step_title = "Review"
    step_subtitle = "Nothing has been written or sent to sbomify yet. Last chance to bail."

    BINDINGS = [
        Binding("enter", "apply", "Apply", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._planned_files: list[tuple[Path, str, WorkflowFileAction]] = []

    def compose_body(self) -> ComposeResult:
        with Vertical(classes="wizard-panel"):
            yield Static("[b #8A7DFF]On sbomify[/]", classes="wizard-title")
            yield Static(id="api-plan", markup=True)
            yield Static("")
            yield Static("[b #8A7DFF]Filesystem[/]", classes="wizard-title")
            yield DataTable(id="file-plan", cursor_type="row", zebra_stripes=True)
            yield Static("")
            yield Static("", id="conflict-header", markup=True)
            yield Vertical(id="conflict-pane")
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Apply  ▸", id="apply", variant="primary")

    def on_mount(self) -> None:
        self._materialise_plan()
        self._render_api_summary()
        self._render_file_table()
        self._render_conflicts()
        if self.wizard.opts.dry_run:
            apply_btn = self.query_one("#apply", Button)
            apply_btn.label = "Dry-run · close"
        self.query_one("#apply", Button).focus()

    def _materialise_plan(self) -> None:
        plan = self.wizard.state.plan
        # sbomify.json writes are derived from per-component "local" strategy
        # (currently unreachable in the MVP; preserved for forward compat).
        plan.sbomify_json_files = [
            (planned.lockfile.path.parent / "sbomify.json", planned.sbomify_json)
            for planned in plan.create_components
            if planned.augmentation == "local" and planned.sbomify_json
        ]
        opts = self.wizard.opts
        self._planned_files = ci_emitter.plan_workflow_files(
            plan=plan,
            output_dir=opts.output_dir,
            api_base_url=opts.api_base_url,
            default_branch=self.wizard.state.facts.default_branch,
            product_id=plan.use_product_id or "<product-id>",
        )

    def _render_api_summary(self) -> None:
        plan = self.wizard.state.plan
        rows: list[str] = []
        rows.append(f"  [#8A7DFF]API[/]      {self.wizard.opts.api_base_url}")
        if plan.create_product:
            rows.append(f"  [#F4B57F]+[/] Product   create [#FFFFFF]{plan.create_product}[/]")
        elif plan.use_product_id:
            rows.append(f"  [#8A7DFF]·[/] Product   use existing  [#CBCCCE]{plan.use_product_id}[/]")
        rows.append(
            f"  [#F4B57F]+[/] Components create [#FFFFFF]{len(plan.create_components)}[/] "
            "(attached via hidden helper project)"
        )
        for comp in plan.create_components:
            release_label = comp.release_strategy
            aug_label = comp.augmentation
            rows.append(
                f"      [#CBCCCE]·[/] {comp.name}   "
                f"[#5E5E5E]release=[/]{release_label}   "
                f"[#5E5E5E]augment=[/]{aug_label}"
            )
        if plan.create_initial_release:
            rows.append(
                "  [#F4B57F]+[/] Release   pre-create [#FFFFFF]v0.0.0[/] (prerelease) for tag-strategy components"
            )
        self.query_one("#api-plan", Static).update("\n".join(rows))

    def _render_file_table(self) -> None:
        table = self.query_one("#file-plan", DataTable)
        table.clear(columns=True)
        table.add_columns("Action", "Path")
        for path, _content, action in self._planned_files:
            verb, colour = {
                "write": ("write", "#4ADE80"),
                "write_new": ("write .new", "#F4B57F"),
                "skip": ("skip", "#CBCCCE"),
            }[action]
            table.add_row(f"[{colour}]{verb}[/]", str(path))
        for path, _ in self.wizard.state.plan.sbomify_json_files:
            table.add_row("[#4ADE80]write[/]", str(path))
        if table.row_count == 0:
            table.add_row("[#CBCCCE]·[/]", "[#5E5E5E]nothing to write[/]")

    def _render_conflicts(self) -> None:
        conflicts = [(i, path) for i, (path, _, action) in enumerate(self._planned_files) if action == "skip"]
        header = self.query_one("#conflict-header", Static)
        pane = self.query_one("#conflict-pane", Vertical)
        pane.remove_children()
        if not conflicts:
            header.update("")
            return
        header.update(
            f"[b #F4B57F]File conflicts[/]\n"
            f"[#CBCCCE]{len(conflicts)} file(s) already exist. Pick what to do for each:[/]"
        )
        for idx, path in conflicts:
            pane.mount(Label(f"  [#FFFFFF]{path}[/]", markup=True))
            radio = RadioSet(id=f"conflict-{idx}")
            radio.styles.margin = (0, 0, 1, 2)
            pane.mount(radio)
            radio.mount(RadioButton("Skip (keep existing)", id=f"conflict-{idx}-skip", value=True))
            radio.mount(RadioButton("Overwrite", id=f"conflict-{idx}-write"))
            radio.mount(RadioButton("Write to .new alongside", id=f"conflict-{idx}-write_new"))

    def action_apply(self) -> None:
        self._apply()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "apply":
            self._apply()

    def _apply(self) -> None:
        resolved: list[tuple[Path, str, WorkflowFileAction]] = []
        for idx, (path, content, action) in enumerate(self._planned_files):
            if action == "skip":
                resolved_action = self._read_conflict_choice(idx)
            else:
                resolved_action = action
            resolved.append((path, content, resolved_action))
        self.wizard.state.plan.workflow_files = resolved

        if self.wizard.opts.dry_run:
            from sbomify_action.cli.wizard.screens.done import DoneScreen

            self.wizard.push_screen(DoneScreen(dry_run=True))
            return

        from sbomify_action.cli.wizard.screens.apply import ApplyScreen

        self.wizard.push_screen(ApplyScreen())

    def _read_conflict_choice(self, idx: int) -> WorkflowFileAction:
        for action in ("skip", "write", "write_new"):
            try:
                button = self.query_one(f"#conflict-{idx}-{action}", RadioButton)
            except Exception:
                continue
            if button.value:
                return action  # type: ignore[return-value]
        return "skip"
