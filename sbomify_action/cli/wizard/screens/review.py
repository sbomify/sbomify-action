"""Review screen — show the staged plan + diff before apply."""

from __future__ import annotations

import difflib
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, RichLog, Static

from sbomify_action.cli.wizard import ci_emitter
from sbomify_action.cli.wizard.existing import workflow_path
from sbomify_action.cli.wizard.screens._base import WizardScreen


class ReviewScreen(WizardScreen):
    """Phase 6 — show what apply will do, then confirm."""

    step_index = 8
    step_title = "Review"
    step_subtitle = "Apply nothing yet. Confirm the plan below to commit."

    BINDINGS = [
        Binding("enter", "apply", "Apply ▸", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        summary = Vertical(classes="wizard-panel")
        summary.border_title = "◆  Plan summary"
        summary.border_subtitle = "what apply will do"
        with summary:
            yield Static(self._summary(), classes="wizard-muted")

        components = Vertical(classes="wizard-panel")
        components.border_title = "◆  Components"
        components.border_subtitle = f"{len(self.wizard.state.plan.create_components)} planned"
        with components:
            yield DataTable(id="components-table", cursor_type="none", zebra_stripes=True)

        diff_panel = Vertical(classes="wizard-panel")
        target = workflow_path(self.wizard.state.facts.repo_root)
        verb = "overwrite" if self.wizard.state.workflow_exists else "create"
        diff_panel.border_title = f"◆  Diff — {verb} {target}"
        diff_panel.border_subtitle = "preview of what apply will write"
        with diff_panel:
            yield RichLog(id="workflow-diff", wrap=False, markup=True, highlight=False)

        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Apply  ▸", id="apply", variant="primary")

    def on_mount(self) -> None:
        table = self.query_one("#components-table", DataTable)
        table.add_columns("Lockfile", "Ecosystem", "Component", "Action")
        for c in self.wizard.state.plan.create_components:
            action = (
                "[#CBCCCE]reuse[/]"
                if c.existing_id is not None
                else "[#86EFAC]create[/]"
            )
            table.add_row(str(c.lockfile.rel_path), c.lockfile.ecosystem, c.name, action)
        self._render_diff()
        self.query_one("#apply", Button).focus()

    def action_apply(self) -> None:
        self._advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()

    def _advance(self) -> None:
        from sbomify_action.cli.wizard.screens.apply import ApplyScreen

        self.wizard.push_screen(ApplyScreen())

    def _summary(self) -> str:
        plan = self.wizard.state.plan
        workspace = self.wizard.state.workspace
        product_label = "(no product)"
        if plan.create_product:
            product_label = f"new: {plan.create_product}"
        elif plan.use_product_id and workspace:
            match = next(
                (p for p in workspace.products if str(p.get("id")) == plan.use_product_id),
                None,
            )
            if match:
                product_label = f"existing: {match.get('name')} ({plan.use_product_id})"
            else:
                product_label = f"existing: {plan.use_product_id}"
        formats_label = " + ".join(plan.sbom_formats) or "cyclonedx"
        attest_label = "on" if plan.attestation else "off"
        enrich_label = "on" if plan.enrich else "off"
        return (
            f"[#CBCCCE]Product           [/]  {product_label}\n"
            f"[#CBCCCE]Release strategy  [/]  {plan.release_strategy}\n"
            f"[#CBCCCE]Credentials       [/]  {plan.credential_mode}\n"
            f"[#CBCCCE]Augmentation      [/]  {plan.augmentation}\n"
            f"[#CBCCCE]Enrichment        [/]  {enrich_label}\n"
            f"[#CBCCCE]SBOM formats      [/]  {formats_label}\n"
            f"[#CBCCCE]Build provenance  [/]  {attest_label}"
        )

    def _render_diff(self) -> None:
        """Compute and paint the unified diff between the existing file
        (if any) and what apply will write.

        Component IDs that we already know about — existing components
        the user picked on the Components screen — are baked into the
        preview. Components scheduled to be *created* during apply
        appear as ``REPLACE_WITH_COMPONENT_ID`` placeholders since we
        don't have their real ids yet; a note above the diff calls
        that out so the user isn't surprised.
        """
        target = workflow_path(self.wizard.state.facts.repo_root)
        plan = self.wizard.state.plan
        component_ids = {
            str(c.lockfile.rel_path): c.existing_id
            for c in plan.create_components
            if c.existing_id is not None
        }
        new_content = ci_emitter.emit_workflow(
            plan,
            facts=self.wizard.state.facts,
            api_base_url=self.wizard.opts.api_base_url,
            component_ids=component_ids,
        )
        old_content = self._read_existing(target)

        log = self.query_one("#workflow-diff", RichLog)
        any_new_placeholders = "REPLACE_WITH_COMPONENT_ID" in new_content
        if any_new_placeholders:
            log.write(
                "[#5E5E5E]Note: REPLACE_WITH_COMPONENT_ID rows are placeholders "
                "for components apply will create. They'll be substituted with "
                "real ids in the file actually written to disk.[/]"
            )
            log.write("")

        diff_lines = list(
            difflib.unified_diff(
                old_content.splitlines(keepends=False),
                new_content.splitlines(keepends=False),
                fromfile=f"a/{target.name}" if old_content else "/dev/null",
                tofile=f"b/{target.name}",
                lineterm="",
            )
        )

        if not diff_lines:
            log.write("[#86EFAC]✓  No changes — the workflow file on disk already matches.[/]")
            return

        for line in diff_lines:
            log.write(self._stylise(line))

    @staticmethod
    def _read_existing(path: Path) -> str:
        if not path.exists():
            return ""
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return ""

    @staticmethod
    def _stylise(line: str) -> str:
        """Colour a single unified-diff line, escaping Rich markup."""
        # Escape stray '[' that might be Rich markup in the file content.
        escaped = line.replace("[", r"\[")
        if line.startswith("+++") or line.startswith("---"):
            return f"[b #8A7DFF]{escaped}[/]"
        if line.startswith("@@"):
            return f"[b #F4B57F]{escaped}[/]"
        if line.startswith("+"):
            return f"[#86EFAC]{escaped}[/]"
        if line.startswith("-"):
            return f"[#F87171]{escaped}[/]"
        return f"[#5E5E5E]{escaped}[/]"
