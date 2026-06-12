"""Done screen — summary of what apply did + OIDC binding instructions."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen


class DoneScreen(WizardScreen):
    """Phase 6c — summary + next steps."""

    step_index = 8
    step_title = "Done"
    step_subtitle = "All set. Here's what you'll want to do next."

    BINDINGS = [
        Binding("enter", "finish", "Finish", show=True, priority=True),
        # Done is terminal — there's nothing useful to go 'back' to,
        # since apply already committed the plan. Treat Escape as a
        # synonym for Finish so it exits the wizard instead of
        # popping back to the Apply screen (which would just re-show
        # the success log from the run that already happened).
        Binding("escape", "finish", "Finish", show=True, priority=True),
        # One-keystroke 'copy first OIDC settings URL to clipboard' so
        # users don't have to drag-select a multi-line URL inside the
        # TUI. Only useful when there's at least one URL to copy; the
        # action no-ops cleanly when there isn't.
        Binding("c", "copy_first_url", "Copy URL", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        applied = Vertical(classes="wizard-panel-emphasis")
        applied.border_title = "✓  Applied"
        applied.border_subtitle = "From zero to SBOM hero"
        with applied:
            yield Static(self._applied_summary(), classes="wizard-muted")

        if self.wizard.state.plan.credential_mode == "oidc":
            state = self.wizard.state
            if state.is_dry_run:
                # Dry-run never actually mutated anything — render a preview
                # panel that surfaces the would-have-registered note without
                # claiming the binding exists. Without this branch, the
                # success card below would fire whenever oidc_binding_note is
                # set on a slug-present dry-run.
                oidc = Vertical(classes="wizard-panel")
                oidc.border_title = "◌  OIDC trusted publishing (dry-run preview)"
                with oidc:
                    yield Static(self._oidc_dry_run_preview(), classes="wizard-muted")
            elif state.oidc_bindings_registered and not state.oidc_failed_components:
                # Fully auto-registered during apply — nothing left to do.
                # Failures are tracked per-component now, so a partial success
                # falls through to the manual-fallback branch and lists ONLY
                # the failed components rather than blanket-listing all of
                # them (the prior behaviour, which made users re-bind already-
                # bound components and hit 409 errors).
                oidc = Vertical(classes="wizard-panel-emphasis")
                oidc.border_title = "✓  OIDC trusted publishing is set up"
                with oidc:
                    yield Static(self._oidc_success(), classes="wizard-muted")
            else:
                # Auto-registration was skipped or failed — show the reason
                # (oidc_binding_note) and the manual fallback instructions.
                oidc = Vertical(classes="wizard-panel")
                oidc.border_title = "⚠  One more step — set up OIDC trusted publishing"
                with oidc:
                    yield Static(self._oidc_instructions(), classes="wizard-muted")
        else:
            tok = Vertical(classes="wizard-panel")
            tok.border_title = "⚠  Add the SBOMIFY_TOKEN secret"
            with tok:
                yield Static(self._token_instructions(), classes="wizard-muted")

        with Horizontal(classes="button-row"):
            yield Button("Finish", id="finish", variant="primary")

    def on_mount(self) -> None:
        self.query_one("#finish", Button).focus()

    def action_finish(self) -> None:
        self.wizard.exit(0)

    def action_copy_first_url(self) -> None:
        """Copy the component page URL for the first applied component."""
        state = self.wizard.state
        if not state.component_ids:
            self.notify(
                "No components were applied — nothing to copy.",
                severity="warning",
            )
            return
        if state.is_dry_run:
            # The component IDs in dry-run are synthetic placeholders
            # (eg ``<dry-run:component:foo>``) that resolve to a 404 URL.
            # Refuse the action loudly rather than copying garbage that
            # looks plausible to paste into a browser.
            self.notify(
                "Dry-run preview — no real component IDs to copy. Re-run without --dry-run to get real URLs.",
                severity="warning",
            )
            return
        api_base = self.wizard.opts.api_base_url
        first_cid = next(iter(state.component_ids.values()))
        url = f"{api_base}/component/{first_cid}/"
        self.app.copy_to_clipboard(url)
        self.notify(f"Copied {url} to clipboard.", severity="information")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "finish":
            self.wizard.exit(0)

    def _applied_summary(self) -> str:
        state = self.wizard.state
        lines: list[str] = []
        if state.created_product_id:
            lines.append(f"[#86EFAC]✓[/]  [#CBCCCE]Product[/]    {state.created_product_id}")
        if state.component_ids:
            # Reused components don't deserve the same green-checkmark
            # weight as newly-created ones — re-running the wizard
            # against an already-onboarded workspace should feel quiet,
            # not like every line is an "event". apply.apply_plan
            # populates state.reused_component_ids with both pre-picked
            # IDs and DUPLICATE_NAME-recovered IDs, so we don't need to
            # re-derive the set here.
            lines.append("[#86EFAC]✓[/]  [#CBCCCE]Components[/]")
            for rel, cid in state.component_ids.items():
                if cid in state.reused_component_ids:
                    glyph = "[#5E5E5E]·[/]"  # muted dot — reused, nothing changed
                    label = "[#5E5E5E]reused[/]"
                    cid_style = f"[#5E5E5E]{cid}[/]"
                else:
                    glyph = "[#86EFAC]+[/]"  # green plus — newly created
                    label = "[#86EFAC]created[/]"
                    cid_style = f"[b]{cid}[/]"
                lines.append(f"     {glyph}  {rel}  [#5E5E5E]→[/]  {cid_style}  {label}")
        if state.attach_error:
            # Components were created but attach failed — surface this
            # prominently so the user knows their workflow file points at
            # components that aren't actually linked to the product.
            lines.append(
                "[#F87171]✗[/]  [#CBCCCE]Attach[/]     [#F87171]failed — components are not linked to the product[/]"
            )
            lines.append(f"     [#5E5E5E]reason: {state.attach_error}[/]")
        # Dry-run "would write" rows use a muted glyph + label so the user
        # can tell from the summary that nothing actually hit disk. The
        # real-apply branch keeps the existing green ✓ + "Wrote" labelling.
        if state.is_dry_run:
            for path in state.written_files:
                lines.append(f"[#5E5E5E]◌  would write[/]  {path}")
        else:
            for path in state.written_files:
                lines.append(f"[#86EFAC]✓[/]  [#CBCCCE]Wrote[/]      {path}")
        # Outcome of the optional 'generate & upload now' step. None means it
        # was skipped or never offered, so say nothing in that case.
        if state.generated_ok is not None:
            total = state.generated_total
            ok = state.generated_ok
            if total and ok == total:
                lines.append(f"[#86EFAC]✓[/]  [#CBCCCE]SBOMs[/]      generated + uploaded {ok}")
            elif ok:
                lines.append(f"[#F4B57F]⚠[/]  [#CBCCCE]SBOMs[/]      uploaded {ok}/{total} — see the generate log")
            else:
                lines.append(
                    "[#F87171]✗[/]  [#CBCCCE]SBOMs[/]      generation didn't upload anything — see the generate log"
                )
        if not lines:
            lines.append("[#5E5E5E]◌  (nothing applied)[/]")
        return "\n".join(lines)

    def _oidc_success(self) -> str:
        state = self.wizard.state
        slug = state.facts.owner_repo_slug or "your repository"
        newly = state.oidc_newly_registered
        already = state.oidc_bindings_registered - newly
        if newly and already:
            headline = (
                f"Registered the trusted publisher for [b]{slug}[/] on {newly} new "
                f"component(s); {already} already had a binding."
            )
        elif newly:
            headline = f"Registered the trusted publisher for [b]{slug}[/] on {newly} component(s)."
        else:
            # All bindings pre-existed — re-runs land here. Don't claim
            # "registered" since nothing was created this round.
            headline = f"Trusted publisher for [b]{slug}[/] was already set on {already} component(s) — nothing to do."
        return "\n".join(
            [
                headline,
                "",
                "Nothing else to do — pushing to the default branch will mint a short-lived",
                "token via OIDC and publish your first SBOM.",
            ]
        )

    def _oidc_instructions(self) -> str:
        state = self.wizard.state
        api_base = self.wizard.opts.api_base_url
        slug = state.facts.owner_repo_slug or "<owner>/<repo>"
        lines: list[str] = []
        # Explain WHY auto-registration didn't happen (private repo, missing
        # slug, not owner/admin, backend error) before the manual steps.
        if state.oidc_binding_note:
            lines.extend([state.oidc_binding_note, ""])
        lines += [
            "Trusted publishing needs an OIDC binding per component in the sbomify UI.",
            "",
            f"  Repository: [b]{slug}[/]",
            "",
        ]
        # Partial success — list ONLY the components that failed, not the ones
        # that were already auto-bound. Telling the user to manually re-bind
        # successful components produces 409 noise and confusion.
        if state.oidc_failed_components:
            failed_count = len(state.oidc_failed_components)
            bound_count = state.oidc_bindings_registered
            if bound_count:
                lines.append(
                    f"[#86EFAC]✓[/] {bound_count} component(s) auto-registered. "
                    f"The remaining {failed_count} need manual setup:"
                )
            else:
                lines.append("For each component:")
            for rel, _err in state.oidc_failed_components.items():
                cid = state.component_ids.get(rel, "")
                lines.append(f"  · {rel}  →  {api_base}/component/{cid}/")
        else:
            # Whole-step skip (no slug detected, or no components yet) — list
            # every applied component for manual setup.
            lines.append("For each component:")
            for rel, cid in state.component_ids.items():
                lines.append(f"  · {rel}  →  {api_base}/component/{cid}/")
        lines.extend(
            [
                "",
                "Open each link → [b]Trusted Publishing → Add binding[/] → paste the repository slug.",
                "After that, pushing to the default branch will mint a short-lived token via OIDC and publish your first SBOM.",
            ]
        )
        return "\n".join(lines)

    def _oidc_dry_run_preview(self) -> str:
        state = self.wizard.state
        slug = state.facts.owner_repo_slug
        if slug:
            count = len(state.component_ids)
            return "\n".join(
                [
                    f"Would register the trusted publisher for [b]{slug}[/] on {count} component(s).",
                    "",
                    "No binding was actually created — this is a preview only.",
                    "Re-run without [b]--dry-run[/] to apply.",
                ]
            )
        # No slug — the real apply would also fall through to manual
        # instructions. Surface the same explanation in preview form.
        return state.oidc_binding_note or (
            "Couldn't detect a GitHub 'owner/repo' from the git remote, so the "
            "trusted publisher would need to be registered manually."
        )

    def _token_instructions(self) -> str:
        return (
            "Add a repository secret named [b]SBOMIFY_TOKEN[/] with a sbomify API token "
            "(Repository → Settings → Secrets and variables → Actions → New repository secret).\n"
            "After that, pushing to the default branch will publish your first SBOM."
        )
