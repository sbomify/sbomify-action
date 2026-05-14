"""WizardApp — Textual entrypoint for the interactive sbomify wizard.

The wizard is composed as a sequence of `Screen` subclasses pushed onto
the stack by the app. Each screen reads from / writes to a single shared
`WizardState` instance on the app so that state survives screen
transitions. Background I/O (API calls, git/gh subprocess) runs on
worker threads via Textual's `@work(thread=True)` decorator so the UI
never blocks.

Phases (one screen each, except `configure` which iterates per
component):

  0. welcome              ─ banner, intro, "start"
  1. discover             ─ multi-select lockfiles
  2. authenticate         ─ token entry + workspace prefetch
  3. product              ─ pick existing or create new
  4. configure            ─ per-component name/augmentation/release
  5. review               ─ DataTable of planned writes + apply confirm
  6. apply                ─ ProgressBar + RichLog as side effects happen
  6.5. generate (optional)─ local SBOM gen to confirm wiring
  6.7. pr (optional)      ─ gh pr create
  7. done                 ─ summary + next steps
"""

from __future__ import annotations

from typing import Literal

from textual.app import App
from textual.binding import Binding

from sbomify_action.cli.wizard import discovery
from sbomify_action.cli.wizard.existing import detect_existing_workflows
from sbomify_action.cli.wizard.options import WizardOptions
from sbomify_action.cli.wizard.repo_facts import gather_repo_facts
from sbomify_action.cli.wizard.state import WizardState

#: Top-level intent picked on the welcome screen. Authenticate routes to a
#: different next screen based on which one the user chose.
FlowMode = Literal["onboard", "edit"]


class WizardApp(App[int]):
    """Textual app implementing the sbomify-action onboarding wizard."""

    CSS_PATH = "styles.tcss"
    TITLE = "sbomify wizard"
    SUB_TITLE = "From zero to SBOM hero"

    BINDINGS = [
        Binding("ctrl+c", "quit_with_cancel", "Cancel", priority=True, show=True),
        Binding("ctrl+q", "quit_with_cancel", "Cancel", show=False),
    ]

    def __init__(self, opts: WizardOptions) -> None:
        super().__init__()
        self.opts = opts
        # Facts, lockfile discovery, and existing-workflow detection all run
        # synchronously before App.run() so the welcome screen can render
        # accurate coverage stats ("found jobs for N/M lockfiles") without
        # flashing empty state or waiting on a worker.
        facts = gather_repo_facts(opts.repo_root)
        existing = detect_existing_workflows(opts.repo_root)
        discovered = discovery.discover(opts.repo_root)
        self.state: WizardState = WizardState(
            facts=facts,
            discovered=discovered,
            existing_workflows=existing,
        )
        # Tracks ordinal step for the progress crumb in screen headers.
        # 6 user-facing steps; apply (and generate/pr) share the apply phase.
        self.total_steps = 6
        # Default flow is the full onboarding wizard. Set to "edit" on the
        # welcome screen when the user picks "Edit existing workflows" —
        # AuthenticateScreen reads this to decide where to push next.
        self.flow_mode: FlowMode = "onboard"

    def on_mount(self) -> None:
        # Lazy import keeps screen imports off the hot path during test
        # collection (each screen pulls Textual widgets).
        from sbomify_action.cli.wizard.screens.welcome import WelcomeScreen

        self.push_screen(WelcomeScreen())

    def action_quit_with_cancel(self) -> None:
        """Ctrl-C / Ctrl-Q: cancel cleanly with a non-zero exit code."""
        self.exit(130)


def launch_wizard(opts: WizardOptions) -> int:
    """Run the Textual wizard. Returns the process exit code."""
    return WizardApp(opts).run() or 0


__all__ = ["WizardApp", "WizardOptions", "launch_wizard"]
