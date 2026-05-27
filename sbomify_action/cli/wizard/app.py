"""Textual entrypoint for the sbomify wizard.

The wizard is a stack of ``WizardScreen`` subclasses. Each screen
reads from / writes to a single shared ``WizardState`` instance on the
app so state survives screen transitions. Background I/O runs on
``@work(thread=True)`` workers, so the UI never blocks.

Phases:

  1. welcome        — banner + repo summary + start button
  2. discover       — multi-select lockfiles
  3. authenticate   — token entry + parallel workspace prefetch
  4. product        — pick existing or create new
  5. configure      — release strategy + credential + augmentation
                      + per-component name
  6. review         — table of planned writes + confirm
  6b. apply         — RichLog + progress bar
  6c. done          — summary + OIDC binding instructions
"""

from __future__ import annotations

from textual.app import App
from textual.binding import Binding

from sbomify_action.cli.wizard import discovery
from sbomify_action.cli.wizard.existing import wizard_workflow_exists
from sbomify_action.cli.wizard.options import WizardOptions
from sbomify_action.cli.wizard.repo_facts import gather_repo_facts
from sbomify_action.cli.wizard.state import WizardState


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
        # Read-only observations are gathered synchronously *before* the app
        # mounts, so the welcome screen can render accurate coverage stats
        # without flashing empty state or waiting on a worker.
        facts = gather_repo_facts(opts.repo_root)
        discovered = discovery.discover(opts.repo_root, repo_name=facts.suggested_repo_name)
        self.state: WizardState = WizardState(
            facts=facts,
            discovered=discovered,
            workflow_exists=wizard_workflow_exists(opts.repo_root),
        )

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


__all__ = ["WizardApp", "launch_wizard"]
