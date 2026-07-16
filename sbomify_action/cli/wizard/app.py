"""Textual entrypoint for the sbomify wizard.

The wizard is a stack of ``WizardScreen`` subclasses. Each screen
reads from / writes to a single shared ``WizardState`` instance on the
app so state survives screen transitions. Background I/O runs on
``@work(thread=True)`` workers, so the UI never blocks.

Phases (``step_index`` on each ``WizardScreen``):

  1. welcome              — hero, repo summary, start button
  2. discover             — multi-select lockfiles
  3. authenticate         — token entry + parallel workspace prefetch
  4. product              — pick existing or create new
  5. components           — pick existing or create per lockfile
  6. configure (workflow) — release strategy + credential + augmentation
  7. configure (SBOM)     — enrichment / formats / attestation /
                            (when augmentation=profile) profile picker /
                            (when augmentation=json_config) push to
                            configure (sbomify.json) for the in-repo
                            metadata form
  8. review + apply        — table of planned writes → RichLog progress
  9. publish + done        — optional local generate-and-upload of the
                             first SBOMs (one pipeline subprocess per
                             matrix row) → summary panel + OIDC
                             instructions
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
        Binding("question_mark", "show_help", "Help", priority=True, show=True),
    ]

    def __init__(self, opts: WizardOptions) -> None:
        super().__init__()
        self.opts = opts
        # Track Ctrl-C presses for double-tap-to-quit confirmation.
        # A single press shows a notification; a second within the
        # window actually exits. Stops accidental keypresses from
        # killing a wizard mid-API-call.
        self._last_cancel_press: float = 0.0
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
        """Double-tap quit. First press shows a notification; a second
        press within ``_CANCEL_WINDOW`` seconds actually exits.

        Stops accidental Ctrl-C keypresses from killing a wizard mid-
        API-call. The 3-second window is short enough that confirming
        feels intentional but long enough that the user has time to
        read the notification.
        """
        import time

        cancel_window = 3.0
        now = time.monotonic()
        if now - self._last_cancel_press < cancel_window:
            self.exit(130)
            return
        self._last_cancel_press = now
        self.notify(
            "Press Ctrl-C again within 3 seconds to quit.",
            title="◆  Quit the wizard?",
            severity="warning",
            timeout=cancel_window,
        )

    def action_show_help(self) -> None:
        """Push the global keybind cheat sheet over the current screen."""
        from sbomify_action.cli.wizard.screens.help import HelpScreen

        self.push_screen(HelpScreen())

    def action_open_url(self, url: str) -> None:
        """Hand a URL off to the user's default browser.

        Used by ``@click=app.open_url('…')`` markup on Static widgets
        so docs links in the wizard are actually clickable. If we
        can't reach a browser (headless box, no DISPLAY, etc.) this
        silently no-ops — the URL itself is still rendered as text so
        the user can copy it.
        """
        import webbrowser

        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass


def launch_wizard(opts: WizardOptions) -> int:
    """Run the Textual wizard. Returns the process exit code."""
    return WizardApp(opts).run() or 0


__all__ = ["WizardApp", "launch_wizard"]
