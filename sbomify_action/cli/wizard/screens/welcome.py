"""Welcome screen — hero, tagline, what-we'll-do, repo summary, start CTA."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen

# The sbomify marketing tagline. Same words as the home page hero.
TAGLINE = "Zero to SBOM Hero"

# Headline hero rendered with the sbomify signature gradient. Each
# segment is a slice of the blue → magenta → peach gradient that the
# marketing site uses for the homepage title.
HERO_TITLE = "[b][#4059D0]sbom[/][#CC58BB]ify[/][#F4B57F] wizard[/][/]"

# ASCII wizard mascot. Built from common ASCII art conventions (the
# /\ hat outline, WWW beard pattern, ( o o ) face) rather than copied
# from any one artist — a real wizard hat is at least as tall as the
# face + beard, which is what the previous draft was missing.
#
# Rows are coloured to echo the sbomify gradient: peach hat tip,
# magenta hat base with stars, silvery beard (Gandalf cue), blue
# robe deepening to brand-primary at the hem. Pure ASCII (no
# box-drawing or exotic Unicode) so the figure renders uniformly
# across terminals and SSH sessions.
ASCII_WIZARD = (
    "[#F4B57F]            *[/]\n"
    "[#F4B57F]           /\\[/]\n"
    "[#F4B57F]          /  \\[/]\n"
    "[#CC58BB]         /    \\         [#F4B57F]( )[/][/]\n"
    "[#CC58BB]        /  *   \\         [#F4B57F]|[/][/]\n"
    "[#CC58BB]       /        \\        [#F4B57F]|[/][/]\n"
    "[#CC58BB]      /    *     \\       [#F4B57F]|[/][/]\n"
    "[#CC58BB]     /            \\      [#F4B57F]|[/][/]\n"
    "[#CC58BB]    /______________\\     [#F4B57F]|[/][/]\n"
    "[#CBCCCE]        ~^~  ~^~         [#F4B57F]|[/][/]\n"
    "[#CBCCCE]         o    o          [#F4B57F]|[/][/]\n"
    "[#CBCCCE]          \\--/           [#F4B57F]|[/][/]\n"
    "[#E0E0E5]         /WWWWW\\         [#F4B57F]|[/][/]\n"
    "[#E0E0E5]        /WWWWWWW\\        [#F4B57F]|[/][/]\n"
    "[#E0E0E5]       /WWWWWWWWW\\       [#F4B57F]|[/][/]\n"
    "[#E0E0E5]      /WWWWWWWWWWW\\      [#F4B57F]|[/][/]\n"
    "[#8A7DFF]      WWWWWWWWWWWWW      [#F4B57F]|[/][/]\n"
    "[#8A7DFF]       WWWWWWWWWWW       [#F4B57F]|[/][/]\n"
    "[#4059D0]        WWWWWWWWW        [#F4B57F]|[/][/]\n"
    "[#4059D0]         WWWWWWW         [#F4B57F]|[/][/]\n"
    "[#4059D0]          WWWWW          [#F4B57F]|[/][/]\n"
    "[#37306B]           WWW          [#37306B]_|_[/][/]"
)


class WelcomeScreen(WizardScreen):
    """Phase 1 — hero + repo summary + start CTA."""

    step_index = 1
    step_title = "Welcome"
    step_subtitle = ""

    BINDINGS = [
        Binding("enter", "start", "Continue", show=True),
        Binding("escape", "app.quit_with_cancel", "Cancel", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        # Hero card — the wizard's first impression. Two columns:
        # gradient title + tagline + strap on the left, ASCII wizard
        # mascot on the right.
        hero = Vertical(classes="wizard-hero")
        hero.border_title = "◆  sbomify"
        with hero:
            with Horizontal(classes="wizard-hero-row"):
                with Vertical(classes="wizard-hero-text"):
                    yield Static(HERO_TITLE, classes="wizard-hero-title")
                    yield Static(f"[#CC58BB]{TAGLINE}[/]", classes="wizard-hero-tagline")
                    yield Static(
                        "Scans your repo for lockfiles, registers the matching "
                        "components in sbomify, and writes a release-ready GitHub "
                        "Actions workflow.",
                        classes="wizard-hero-strap",
                    )
                yield Static(ASCII_WIZARD, classes="wizard-hero-mascot")

        # What-we'll-do — six iconified steps, one per upcoming screen.
        # Mirrors the step indicator at the top of every screen so the
        # mental model is consistent throughout the wizard.
        steps = Vertical(classes="wizard-panel")
        steps.border_title = "What we'll do"
        steps.border_subtitle = "6 steps · ~3 minutes"
        with steps:
            yield Static("\n".join(self._steps_list()))

        # Repo summary — observations from the current working tree.
        repo = Vertical(classes="wizard-panel")
        repo.border_title = "This repository"
        with repo:
            yield Static("\n".join(self._repo_lines()))

        with Horizontal(classes="button-row"):
            yield Button("Start  ▸", id="start", variant="primary")
            yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#start", Button).focus()

    def action_start(self) -> None:
        self._advance()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            self._advance()
        elif event.button.id == "cancel":
            self.wizard.action_quit_with_cancel()

    def _advance(self) -> None:
        from sbomify_action.cli.wizard.screens.discover import DiscoverScreen

        self.wizard.push_screen(DiscoverScreen())

    def _steps_list(self) -> list[str]:
        return [
            "[#8A7DFF]01[/]  Pick which lockfiles to track",
            "[#8A7DFF]02[/]  Authenticate against sbomify",
            "[#8A7DFF]03[/]  Pick a product",
            "[#8A7DFF]04[/]  Configure the workflow (format / credentials / provenance)",
            "[#8A7DFF]05[/]  Review the plan",
            "[#8A7DFF]06[/]  Apply — create components & write the workflow file",
        ]

    def _repo_lines(self) -> list[str]:
        facts = self.wizard.state.facts
        lockfile_count = len(self.wizard.state.discovered)
        lines = [
            f"[#CBCCCE]Repository[/]  [b]{facts.suggested_repo_name}[/]",
            f"[#CBCCCE]Branch    [/]  {facts.current_branch or facts.default_branch}",
            f"[#CBCCCE]Lockfiles [/]  [b]{lockfile_count}[/] found",
        ]
        if self.wizard.state.workflow_exists:
            lines.append(
                "[#F4B57F]⚠  A wizard-managed sboms.yml already exists — it'll be backed up before overwrite.[/]"
            )
        if facts.has_release_tags:
            lines.append("[#86EFAC]✓  Release tags detected (v*) — tag-based strategy recommended.[/]")
        return lines
