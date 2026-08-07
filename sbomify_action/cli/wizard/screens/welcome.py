"""Welcome screen — hero, tagline, what-we'll-do, repo summary, start CTA."""

from __future__ import annotations

from rich.text import Text
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
# Rows are colored to echo the sbomify gradient: peach hat tip,
# magenta hat base with stars, silvery beard (Gandalf cue), blue
# robe deepening to brand-primary at the hem. Pure ASCII (no
# box-drawing or exotic Unicode) so the figure renders uniformly
# across terminals and SSH sessions.
#
# The rows below are PLAIN TEXT. ``_build_mascot`` assembles them into a
# styled ``rich.text.Text`` — deliberately NOT a markup string.
#
# This art is almost entirely backslashes, and a backslash adjacent to a
# tag is an escape character in both markup dialects in play here. As
# hand-written markup, ``/\[/]`` made the top of the hat render as
# ``/[/]``: right edge eaten, closing tag printed as literal text. And
# the two dialects disagree on the fix — ``rich.markup.escape`` doubles a
# trailing backslash, which Rich unescapes but Textual's own parser
# renders as ``\`` *plus* a literal ``[/]``. Building a Text with explicit
# style spans sidesteps markup parsing altogether, so no escaping rule has
# to be right.
_MASCOT_FIGURE: list[tuple[str, str]] = [
    ("#F4B57F", "            *"),
    ("#F4B57F", "           /\\"),
    ("#F4B57F", "          /  \\"),
    ("#CC58BB", "         /    \\"),
    ("#CC58BB", "        /  *   \\"),
    ("#CC58BB", "       /        \\"),
    ("#CC58BB", "      /    *     \\"),
    ("#CC58BB", "     /            \\"),
    ("#CC58BB", "    /______________\\"),
    ("#CBCCCE", "        ~^~  ~^~"),
    ("#CBCCCE", "         o    o"),
    ("#CBCCCE", "          \\--/"),
    ("#E0E0E5", "         /WWWWW\\"),
    ("#E0E0E5", "        /WWWWWWW\\"),
    ("#E0E0E5", "       /WWWWWWWWW\\"),
    ("#E0E0E5", "      /WWWWWWWWWWW\\"),
    ("#8A7DFF", "      WWWWWWWWWWWWW"),
    ("#8A7DFF", "       WWWWWWWWWWW"),
    ("#4059D0", "        WWWWWWWWW"),
    ("#4059D0", "         WWWWWWW"),
    ("#4059D0", "          WWWWW"),
    ("#37306B", "           WWW"),
]

# The staff the wizard holds, drawn in its own color to the right of the
# figure. Each glyph is centered on ``_MASCOT_STAFF_COL``; rows not listed
# here (the hat tip, which the staff doesn't reach) get no staff.
_MASCOT_STAFF_COL = 25
_MASCOT_STAFF: dict[int, tuple[str, str]] = {
    **{3: ("#F4B57F", "( )")},
    **{row: ("#F4B57F", "|") for row in range(4, 21)},
    **{21: ("#37306B", "_|_")},
}


def _build_mascot() -> Text:
    """Compose the mascot as a styled ``Text`` from the plain rows above."""
    art = Text(no_wrap=True)
    for index, (color, figure) in enumerate(_MASCOT_FIGURE):
        if index:
            art.append("\n")
        art.append(figure, style=color)
        staff = _MASCOT_STAFF.get(index)
        if staff is not None:
            staff_color, glyph = staff
            start = _MASCOT_STAFF_COL - len(glyph) // 2
            art.append(" " * (start - len(figure)))
            art.append(glyph, style=staff_color)
    return art


ASCII_WIZARD = _build_mascot()


class WelcomeScreen(WizardScreen):
    """Phase 1 — hero + repo summary + start CTA."""

    step_index = 1
    step_title = "Welcome"
    step_subtitle = ""

    BINDINGS = [
        # priority=True so the binding wins over default Button activations —
        # we route Enter through ``route_enter`` (in WizardScreen) so a
        # focused Cancel button gets pressed instead of advancing the wizard.
        #
        # Two Enter bindings, gated by ``check_action``: with no lockfiles
        # there is nothing to continue *to* — Enter exits — so advertising
        # "Continue" in the footer would tell the user the opposite of what
        # the key does. Textual dispatches to the first enabled binding and
        # the Footer only renders enabled ones, so exactly one shows.
        Binding("enter", "start", "Continue", show=True, priority=True),
        Binding("enter", "exit_empty", "Exit", show=True, priority=True),
        Binding("escape", "app.quit_with_cancel", "Cancel", show=True),
    ]

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action == "start":
            return bool(self.wizard.state.discovered)
        if action == "exit_empty":
            return not self.wizard.state.discovered
        return True

    def action_exit_empty(self) -> None:
        """Enter on a repo with no lockfiles — leave immediately.

        ``app.quit_with_cancel`` is for accidental Ctrl-C presses mid-flow
        and needs a double-tap; pressing Enter on a dead-end screen is an
        explicit signal that the user wants out.
        """
        self.route_enter(lambda: self.wizard.exit(0))

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
                    # Trust chip — this tool's own source is SAST-scanned in CI.
                    yield Static(
                        "[#86EFAC]✓[/] [#CBCCCE]Scanned by[/] [b #8A7DFF]OpenGrep[/]",
                        classes="wizard-hero-badge",
                    )
                yield Static(ASCII_WIZARD, classes="wizard-hero-mascot")

        # No lockfiles → no point walking the rest of the wizard.
        # Surface a clear dead-end card and skip the "What we'll do"
        # preview so the user isn't promised six more steps that lead
        # nowhere.
        if not self.wizard.state.discovered:
            empty = Vertical(classes="wizard-panel")
            empty.border_title = "✗  No lockfiles found"
            empty.border_subtitle = "this wizard needs at least one"
            with empty:
                yield Static(
                    "[#F4B57F]The wizard scanned this repo and didn't find any "
                    "lockfiles it knows how to read.[/]\n\n"
                    "Supported lockfiles include [b]uv.lock[/], [b]poetry.lock[/], "
                    "[b]package-lock.json[/], [b]pnpm-lock.yaml[/], [b]bun.lock[/], "
                    "[b]yarn.lock[/], [b]go.sum[/], [b]Cargo.lock[/], "
                    "[b]composer.lock[/], [b]Gemfile.lock[/], "
                    "[b]Package.resolved[/], and a handful of manifests.\n\n"
                    "Full list: [#8A7DFF u]https://github.com/sbomify/"
                    "sbomify-action#supported-lockfiles[/]",
                    classes="wizard-muted",
                )

        # What-we'll-do — only when there's a path forward. Mirrors the
        # step indicator at the top of every screen so the mental model
        # is consistent throughout the wizard.
        if self.wizard.state.discovered:
            steps = Vertical(classes="wizard-panel", id="what-well-do")
            steps.border_title = "What we'll do"
            steps.border_subtitle = "8 steps · ~3 minutes"
            with steps:
                yield Static("\n".join(self._steps_list()))

        # Repo summary — observations from the current working tree.
        repo = Vertical(classes="wizard-panel")
        repo.border_title = "This repository"
        with repo:
            yield Static("\n".join(self._repo_lines()))

    def compose_actions(self) -> ComposeResult:
        with Horizontal(classes="button-row"):
            if self.wizard.state.discovered:
                yield Button("Start  ▸", id="start", variant="primary")
                yield Button("Cancel", id="cancel")
            else:
                # Nothing to onboard: leaving is the only action, so name the
                # button for what it does rather than offering a "Cancel" that
                # cancels nothing.
                yield Button("Exit", id="cancel", variant="primary")

    def on_mount(self) -> None:
        # When there's nothing to do, Start isn't rendered — focus the
        # Cancel button so Enter quits cleanly instead of dinging.
        try:
            self.query_one("#start", Button).focus()
        except Exception:
            self.query_one("#cancel", Button).focus()

    def action_start(self) -> None:
        # Route Enter through ``route_enter`` so a focused Cancel button gets
        # pressed instead of advancing — without this, a user who tabs to
        # Cancel and presses Enter still moves forward, which is the opposite
        # of what every other wizard screen does.
        self.route_enter(self._advance)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            self._advance()
        elif event.button.id == "cancel":
            # The Cancel button is an explicit, deliberate click — exit without
            # the Ctrl-C double-tap confirmation, which would otherwise show
            # the user a misleading "Press Ctrl-C again" notification despite
            # no Ctrl-C being involved.
            self.wizard.exit(130)

    def _advance(self) -> None:
        from sbomify_action.cli.wizard.screens.discover import DiscoverScreen

        self.wizard.push_screen(DiscoverScreen())

    def _steps_list(self) -> list[str]:
        # Numbering matches the progress crumb exactly — this screen is
        # step 01, so the work ahead starts at 02. The two used to disagree
        # (this list started at 01 and ended at 08 while the crumb had
        # already reached 08/08 on Review), which made the crumb look like
        # it had finished with two screens still to go.
        return [
            "[#8A7DFF]02[/]  Pick which lockfiles to track",
            "[#8A7DFF]03[/]  Authenticate against sbomify",
            "[#8A7DFF]04[/]  Pick a product",
            "[#8A7DFF]05[/]  Reuse or create a component per lockfile",
            "[#8A7DFF]06[/]  Configure the workflow shape (release / credentials / metadata)",
            "[#8A7DFF]07[/]  Configure SBOM content (enrichment / formats / provenance)",
            "[#8A7DFF]08[/]  Review the plan",
            "[#8A7DFF]09[/]  Apply — write the workflow file & finalise components",
        ]

    def _repo_lines(self) -> list[str]:
        facts = self.wizard.state.facts
        lockfile_count = len(self.wizard.state.discovered)
        lines = [
            f"[#CBCCCE]Repository[/]  [b]{facts.suggested_repo_name}[/]",
            f"[#CBCCCE]Branch    [/]  {facts.current_branch or facts.default_branch}",
            f"[#CBCCCE]Visibility[/]  {self._visibility_chip(facts.visibility)}",
            f"[#CBCCCE]Lockfiles [/]  [b]{lockfile_count}[/] found",
        ]
        if self.wizard.state.workflow_exists:
            lines.append(
                "[#F4B57F]⚠  A wizard-managed sboms.yml already exists — Review shows the diff before apply overwrites it.[/]"
            )
        if facts.has_release_tags:
            lines.append("[#86EFAC]✓  Release tags detected — tag-based strategy recommended.[/]")
        return lines

    @staticmethod
    def _visibility_chip(visibility: str) -> str:
        """One-liner chip describing the detected GitHub repo visibility."""
        if visibility == "public":
            return "[#86EFAC]✓ public[/]"
        if visibility == "private":
            return "[#F4B57F]⚠ private[/]  [#5E5E5E](attestation needs GitHub Enterprise Cloud)[/]"
        return "[#5E5E5E]◌ unknown[/]  [#5E5E5E](non-github remote or no network)[/]"
