"""Discover screen — multi-select lockfiles to track."""

from __future__ import annotations

from pathlib import PurePath

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, SelectionList, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen
from sbomify_action.cli.wizard.state import NestedRepoKind

# How each nested-repo kind is described in a row annotation.
_NESTED_REPO_LABELS: dict[NestedRepoKind | None, str] = {
    "submodule": "submodule",
    "vendored": "vendored repo",
}

#: Top-level directories whose lockfiles describe how the project is built,
#: tested or documented rather than what it ships.
#:
#: Matched only at the top level, deliberately. A `docs/` directory beside the
#: root is the project's documentation; a `packages/web/docs/` inside a
#: monorepo may be a published component, and a rule that skipped both would
#: hide real dependencies to avoid a nuisance.
_TOOLING_DIRS = frozenset(
    {
        ".ci",
        ".github",
        ".gitlab",
        "bench",
        "benchmark",
        "benchmarks",
        "ci",
        "contrib",
        "demo",
        "demos",
        "doc",
        "docs",
        "e2e",
        "example",
        "examples",
        "samples",
        "script",
        "scripts",
        "test",
        "testing",
        "tests",
        "tools",
    }
)


def _is_tooling(rel_path: PurePath) -> bool:
    """Whether this input describes the project's tooling rather than the project."""
    parts = rel_path.parts
    return len(parts) > 1 and parts[0].lower() in _TOOLING_DIRS


class DiscoverScreen(WizardScreen):
    """Phase 2 — multi-select discovered lockfiles."""

    step_index = 2
    step_title = "Discover lockfiles"
    step_subtitle = "Pick the lockfiles the SBOM workflow should track."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        # priority so the SelectionList can't swallow Escape.
        Binding("escape", "app.pop_screen", "Back", show=True, priority=True),
        # priority=True so this wins over SelectionList's own Space binding.
        # Not for behaviour — ``action_toggle_selection`` calls straight
        # through to ``SelectionList.action_select`` — but for the footer:
        # a binding shadowed by the focused widget is never rendered, so
        # without priority the screen's primary interaction had no hint at
        # any terminal width, while the secondary "a / n" bulk keys did.
        Binding("space", "toggle_selection", "Toggle", show=True, priority=True),
        # Bulk operations for users with many lockfiles — Tab-and-Space
        # through 20 rows gets old fast.
        Binding("a", "select_all", "All", show=True),
        Binding("n", "select_none", "None", show=True),
    ]

    def compose_body(self) -> ComposeResult:
        panel = Vertical(classes="wizard-panel")
        panel.border_title = "◆  Lockfiles"
        panel.border_subtitle = f"{len(self.wizard.state.discovered)} found"
        with panel:
            yield Static(
                "Use [b]Space[/] to toggle each lockfile, [b]a[/] to select all, "
                "[b]n[/] to select none, [b]Enter[/] when you're done.",
                classes="wizard-help",
            )
            if any(lf.nested_repo for lf in self.wizard.state.discovered):
                # ``wizard-muted``, not ``wizard-help``: this is the only
                # explanation for why some rows arrive pre-deselected, so
                # dropping it in compact mode left those rows looking
                # arbitrary. Help prose is expendable on small terminals;
                # the reason a default was chosen for the user is not.
                yield Static(
                    "[#F4B57F]Lockfiles inside submodules or vendored repos are deselected "
                    "by default — they belong to another repository, so set up SBOMs there "
                    "instead.[/]",
                    id="nested-repo-note",
                    classes="wizard-muted",
                )
            # Same reasoning as the nested-repo note: a row that arrives
            # unticked without an explanation looks arbitrary, and this is the
            # only place the reason appears.
            if any(_is_tooling(lf.rel_path) for lf in self.wizard.state.discovered):
                yield Static(
                    "[#F4B57F]Lockfiles under tests/, docs/, examples/ and similar are "
                    "deselected by default — they describe how this project is built or "
                    "tested, not what it ships.[/]",
                    id="tooling-note",
                    classes="wizard-muted",
                )
            yield SelectionList[int](id="lockfile-list")

    def compose_actions(self) -> ComposeResult:
        # The "pick at least one" validation message lives with the buttons,
        # not inside the scrolling panel — it fires in response to pressing
        # Next, so it has to be visible from wherever Next is.
        yield Static("", id="discover-status", markup=True)
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("Next  ▸", id="next", variant="primary")

    def _default_selected(self) -> set[int]:
        """Indices to tick on arrival.

        Everything used to be ticked, which is fine for the median repo --
        six lockfiles -- and wrong for the ones that matter. Measured across
        251 repositories the mean was 31.8, forty-two had more than fifty,
        and nine hit the discovery cap of 200: vite, next.js, spring-boot,
        rust-lang/rust, deno. Pressing Enter on vite created two hundred
        sbomify components, most of them scaffolding templates
        (`packages/create-vite/template-lit/package.json`) that are not
        dependencies of vite at all.

        So: tick the shallowest depth that has anything selectable, and
        leave the rest listed but unticked. A polyglot root still gets both
        of its lockfiles; a monorepo gets its top-level one instead of every
        package underneath.

        Depth rather than "root only", which was the first idea and is
        wrong: thirty of those repositories have no lockfile at the root at
        all, and ticking nothing leaves the user on a screen that refuses to
        advance. Replayed over the same corpus this rule takes the mean from
        31.8 to 1.5 and the worst case from 200 to 52, and never selects
        nothing.
        """
        selectable = [(idx, lf) for idx, lf in enumerate(self.wizard.state.discovered) if lf.nested_repo is None]
        if not selectable:
            return set()

        # Tooling is skipped for the same reason nested repos are: it is not
        # what this project ships. The difference is that it only bites when
        # there is nothing at the root, which is exactly when the fallthrough
        # is invisible -- a C project has no lockfile we support, so the
        # shallowest thing left is whatever its CI installs.
        #
        # curl is the case that named this. At curl-8_21_0 the candidates are
        # .github/scripts/requirements.txt, tests/requirements.txt,
        # tests/http/requirements.txt and a Windows solution template; the
        # shallowest is tests/requirements.txt, and the run produces a
        # one-component SBOM called "curl" that describes curl's test harness.
        #
        # Measured over 353 repositories: 60 have no root-level input at all,
        # and 29 of those default to a tooling directory. Homebrew/brew to
        # docs/Gemfile.lock, NixOS/nixpkgs to ci/github-script/package-lock.json,
        # ocaml/dune to doc/requirements.txt, and emqx/emqx to
        # scripts/sbom/requirements.txt.
        real = [(idx, lf) for idx, lf in selectable if not _is_tooling(lf.rel_path)]

        # Never select nothing -- the invariant above. A repository that is
        # *only* tooling still has to advance, and the user can see what was
        # ticked and untick it.
        tier = real or selectable
        shallowest = min(len(lf.rel_path.parts) for _idx, lf in tier)
        return {idx for idx, lf in tier if len(lf.rel_path.parts) == shallowest}

    def on_mount(self) -> None:
        sel = self.query_one("#lockfile-list", SelectionList)
        default = self._default_selected()
        for idx, lf in enumerate(self.wizard.state.discovered):
            label = f"{lf.rel_path}  [#5E5E5E]({lf.ecosystem})[/]"
            if lf.nested_repo:
                # Both fields are optional on DiscoveredLockfile, so an
                # unset/unknown kind falls back to a neutral label rather
                # than claiming "vendored".
                kind = _NESTED_REPO_LABELS.get(lf.nested_repo_kind, "nested repo")
                label += f"  [#F4B57F]({kind}: {lf.nested_repo})[/]"
            # What starts ticked is decided by _default_selected: the
            # shallowest depth that has anything selectable, with nested-repo
            # lockfiles excluded entirely because they belong to another
            # repository. So a deeper lockfile of this repo's own is listed
            # and left unticked too, not only a vendored one.
            sel.add_option((label, idx, idx in default))
        sel.focus()

    def action_toggle_selection(self) -> None:
        """Custom toggle action — Textual's built-in `action_toggle` is generic."""
        self.query_one("#lockfile-list", SelectionList).action_select()
        self._clear_status()

    def action_select_all(self) -> None:
        self.query_one("#lockfile-list", SelectionList).select_all()
        self._clear_status()

    def action_select_none(self) -> None:
        self.query_one("#lockfile-list", SelectionList).deselect_all()
        self._clear_status()

    def action_submit(self) -> None:
        self.route_enter(self._advance)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()

    def _advance(self) -> None:
        sel = self.query_one("#lockfile-list", SelectionList)
        indices = list(sel.selected)
        if not indices:
            # Replace the silent bell with a visible hint so the user
            # knows why nothing happened.
            status = self.query_one("#discover-status", Static)
            status.update(
                "[#F87171]Pick at least one lockfile to continue — "
                "press [b]Space[/] to toggle, [b]a[/] to select all.[/]"
            )
            self.app.bell()
            return
        self.wizard.state.selected = [self.wizard.state.discovered[i] for i in indices]
        from sbomify_action.cli.wizard.screens.authenticate import AuthenticateScreen

        self.wizard.push_screen(AuthenticateScreen())

    def _clear_status(self) -> None:
        try:
            self.query_one("#discover-status", Static).update("")
        except Exception:  # noqa: BLE001
            pass
