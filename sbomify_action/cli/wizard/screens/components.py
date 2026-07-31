"""Components screen — pick or create a sbomify component per lockfile.

Lives between Product and Configure. For each selected lockfile the
user gets a ``PickOrCreate`` widget — same interaction the Product
screen uses, repeated once per lockfile — so they can either reuse an
existing component or create a new one. Names that match an existing
component exactly default to that component (re-running the wizard
against an already-onboarded workspace doesn't push toward duplicate
creates).
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static

from sbomify_action.cli.wizard.screens._base import WizardScreen, strip_status_codes
from sbomify_action.cli.wizard.state import PlannedComponent
from sbomify_action.cli.wizard.widgets import NEW_SENTINEL, PickOrCreate
from sbomify_action.logging_config import logger


class ComponentsScreen(WizardScreen):
    """Phase 5 — pick or create a component per selected lockfile."""

    step_index = 5
    step_title = "Components"
    step_subtitle = "Reuse an existing sbomify component or create a new one for each lockfile."

    BINDINGS = [
        Binding("enter", "submit", "Next ▸", show=True, priority=True),
        Binding("escape", "app.pop_screen", "Back", show=True, priority=True),
        Binding("r", "reload", "Reload", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        # Selections captured before a reload, keyed by lockfile index, so a
        # refetch does not discard choices the user has already made. Each entry
        # is ``(picked_id_or_None, typed_new_name)``; ``compose_body`` prefers
        # these over the name-match defaults when present.
        self._selection_overrides: dict[int, tuple[str | None, str]] = {}
        self._reloading = False

    def compose_body(self) -> ComposeResult:
        from rich.markup import escape as _esc

        existing = self.wizard.state.workspace.components if self.wizard.state.workspace else []
        # The API returns components in no particular order — sort by
        # name (case-insensitive) so the picker reads alphabetically.
        existing = sorted(
            existing,
            key=lambda c: (
                str(c.get("name") or c.get("id") or "(unnamed)").casefold(),
                str(c.get("id") or ""),
            ),
        )
        # Escape API-supplied names before passing them as picker
        # labels — PickOrCreate's OptionList renders labels as Rich
        # markup, so a component literally named "widget [pre-release]"
        # would otherwise have ``[pre-release]`` parsed as a markup tag
        # and either crash the render or emit garbled output. The
        # auto-match map keys by RAW name so a lockfile's
        # suggested_name (eg "widget-py") still matches the picker
        # entry — escaping is purely a rendering concern.
        existing_pairs = [
            (_esc(str(c.get("name") or c.get("id") or "(unnamed)")), str(c.get("id"))) for c in existing if c.get("id")
        ]
        existing_by_name = {
            str(c.get("name") or c.get("id") or "(unnamed)"): str(c.get("id")) for c in existing if c.get("id")
        }

        intro = Vertical(classes="wizard-panel")
        intro.border_title = "◆  Components"
        intro.border_subtitle = f"{len(self.wizard.state.selected)} lockfile(s) · {len(existing_pairs)} existing"
        with intro:
            yield Static(
                "One component per lockfile. Use [b]↑/↓[/] to highlight an "
                "existing component (or leave on [b]Create new[/]), then "
                "[b]Tab[/] to edit the new-component name. [b]Enter[/] / "
                "[b]Next[/] when done.",
                classes="wizard-help",
            )

        # Each lockfile gets its own card so the relationship between
        # the picker and the file it maps to is structural, not just
        # positional. The card's title bar carries the lockfile path
        # and the subtitle carries the ecosystem badge.
        for idx, lockfile in enumerate(self.wizard.state.selected):
            card = Vertical(classes="wizard-panel")
            card.border_title = f"◇  {lockfile.rel_path}"
            card.border_subtitle = lockfile.ecosystem
            with card:
                # After a reload, prefer what the user had already chosen over
                # the name-match default: a refetch must not silently reassign
                # a lockfile they had deliberately pointed somewhere else. A
                # previously picked component that has since disappeared server
                # side falls back to the default, which is the honest outcome.
                override = self._selection_overrides.get(idx)
                if override is not None:
                    picked_id, typed_name = override
                    pre_select = picked_id if picked_id in {i for _, i in existing_pairs} else None
                    default_name = typed_name or lockfile.suggested_name
                else:
                    pre_select = existing_by_name.get(lockfile.suggested_name)
                    default_name = lockfile.suggested_name

                yield PickOrCreate(
                    existing=existing_pairs,
                    create_label="[#86EFAC]➕  Create a new component[/]",
                    placeholder=("New component name (used only when 'Create new' is highlighted)"),
                    default_new_value=default_name,
                    # Auto-match by name: if a component called exactly
                    # ``suggested_name`` already exists, default to that
                    # one rather than the "Create new" sentinel. After a
                    # reload this is the user's own prior choice instead.
                    pre_select_id=pre_select,
                    id=f"component-{idx}",
                )
        yield Static("", id="components-status", markup=True)
        with Horizontal(classes="button-row"):
            yield Button("◂ Back", id="back")
            yield Button("⟳ Reload", id="reload")
            yield Button("Next  ▸", id="next", variant="primary")

    def on_mount(self) -> None:
        if not self.wizard.state.selected:
            return
        try:
            self.query_one("#component-0", PickOrCreate).focus_list()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Reload
    #
    # Components are prefetched once, on the Authenticate screen. If the user
    # creates a component in the sbomify UI while sitting on this screen, the
    # only way to see it was to restart the wizard. Reload refetches just the
    # component list and rebuilds the pickers in place.
    # ------------------------------------------------------------------

    def action_reload(self) -> None:
        if self._reloading:
            return
        if self.wizard.state.api is None:
            self._set_status("[#F87171]Not authenticated — nothing to reload.[/]")
            return

        self._capture_selections()
        self._reloading = True
        self._set_status("[#CBCCCE]Reloading components…[/]")
        self.run_worker(self._reload_worker, name="reload-components", thread=True, exclusive=True)

    def _capture_selections(self) -> None:
        """Snapshot what the user has chosen so a refetch does not lose it."""
        for idx in range(len(self.wizard.state.selected)):
            try:
                picker = self.query_one(f"#component-{idx}", PickOrCreate)
            except Exception:  # noqa: BLE001
                continue
            picked = picker.picked_id
            self._selection_overrides[idx] = (
                None if picked == NEW_SENTINEL else picked,
                picker.new_value or "",
            )

    def _reload_worker(self) -> tuple[list[dict[str, object]] | None, str | None]:
        """Refetch components off the UI thread. Returns ``(components, error)``."""
        from sbomify_action.exceptions import APIError

        api = self.wizard.state.api
        assert api is not None  # guarded in action_reload
        try:
            return api.list_components(), None
        except APIError as e:
            return None, str(e)
        except Exception as e:  # noqa: BLE001
            return None, f"Unexpected error: {e}"

    async def on_worker_state_changed(self, event) -> None:
        from textual.worker import WorkerState

        if event.worker.name != "reload-components":
            return
        if event.state == WorkerState.SUCCESS:
            components, error = event.worker.result
            self._reloading = False
            if error is not None:
                self._set_status(f"[#F87171]Reload failed: {strip_status_codes(error)}[/]")
                return
            assert components is not None
            before = len(self.wizard.state.workspace.components) if self.wizard.state.workspace else 0
            if self.wizard.state.workspace is not None:
                self.wizard.state.workspace.components = components
            delta = len(components) - before
            if delta > 0:
                summary = f"[#86EFAC]Reloaded — {delta} new component(s), {len(components)} total.[/]"
            elif delta < 0:
                summary = f"[#F4B57F]Reloaded — {-delta} fewer, {len(components)} total.[/]"
            else:
                summary = f"[#CBCCCE]Reloaded — no change, {len(components)} total.[/]"
            # recompose() is a coroutine -- calling it bare silently does nothing
            # and the rebuilt list never appears. Set the status *after* it, since
            # recompose replaces the body (and does not re-fire on_mount, so
            # stashing the message for on_mount would never surface it).
            await self.recompose()
            self._set_status(summary)
        elif event.state == WorkerState.ERROR:
            self._reloading = False
            self._set_status(f"[#F87171]Reload failed: {event.worker.error}[/]")

    def _set_status(self, message: str) -> None:
        try:
            self.query_one("#components-status", Static).update(message)
        except Exception:  # noqa: BLE001
            pass

    def action_submit(self) -> None:
        self.route_enter(self._advance)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "next":
            self._advance()
        elif event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "reload":
            self.action_reload()

    def _advance(self) -> None:
        plan = self.wizard.state.plan
        existing = self.wizard.state.workspace.components if self.wizard.state.workspace else []
        plan.create_components = []
        for idx, lockfile in enumerate(self.wizard.state.selected):
            picker = self.query_one(f"#component-{idx}", PickOrCreate)
            picked_id = picker.picked_id
            if picked_id is None or picked_id == NEW_SENTINEL:
                name = picker.new_value or lockfile.suggested_name
                plan.create_components.append(PlannedComponent(lockfile=lockfile, name=name))
                logger.debug("Components: will create %r for %s", name, lockfile.rel_path)
            else:
                comp = next(c for c in existing if str(c.get("id")) == picked_id)
                name = str(comp.get("name") or comp.get("id") or "(unnamed)")
                plan.create_components.append(PlannedComponent(lockfile=lockfile, name=name, existing_id=picked_id))
                logger.debug(
                    "Components: will reuse %s (id=%s) for %s",
                    name,
                    picked_id,
                    lockfile.rel_path,
                )

        from sbomify_action.cli.wizard.screens.configure_workflow import ConfigureWorkflowScreen

        self.wizard.push_screen(ConfigureWorkflowScreen())
