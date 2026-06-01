"""Tests for the Done screen's OIDC trusted-publishing rendering branch.

The two string-builders (`_oidc_success`, `_oidc_instructions`) are pure
functions of wizard state + opts, so we exercise them on a DoneScreen instance
built via ``__new__`` (bypassing Textual's ``Screen.__init__``, which needs a
running app) with a stubbed ``wizard`` property. Full screen composition is
covered by the Textual smoke tests; this pins the success-vs-fallback text.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from sbomify_action.cli.wizard.screens.done import DoneScreen
from sbomify_action.cli.wizard.state import RepoFacts, WizardState


def _facts(slug: str | None = "acme/widget", visibility: str = "public") -> RepoFacts:
    return RepoFacts(
        repo_root=Path("/tmp"),
        is_git=True,
        remote_url="git@github.com:acme/widget.git",
        suggested_repo_name="widget",
        default_branch="main",
        current_branch="main",
        has_release_tags=False,
        owner_repo_slug=slug,
        visibility=visibility,  # type: ignore[arg-type]
    )


def _done_screen(monkeypatch: pytest.MonkeyPatch, state: WizardState, api_base: str = "https://app.test") -> DoneScreen:
    screen = DoneScreen.__new__(DoneScreen)  # bypass Textual Screen.__init__ (needs an app)
    fake_wizard = SimpleNamespace(state=state, opts=SimpleNamespace(api_base_url=api_base))
    monkeypatch.setattr(DoneScreen, "wizard", property(lambda self: fake_wizard))
    return screen


def test_oidc_success_text_mentions_repo_and_count(monkeypatch: pytest.MonkeyPatch) -> None:
    state = WizardState(facts=_facts())
    state.component_ids = {Path("a.lock"): "c1", Path("b.lock"): "c2"}
    state.oidc_bindings_registered = 2
    state.oidc_binding_note = None

    text = _done_screen(monkeypatch, state)._oidc_success()

    assert "acme/widget" in text
    assert "2 component" in text
    assert "Nothing else to do" in text


def test_oidc_instructions_prepend_note_when_auto_register_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    state = WizardState(facts=_facts(visibility="private"))
    state.component_ids = {Path("a.lock"): "c1"}
    state.oidc_binding_note = "'acme/widget' looks private — register the trusted publisher manually."

    text = _done_screen(monkeypatch, state)._oidc_instructions()

    # The reason comes first, then the manual steps + per-component settings link.
    assert text.startswith("'acme/widget' looks private")
    assert "Trusted publishing needs an OIDC binding" in text
    assert "components/c1/settings" in text


def test_oidc_instructions_without_note_is_plain_manual_steps(monkeypatch: pytest.MonkeyPatch) -> None:
    state = WizardState(facts=_facts())
    state.component_ids = {Path("a.lock"): "c1"}
    state.oidc_binding_note = None

    text = _done_screen(monkeypatch, state)._oidc_instructions()

    assert text.startswith("Trusted publishing needs an OIDC binding")
