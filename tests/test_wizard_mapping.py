"""Tests for the mapping module (product picker + per-component config)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from sbomify_action.cli.wizard import mapping
from sbomify_action.cli.wizard.state import (
    DiscoveredLockfile,
    Plan,
    RepoFacts,
    WizardState,
    WorkspaceSnapshot,
)


def _lockfile(rel: str, ecosystem: str = "python") -> DiscoveredLockfile:
    rel_path = Path(rel)
    return DiscoveredLockfile(
        path=Path("/repo") / rel_path,
        rel_path=rel_path,
        ecosystem=ecosystem,
        suggested_name=rel_path.parent.name or "component",
    )


def _state(
    selected: list[DiscoveredLockfile],
    *,
    products=None,
    components=None,
    profiles=None,
    has_release_tags: bool = False,
) -> WizardState:
    facts = RepoFacts(
        repo_root=Path("/repo"),
        is_git=True,
        remote_url=None,
        suggested_repo_name="repo",
        default_branch="main",
        current_branch="feat",
        has_release_tags=has_release_tags,
    )
    workspace = WorkspaceSnapshot(
        user={},
        products=products or [],
        components=components or [],
        contact_profiles=profiles or [],
    )
    return WizardState(
        facts=facts,
        api=MagicMock(),
        workspace=workspace,
        selected=selected,
        plan=Plan(),
    )


def test_pick_or_create_product_records_existing_choice(monkeypatch):
    state = _state([], products=[{"id": "prod_1", "name": "Existing"}])
    monkeypatch.setattr(mapping, "ask_select", lambda *a, **k: "prod_1")
    monkeypatch.setattr(mapping, "ask_text", lambda *a, **k: "ignored")

    mapping.pick_or_create_product(state)

    assert state.plan.use_product_id == "prod_1"
    assert state.plan.create_product is None


def test_pick_or_create_product_records_create_intent(monkeypatch):
    state = _state([], products=[{"id": "prod_1", "name": "Existing"}])
    monkeypatch.setattr(mapping, "ask_select", lambda *a, **k: "__create_new__")
    monkeypatch.setattr(mapping, "ask_text", lambda *a, **k: "new-product")

    mapping.pick_or_create_product(state)

    assert state.plan.create_product == "new-product"
    assert state.plan.use_product_id is None


def test_pick_or_create_product_create_only_when_no_products(monkeypatch):
    state = _state([], products=[])
    monkeypatch.setattr(mapping, "ask_select", lambda *a, **k: "anything")
    monkeypatch.setattr(mapping, "ask_text", lambda *a, **k: "fresh")

    mapping.pick_or_create_product(state)

    assert state.plan.create_product == "fresh"


def test_configure_components_uses_apply_to_rest_shortcut(monkeypatch):
    lockfiles = [
        _lockfile("backend/poetry.lock"),
        _lockfile("frontend/package-lock.json", "javascript"),
        _lockfile("cmd/cli/go.sum", "go"),
    ]
    state = _state(lockfiles)

    select_answers = iter(["skip", "tag"])  # only asked for the first lockfile
    text_answers = iter(["backend", "frontend", "cli"])
    confirm_answers = iter([True, True])  # apply augmentation + release to rest

    monkeypatch.setattr(mapping, "ask_select", lambda *a, **k: next(select_answers))
    monkeypatch.setattr(mapping, "ask_text", lambda *a, **k: next(text_answers))
    monkeypatch.setattr(mapping, "ask_confirm", lambda *a, **k: next(confirm_answers))

    mapping.configure_components(state)

    assert len(state.plan.create_components) == 3
    assert all(c.augmentation == "skip" for c in state.plan.create_components)
    assert all(c.release_strategy == "tag" for c in state.plan.create_components)
    assert state.plan.create_initial_release is True


def test_configure_components_per_component_when_shortcut_declined(monkeypatch):
    lockfiles = [
        _lockfile("backend/poetry.lock"),
        _lockfile("frontend/package-lock.json", "javascript"),
    ]
    state = _state(lockfiles)

    select_answers = iter(["skip", "latest", "skip", "manual"])
    text_answers = iter(["backend", "frontend"])
    confirm_answers = iter([False, False])

    monkeypatch.setattr(mapping, "ask_select", lambda *a, **k: next(select_answers))
    monkeypatch.setattr(mapping, "ask_text", lambda *a, **k: next(text_answers))
    monkeypatch.setattr(mapping, "ask_confirm", lambda *a, **k: next(confirm_answers))

    mapping.configure_components(state)

    assert [c.release_strategy for c in state.plan.create_components] == ["latest", "manual"]


def test_collision_with_existing_component_offers_suffix(monkeypatch):
    state = _state(
        [_lockfile("backend/poetry.lock")],
        components=[{"id": "comp_existing", "name": "backend"}],
    )

    text_answers = iter(["backend"])
    select_answers = iter(["suffix", "skip", "latest"])

    monkeypatch.setattr(mapping, "ask_text", lambda *a, **k: next(text_answers))
    monkeypatch.setattr(mapping, "ask_select", lambda *a, **k: next(select_answers))
    monkeypatch.setattr(mapping, "ask_confirm", lambda *a, **k: True)

    mapping.configure_components(state)
    assert state.plan.create_components[0].name == "backend-2"


def test_profile_augmentation_records_profile_id(monkeypatch):
    state = _state(
        [_lockfile("backend/poetry.lock")],
        profiles=[{"id": "profile_42", "name": "ACME profile"}],
    )

    text_answers = iter(["backend"])
    select_answers = iter(["profile", "profile_42", "latest"])

    monkeypatch.setattr(mapping, "ask_text", lambda *a, **k: next(text_answers))
    monkeypatch.setattr(mapping, "ask_select", lambda *a, **k: next(select_answers))

    mapping.configure_components(state)

    component = state.plan.create_components[0]
    assert component.augmentation == "profile"
    assert component.profile_id == "profile_42"
