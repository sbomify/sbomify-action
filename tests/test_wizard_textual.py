"""Smoke tests for the Textual wizard via App.run_test().

These tests confirm screens compose without exceptions and that state
advances correctly between phases. Per-screen styling / rendering is
verified by maintainers manually — Pilot is not the right tool for
visual fidelity checks.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sbomify_action.cli.wizard.app import WizardApp
from sbomify_action.cli.wizard.options import WizardOptions
from sbomify_action.cli.wizard.state import DiscoveredLockfile


def _opts(tmp_path: Path, *, dry_run: bool = True) -> WizardOptions:
    return WizardOptions(
        token="t-fake",
        api_base_url="https://app.sbomify.test",
        repo_root=tmp_path,
        output_dir=tmp_path / ".github" / "workflows",
        dry_run=dry_run,
    )


def _stub_discovery(monkeypatch: pytest.MonkeyPatch, lockfiles: list[DiscoveredLockfile]) -> None:
    """Replace lockfile discovery so each test owns the lockfile set."""
    monkeypatch.setattr(
        "sbomify_action.cli.wizard.app.discovery.discover",
        lambda _root, repo_name=None: lockfiles,
    )


def _stub_client(monkeypatch: pytest.MonkeyPatch, **kwargs: object) -> MagicMock:
    """Replace SbomifyApiClient at the authenticate screen's import site."""
    products = kwargs.get("products") or []
    components = kwargs.get("components") or []
    profiles = kwargs.get("profiles") or []

    instance = MagicMock()
    instance.whoami.return_value = None
    instance.list_products.return_value = products
    instance.list_components.return_value = components
    instance.list_contact_profiles.return_value = profiles

    monkeypatch.setattr(
        "sbomify_action.cli.wizard.screens.authenticate.SbomifyApiClient",
        lambda *args, **kwargs: instance,
    )
    return instance


async def test_app_starts_and_renders_welcome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_discovery(monkeypatch, [])

    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        # Welcome should be on the stack.
        from sbomify_action.cli.wizard.screens.welcome import WelcomeScreen

        assert isinstance(app.screen, WelcomeScreen)
        await pilot.pause()


async def test_welcome_to_discover_navigates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lockfiles = [
        DiscoveredLockfile(
            path=tmp_path / "uv.lock",
            rel_path=Path("uv.lock"),
            ecosystem="python",
            suggested_name="widget-py",
        )
    ]
    _stub_discovery(monkeypatch, lockfiles)

    app = WizardApp(_opts(tmp_path))
    async with app.run_test() as pilot:
        await pilot.press("enter")
        await pilot.pause()

        from sbomify_action.cli.wizard.screens.discover import DiscoverScreen

        assert isinstance(app.screen, DiscoverScreen)
        assert len(app.state.discovered) == 1
