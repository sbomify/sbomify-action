"""Interactive product picker and per-lockfile component configuration."""

from __future__ import annotations

from typing import Any

from questionary import Choice

from sbomify_action.cli.wizard.discovery import slugify
from sbomify_action.cli.wizard.prompts import (
    GoBack,
    ask_confirm,
    ask_select,
    ask_text,
    print_info,
    print_section_header,
)
from sbomify_action.cli.wizard.sections import (
    collect_authors,
    collect_licenses,
    collect_lifecycle_and_dates,
    collect_organization,
    collect_security_contact,
    collect_vcs_override,
)
from sbomify_action.cli.wizard.state import (
    AugmentationStrategy,
    PlannedComponent,
    ReleaseStrategy,
    WizardState,
)


def _component_count(components: list[dict[str, Any]], product_id: str) -> int:
    count = 0
    for component in components:
        products = component.get("products") or component.get("product_ids") or []
        for entry in products:
            entry_id = entry if isinstance(entry, str) else entry.get("id") if isinstance(entry, dict) else None
            if entry_id == product_id:
                count += 1
                break
    return count


def pick_or_create_product(state: WizardState) -> None:
    """Phase 3: pick or create a Product, recording the choice in state.plan."""
    assert state.workspace is not None

    print_section_header(
        "Choose your product",
        "Sbomify hierarchy:  Product → Component  (analogy: App → Lockfile)",
    )

    products = state.workspace.products
    components = state.workspace.components

    suggested = state.facts.suggested_repo_name or state.facts.repo_root.name
    suggested_slug = slugify(suggested) or "product"

    create_value = "__create_new__"
    choices: list[Choice] = []
    for product in products:
        pid = str(product.get("id") or "")
        name = str(product.get("name") or pid or "(unnamed)")
        count = _component_count(components, pid)
        label = f"{name}  ({count} component{'s' if count != 1 else ''})"
        choices.append(Choice(label, value=pid))
    choices.append(Choice(f"+ Create new product…   default: {suggested_slug}", value=create_value))

    selection = ask_select(
        "Pick a product:",
        choices=choices,
        allow_back=True,
    )

    if selection == create_value or not products:
        name = ask_text(
            "Product name:",
            default=suggested_slug,
            validate=lambda value: bool(value.strip()) or "Name is required",
        )
        state.plan.create_product = name.strip()
        state.plan.use_product_id = None
    else:
        state.plan.use_product_id = selection
        state.plan.create_product = None


def _existing_component_names(state: WizardState) -> set[str]:
    return {
        str(c.get("name") or "").lower()
        for c in (state.workspace.components if state.workspace else [])
        if c.get("name")
    }


def _ask_component_name(
    suggested: str,
    *,
    existing_names: set[str],
    used_in_plan: set[str],
) -> str:
    """Prompt for a component name. Warns on collision but lets the user proceed."""
    while True:
        name = ask_text(
            "Component name:",
            default=suggested,
            validate=lambda value: bool(value.strip()) or "Name is required",
        ).strip()
        lowered = name.lower()
        if lowered in used_in_plan:
            print_info(f"'{name}' is already used by another component in this run; pick a different name.")
            continue
        if lowered in existing_names:
            choice = ask_select(
                f"A component named '{name}' already exists on sbomify. What would you like to do?",
                choices=[
                    Choice("Use a different name", value="rename"),
                    Choice("Append a suffix (e.g. -2)", value="suffix"),
                    Choice("Continue anyway (the API may reject the create)", value="continue"),
                ],
            )
            if choice == "rename":
                continue
            if choice == "suffix":
                base = name
                index = 2
                while f"{base}-{index}".lower() in existing_names or f"{base}-{index}".lower() in used_in_plan:
                    index += 1
                return f"{base}-{index}"
        return name


def _ask_augmentation(
    state: WizardState,
) -> tuple[AugmentationStrategy, str | None, dict[str, Any] | None]:
    profiles = state.workspace.contact_profiles if state.workspace else []
    profile_label = "Use a contact profile saved on sbomify"
    if not profiles:
        profile_label += "  (none configured yet — create one in sbomify first)"

    choices = [
        Choice(profile_label, value="profile", disabled=None if profiles else "no contact profiles"),
        Choice("Configure locally in this repo (sbomify.json)", value="local"),
        Choice("Skip for now", value="skip"),
    ]
    selection = ask_select(
        "Component details "
        "(supplier, authors, licenses, lifecycle, security contact — added to every SBOM you upload):",
        choices=choices,
    )
    strategy: AugmentationStrategy = selection or "skip"  # type: ignore[assignment]

    if strategy == "profile":
        profile_choices = [
            Choice(
                str(profile.get("name") or profile.get("id") or "(unnamed)"),
                value=str(profile.get("id")),
            )
            for profile in profiles
        ]
        profile_id = ask_select("Pick a contact profile:", choices=profile_choices)
        return strategy, profile_id, None

    if strategy == "local":
        sbomify_json = _collect_sbomify_json()
        return strategy, None, sbomify_json

    return strategy, None, None


def _collect_sbomify_json() -> dict[str, Any]:
    """Drive the existing sbomify.json section collectors and return the dict."""
    config: dict[str, Any] = {}

    org = collect_organization(config)
    config.update({k: v for k, v in org.items() if v})

    authors = collect_authors(None)
    if authors:
        config["authors"] = authors

    licenses = collect_licenses(None)
    if licenses:
        config["licenses"] = licenses

    security = collect_security_contact(None)
    if security:
        config["security_contact"] = security

    lifecycle = collect_lifecycle_and_dates(config)
    config.update({k: v for k, v in lifecycle.items() if v})

    vcs = collect_vcs_override(config)
    config.update({k: v for k, v in vcs.items() if v})

    return {k: v for k, v in config.items() if v not in (None, "", [], {})}


def _ask_release_strategy(suggested: ReleaseStrategy) -> ReleaseStrategy:
    options: list[tuple[ReleaseStrategy, str]] = [
        ("latest", "Latest only — every push, version = git short SHA"),
        ("tag", "Git tags — v*-tagged commits trigger releases"),
        ("manual", "Manual — workflow_dispatch with version input"),
        ("none", "Don't track releases"),
    ]
    choices = [
        Choice(
            f"{label}  (recommended)" if value == suggested else label,
            value=value,
        )
        for value, label in options
    ]
    selection = ask_select("Release tracking:", choices=choices)
    return selection or "latest"  # type: ignore[return-value]


def configure_components(state: WizardState) -> None:
    """Phase 4: build a PlannedComponent for each selected lockfile."""
    print_section_header(
        f"Configure components (1 of {len(state.selected)})",
        "We'll prompt for three things per component: name, component details, release strategy.",
    )

    suggested_release: ReleaseStrategy = "tag" if state.facts.has_release_tags else "latest"
    existing_names = _existing_component_names(state)

    # Apply-to-rest cache, populated after the first component is configured.
    pinned_augmentation: tuple[AugmentationStrategy, str | None, dict[str, Any] | None] | None = None
    pinned_release: ReleaseStrategy | None = None
    apply_aug_to_rest = False
    apply_rel_to_rest = False

    used_in_plan: set[str] = set()

    for index, lockfile in enumerate(state.selected, start=1):
        if index > 1:
            print_section_header(
                f"Configure components ({index} of {len(state.selected)})",
                f"Lockfile: {lockfile.rel_path}",
            )

        try:
            name = _ask_component_name(
                lockfile.suggested_name,
                existing_names=existing_names,
                used_in_plan=used_in_plan,
            )
            used_in_plan.add(name.lower())

            if apply_aug_to_rest and pinned_augmentation is not None:
                augmentation, profile_id, sbomify_json = pinned_augmentation
            else:
                augmentation, profile_id, sbomify_json = _ask_augmentation(state)

            if apply_rel_to_rest and pinned_release is not None:
                release_strategy = pinned_release
            else:
                release_strategy = _ask_release_strategy(suggested_release)
        except GoBack:
            # Drop everything we've planned so far so the runner can re-enter Phase 4.
            state.plan.create_components.clear()
            raise

        state.plan.create_components.append(
            PlannedComponent(
                lockfile=lockfile,
                name=name,
                augmentation=augmentation,
                profile_id=profile_id,
                sbomify_json=sbomify_json,
                release_strategy=release_strategy,
            )
        )

        if index == 1 and len(state.selected) > 1:
            pinned_augmentation = (augmentation, profile_id, sbomify_json)
            pinned_release = release_strategy
            apply_aug_to_rest = ask_confirm(
                f"Apply the same component-details strategy to the remaining {len(state.selected) - 1} lockfile(s)?",
                default=True,
                allow_back=False,
            )
            apply_rel_to_rest = ask_confirm(
                f"Apply the same release strategy to the remaining {len(state.selected) - 1} lockfile(s)?",
                default=True,
                allow_back=False,
            )

    state.plan.create_initial_release = any(c.release_strategy == "tag" for c in state.plan.create_components)
