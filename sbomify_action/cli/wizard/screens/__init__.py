"""Screen subclasses for the Textual sbomify wizard.

Each screen owns one phase of the onboarding flow. Screens share a
common visual frame via `WizardScreen` (header crumb, body panel,
keybind footer) and read/write to `app.state: WizardState` for
cross-phase data.
"""
