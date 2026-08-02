# Per-ecosystem fixtures

Realistic projects: each carries the **manifest as well as the lock file**,
because that is what a real repository looks like and what the generators
need.

The flat fixtures in the parent directory are bare lock files. That made
them exercise the fallback chain rather than the generator intended for
the ecosystem, and hid three defects for as long as they existed:

- `Cargo.lock` with no `Cargo.toml` -- cargo-cyclonedx drives
  `cargo metadata`, which needs the manifest
- `pubspec.lock` with no `pubspec.yaml` -- cdxgen has no root component and
  dies with "Cannot read properties of undefined (reading 'bom-ref')"
- `Pipfile.lock` passed as a file to `cyclonedx-py pipenv`, which wants the
  directory

Each was invisible because falling back to syft still produced *an* SBOM.
The point of the design is the best SBOM for each ecosystem, not merely one,
so tests assert which generator produced it.
