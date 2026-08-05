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

## Why the lock files are short

Trimmed to a few real entries each, not synthesised. The tests here assert
which generator is asked first and that a manifest sits beside its lock file;
nothing parses the contents. Carrying them in full cost 62,000 lines and
2.5MB, of which nothing was ever read -- and it buried every other change in
the diff.

Each file is still valid for its format, so a future test that does parse one
has something real to work with. If you need a full dependency graph, that is
what scripts/fetch_fixtures.py is for: it clones the real repositories, which
is where SBOM quality is actually measured.
