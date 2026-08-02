# Pinned external tool versions

These are real, native manifests -- not a bespoke version file -- so that
Dependabot maintains them the same way it maintains everything else, and so
the versions can be read back with the ecosystems' own tooling rather than a
regex.

| file | tools | Dependabot ecosystem |
| ---- | ----- | -------------------- |
| `go.mod` / `go.sum` | syft, cosign, crane | `gomod` |
| `Cargo.toml` / `Cargo.lock` | cargo-cyclonedx | `cargo` |

`bun` and `uv` are pinned by their base images in the `Dockerfile`, and
`cdxgen` by the top-level `package.json`, so they are already covered by the
`docker` and `bun` ecosystems respectively.

Nothing here is compiled as part of the Python package. `src/main.rs` exists
only because Cargo insists a manifest has a target; `go.mod` uses Go 1.24
`tool` directives, which pin a command without vendoring it into a build.

To bump a version, let Dependabot do it. If you must do it by hand, use the
ecosystem's own command (`go get -tool <mod>@<ver>`, `cargo update -p <crate>
--precise <ver>`) so the lockfile hashes are regenerated correctly.
