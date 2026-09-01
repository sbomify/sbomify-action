<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/sbomify/sbomify-action/master/docs/assets/sbomify-logo-dark.svg" />
    <img src="https://raw.githubusercontent.com/sbomify/sbomify-action/master/docs/assets/sbomify-logo.svg" alt="sbomify action" width="400" />
  </picture>
</p>

[![sbomified](https://sbomify.com/assets/images/logo/badge.svg)](https://app.sbomify.com/public/component/Gu9wem8mkX)
[![CI/CD Pipeline](https://github.com/sbomify/sbomify-action/actions/workflows/sbomify.yaml/badge.svg)](https://github.com/sbomify/sbomify-action/actions/workflows/sbomify.yaml)
[![OpenGrep](https://github.com/sbomify/sbomify-action/actions/workflows/opengrep.yaml/badge.svg)](https://github.com/sbomify/sbomify-action/actions/workflows/opengrep.yaml)
[![PyPI version](https://badge.fury.io/py/sbomify-action.svg)](https://pypi.org/project/sbomify-action/)
[![Slack](https://img.shields.io/badge/Slack-Join%20Community-4A154B?logo=slack)](https://join.slack.com/t/sbomify/shared_invite/zt-3na54pa1f-MXrFWhotmZr0YxXc8sABTw)

A CLI, shipped as a container image, that turns a lock file into a compliance-grade SBOM inside your pipeline. It picks the right generator for your ecosystem, injects packages no lock file knows about, adds your business metadata, and enriches every component from package registries.

It runs as a GitHub Action, as a container image on any other CI, or locally with `uvx`. Configuration is environment variables and is identical everywhere. Works standalone or with [sbomify](https://sbomify.com) — generation, augmentation and enrichment need no account.

📖 **[Full documentation](https://sbomify.com/sbomify-action/)**

### See it in action: FOSDEM 2026 Talk

Watch our FOSDEM 2026 talk for a real-world crash course on generating CRA-ready SBOMs — covering the full pipeline from authoring to enrichment and signing.

[![CRA-Ready SBOMs: A Practical Blueprint for High-Quality Generation — FOSDEM 2026](https://raw.githubusercontent.com/sbomify/sbomify-action/master/docs/assets/fosdem-2026-talk-thumbnail.png)](https://sbomify.com/2026/02/04/announcing-sbomify-action-v0-13-the-one-where-we-go-to-fosdem/)

## Quick start

The fastest way to get going is the **interactive setup wizard**. Run it from the root of your repository:

```bash
docker run --rm -it \
  -v "$(pwd):/workspace" \
  ghcr.io/sbomify/sbomify-action \
  sbomify-action wizard
```

It scans your repository for lock files, signs you in to [sbomify](https://app.sbomify.com), registers the matching components, and writes a release-ready `.github/workflows/sboms.yml`. Pass `--dry-run` to preview the plan without making API changes or writing files.

The wizard is interactive, so the `-it` flags are required, and it must run on your machine rather than in CI. If you would rather not use Docker, `uvx sbomify-action wizard` does the same thing.

📖 [Quick start guide](https://sbomify.com/sbomify-action/quickstart/)

### Or configure it by hand

```yaml
- uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: requirements.txt
    OUTPUT_FILE: sbom.cdx.json
    ENRICH: true
    UPLOAD: false
```

That generates a CycloneDX SBOM from your lock file and enriches it with metadata from package registries. No account required. For SPDX, set `SBOM_FORMAT: spdx`.

On any other CI, pass the same variables to the container image:

```bash
docker run --rm \
  -v "$(pwd):/workspace" \
  -e LOCK_FILE=requirements.txt \
  -e OUTPUT_FILE=sbom.cdx.json \
  -e ENRICH=true \
  -e UPLOAD=false \
  ghcr.io/sbomify/sbomify-action
```

The image's working directory is `/workspace`, so mounting your repository there needs no `-w`. Any other mount point works too, as long as `-w` points at it — including an existing `-v "$PWD:/github/workspace" -w /github/workspace`, which keeps working unchanged. Keep the mount and the `-w` in step: outputs are written relative to the working directory, so a mount without a matching `-w` leaves your SBOM inside the container.

📖 [Runtime guides](https://sbomify.com/sbomify-action/runtimes/) — GitHub Actions, GitLab CI, Bitbucket, Jenkins, CircleCI, Azure DevOps, TeamCity, any container runner, and local

## Why not just run a scanner?

A scanner's job is **detection**. It gives you a name, a version and a PURL, and leaves supplier, license, description and hashes empty — which are exactly the fields [NTIA](https://sbomify.com/compliance/ntia-minimum-elements/), [CISA](https://sbomify.com/compliance/cisa-minimum-elements/) and the [EU CRA](https://sbomify.com/compliance/eu-cra/) ask for. A raw scan is a dependency list; compliance needs an SBOM.

This tool wraps generation in three more steps — inject, augment, enrich — and runs the whole thing at build time, where the full dependency context exists and the result can be signed at origin.

📖 [Why SBOM quality matters](https://sbomify.com/sbomify-action/why/)

## Features

- **Generate** from lock files across 17 ecosystems, container images, or a directory, in CycloneDX or SPDX
- **Native generators** per ecosystem — `cyclonedx-py`, `cargo-cyclonedx`, `cyclonedx-gomod`, `cyclonedx-maven`, `cyclonedx-gradle`, `cyclonedx-sbt` — with cdxgen and Syft as fallbacks
- **Chainguard SBOM reuse** — detects Chainguard base images and uses the publisher's SBOM instead of scanning
- **Yocto/OpenEmbedded** — batch process SPDX SBOMs from Yocto builds
- **Inject** additional packages not in lock files (vendored code, runtime deps, system libraries)
- **Augment** with business metadata — supplier, authors, licenses, lifecycle phase — from a local config file or sbomify
- **VCS auto-detection** on GitHub Actions, GitLab CI, Bitbucket and TeamCity (Git roots only), and from the git checkout itself everywhere else — Jenkins, CircleCI, Azure Pipelines and your own machine. `DISABLE_VCS_AUGMENTATION=true` turns it off
- **Enrich** from PyPI, crates.io, pub.dev, Conan Center, deps.dev, ecosyste.ms and pre-computed distro license databases
- **Hashes and lifecycle data** — integrity hashes pulled from your lock file, CLE end-of-support dates for OS packages and tracked runtimes
- **Audit trail** — every modification logged with UTC timestamps, for attestation and compliance
- **Upload** to sbomify or Dependency Track, tag product releases, attest with GitHub build provenance
- **Tokenless publishing** on GitHub Actions via OIDC trusted publishing

## Supported lock files

| Language    | Files                                                                          |
| ----------- | ------------------------------------------------------------------------------ |
| Python      | `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pyproject.toml` |
| JavaScript  | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` |
| Java        | `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`               |
| Go          | `go.mod`, `go.sum`                                                             |
| Rust        | `Cargo.lock`                                                                   |
| Ruby        | `Gemfile.lock`                                                                 |
| PHP         | `composer.json`, `composer.lock`                                               |
| .NET/C#     | `packages.lock.json`                                                           |
| Swift       | `Package.swift`, `Package.resolved`                                            |
| Dart        | `pubspec.lock`                                                                 |
| Elixir      | `mix.lock`                                                                     |
| Scala       | `build.sbt`                                                                    |
| C++         | `conan.lock`                                                                   |
| Terraform   | `.terraform.lock.hcl`                                                          |
| Haskell     | `stack.yaml.lock`, `stack.yaml`, `cabal.project.freeze`                        |
| Erlang      | `rebar.lock` (rebar3 projects; erlang.mk has no equivalent)                     |
| Clojure     | `deps.edn`, `project.clj`                                                      |

Naming a *manifest* that sits beside its lock file reads the lock file instead: `package.json` defers to `package-lock.json`, `pyproject.toml` to `poetry.lock`.

Container images are supported via `DOCKER_IMAGE`, and a whole directory via `SOURCE_DIR` — though a directory scan is a weaker claim than a lock file, so reach for it only when nothing else applies.

📖 [Input sources](https://sbomify.com/sbomify-action/sources/)

## Format support

- **CycloneDX** 1.2–1.7 (JSON) — generate and process. Defaults to 1.6; override with `SPEC_VERSION`
- **SPDX** 2.2 and 2.3 (JSON) — generate and process. Defaults to 2.3
- **SPDX** 3.0.1 (JSON-LD) — process only; supply an existing document via `SBOM_FILE`

## Documentation

| Topic | |
| --- | --- |
| [Quick start](https://sbomify.com/sbomify-action/quickstart/) | The wizard, and your first pipeline run |
| [Why SBOM quality matters](https://sbomify.com/sbomify-action/why/) | Scanners vs. pipelines, and chain of custody |
| [How it works](https://sbomify.com/sbomify-action/how-it-works/) | The full pipeline, step by step |
| [Configuration](https://sbomify.com/sbomify-action/configuration/) | Every input, environment variable and CLI flag |
| [Input sources](https://sbomify.com/sbomify-action/sources/) | Lock files, container images, directories, Yocto, additional packages |
| [Augmentation](https://sbomify.com/sbomify-action/augmentation/) | Your business metadata via `sbomify.json` |
| [Enrichment](https://sbomify.com/sbomify-action/enrichment/) | Registry metadata, license databases, lifecycle data, hashes |
| [Publishing](https://sbomify.com/sbomify-action/publishing/) | OIDC trusted publishing, releases, Dependency Track |
| [Advanced](https://sbomify.com/sbomify-action/advanced/) | Attestation, audit trail, tool runtimes, caching, troubleshooting |
| [Runtimes](https://sbomify.com/sbomify-action/runtimes/) | Setup for your CI platform |

In this repository:

- [Enrichment coverage](https://github.com/sbomify/sbomify-action/blob/master/docs/enrichment_coverage.md) — expected field coverage per ecosystem
- [NTIA comparison](https://github.com/sbomify/sbomify-action/blob/master/docs/ntia_comparison.md) — how output maps to the NTIA minimum elements
- [Architecture decision records](https://github.com/sbomify/sbomify-action/tree/master/docs/adr)

## Notes

**Tool runtimes.** Only `cyclonedx-py` ships with the package. Syft, cdxgen, the JVM toolchain, Go, Rust, PHP, .NET, `crane` and `cosign` are not baked into the image — they are downloaded on first use, verified against a digest pinned at build time, and cached. Set `SBOMIFY_TOOL_CACHE` to persist that cache across CI runs, or `SBOMIFY_FETCH_RUNTIMES=0` to opt out for air-gapped builds. See [tool runtimes](https://sbomify.com/sbomify-action/advanced/#tool-runtimes).

**Trivy** is currently not shipped, after [compromised releases in March 2026](https://sbomify.com/2026/03/26/trivy-compromise-hardening-sbomify-action/). The remaining generators cover every supported ecosystem.

**Pinning.** Examples here use `@master` so they stay correct as the action moves. Do not ship that: pin to a release tag, or for production to a full 40-character commit SHA — see [SECURITY.md](https://github.com/sbomify/sbomify-action/blob/master/SECURITY.md). The wizard does this automatically for the workflows it generates.

## Security

Report vulnerabilities to <security@sbomify.com>. See [SECURITY.md](https://github.com/sbomify/sbomify-action/blob/master/SECURITY.md) for scope, response targets and hardening guidance.

## Links

- [Documentation](https://sbomify.com/sbomify-action/)
- [sbomify platform](https://sbomify.com)
- [Community Slack](https://join.slack.com/t/sbomify/shared_invite/zt-3na54pa1f-MXrFWhotmZr0YxXc8sABTw)

## License

Apache-2.0
