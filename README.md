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
- **VCS auto-detection** on GitHub Actions, GitLab CI, Bitbucket, Jenkins, CircleCI, Travis CI and TeamCity (Git roots only), and from the git checkout itself everywhere else — Azure Pipelines, any other container runner and your own machine. `DISABLE_VCS_AUGMENTATION=true` turns it off
- **Enrich** from PyPI, crates.io, pub.dev, Conan Center, deps.dev, ecosyste.ms and pre-computed distro license databases
- **Hashes and lifecycle data** — integrity hashes pulled from your lock file, CLE end-of-support dates for OS packages and tracked runtimes
- **Audit trail** — every modification logged with UTC timestamps, for attestation and compliance
- **Upload** to sbomify or Dependency Track, tag product releases, attest with GitHub build provenance
- **Documents** — publish the evidence an SBOM cannot carry (pentest reports, SOC 2 attestations, threat models, declarations of conformity) to the same component and the same release
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

Generating and reading are not the same list. Everything here is read, validated,
augmented, enriched and written back; only some of it can be produced from a lock
file or a container image in the first place.

| Format | Generate | Validate | Default |
| --- | --- | --- | --- |
| CycloneDX (JSON) | 1.2–1.7 | 1.3–1.7 | 1.6 |
| SPDX (JSON) | 2.2, 2.3 | 2.2, 2.3 | 2.3 |
| SPDX (JSON-LD) | additional packages only | 3.0.0, 3.0.1 | — |

**SPDX 3 cannot be scanned out of your code.** Syft is the only SPDX generator here
and it stops at 2.3, so `SPEC_VERSION: 3.0.1` with a lock file or an image fails and
says why. Two routes still produce it. Supply an existing document through `SBOM_FILE`
and it is validated against the official schema for the version it declares, then
written back at that version rather than relabelled. Or set `LOCK_FILE: none` and list
the packages in `ADDITIONAL_PACKAGES`, which builds a 3.0.1 document from that list.

**CycloneDX 1.2 is the one gap in the other direction.** It can be generated, but no
1.2 schema ships here, so a 1.2 document goes out unchecked. Pick 1.3 or higher if you
want the schema check, and 1.6 or higher if you want the BSI floor below.

Override the version with `SPEC_VERSION`, or the `spec-version` input.

### Which standard is which

Worth knowing if a procurement clause cites "the ISO SBOM standard", because the
version you pick decides whether you meet it.

- **ISO/IEC 5962:2021 is SPDX 2.2.1**, published August 2021. It is the only SPDX
  version with an ISO number. See the SPDX project's own
  [v2.2.1 release notes](https://github.com/spdx/spdx-spec/releases/tag/v2.2.1).
- **SPDX 3.0 is an OMG specification**, `formal/24-11-01`, March 2025. See
  [omg.org/spec/SPDX](https://www.omg.org/spec/SPDX/). It is not covered by
  ISO/IEC 5962:2021.
- **[BSI TR-03183-2](https://sbomify.com/compliance/bsi-tr-03183/) v2.1.0 §4** asks
  for SPDX 3.0.1 or higher, or CycloneDX 1.6 or higher, for newly generated SBOMs.
  An SPDX 3.0 document misses that floor by one patch digit, and 3.0 is what syft,
  Microsoft sbom-tool, JFrog Xray and Yocto 5.x emit.

So SPDX 2.3 is the ISO-adjacent choice this action can generate, and CycloneDX 1.6
is the one that clears the BSI floor without needing a document from elsewhere.

## Action inputs

Everything the action does is driven by environment variables, listed in the
[configuration reference](https://sbomify.com/sbomify-action/configuration/). These few are
also available as `with:` inputs:

| Input | Environment variable | Description |
| --- | --- | --- |
| `working-dir` | `WORKING_DIR` | Directory to work in, relative to the repo root |
| `component-purl` | `COMPONENT_PURL` | Override the component PURL in the SBOM |
| `bom-type` | `BOM_TYPE` | `sbom` (default), `vex`, `cbom` or `hbom` |
| `sbom-format` | `SBOM_FORMAT` | `cyclonedx` (default) or `spdx` |
| `spec-version` | `SPEC_VERSION` | Spec version to generate. CycloneDX 1.2–1.7, SPDX 2.2 or 2.3, or SPDX 3.0.1 with `LOCK_FILE: none`. Ignored when `SBOM_FILE` names a real file |
| `oidc-audience` | `OIDC_AUDIENCE` | Audience for trusted publishing; override for self-hosted |

## Documents

Compliance asks for more than an SBOM. The EU CRA wants a security assessment and a declaration of
conformity, SOC 2 and ISO 27001 want their attestation reports, and FDA and PCI DSS name several
more. Those are documents, not BOMs — and they belong beside the SBOM they describe rather than in
a shared drive somewhere.

Point `DOCUMENT_FILE` at the file. It is uploaded exactly as authored: nothing is generated,
augmented, enriched or re-serialized, so a signed report stays byte-for-byte the one that was
signed.

```yaml
- uses: sbomify/sbomify-action@master
  env:
    TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
    COMPONENT_ID: ${{ vars.DOCS_COMPONENT_ID }}
    DOCUMENT_FILE: reports/pentest-2026.pdf
    DOCUMENT_TYPE: pentest-report
    DOCUMENT_VERSION: '2026.1'
```

The component must be of type **document** in sbomify; a component created for SBOMs (type `bom`)
cannot hold documents. Locally or on any other CI the same variables work with the container image
and with `uvx sbomify-action`, and every one of them has a CLI flag (`--document-file`,
`--document-type`, …).

| Variable | Default | Description |
| --- | --- | --- |
| `DOCUMENT_FILE` | — | Path to the document. Mutually exclusive with `SBOM_FILE` / `LOCK_FILE` / `SOURCE_DIR` / `DOCKER_IMAGE` |
| `DOCUMENT_NAME` | file name without its extension | Name shown in sbomify |
| `DOCUMENT_TYPE` | `other` | See the list below |
| `DOCUMENT_VERSION` | `COMPONENT_VERSION`, else `1.0` | Version recorded for the document |
| `DOCUMENT_DESCRIPTION` | empty | Free text stored with the document |
| `DOCUMENT_COMPLIANCE_SUBCATEGORY` | — | `nda`, `soc2` or `iso27001`; only for `DOCUMENT_TYPE: compliance` |

`PRODUCT_RELEASE` tags the uploaded document into a release exactly as it does an SBOM, so a
release can carry its SBOM and its evidence together. OIDC trusted publishing works the same way
too — no token needed on GitHub Actions.

**Document types:** `specification`, `manual`, `readme`, `documentation`, `build-instructions`,
`configuration`, `license`, `compliance`, `evidence`, `changelog`, `release-notes`,
`security-advisory`, `vulnerability-report`, `threat-model`, `risk-assessment`, `pentest-report`,
`static-analysis`, `dynamic-analysis`, `quality-metrics`, `maturity-report`, `report`, `other`.

Documents are capped at 50 MB each.

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
