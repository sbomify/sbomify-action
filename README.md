# sbomify action

[![sbomified](https://sbomify.com/assets/images/logo/badge.svg)](https://app.sbomify.com/public/component/Gu9wem8mkX)
[![CI/CD Pipeline](https://github.com/sbomify/sbomify-action/actions/workflows/sbomify.yaml/badge.svg)](https://github.com/sbomify/sbomify-action/actions/workflows/sbomify.yaml)
[![PyPI version](https://badge.fury.io/py/sbomify-action.svg)](https://pypi.org/project/sbomify-action/)
[![Slack](https://img.shields.io/badge/Slack-Join%20Community-4A154B?logo=slack)](https://join.slack.com/t/sbomify/shared_invite/zt-3na54pa1f-MXrFWhotmZr0YxXc8sABTw)

### See it in action: FOSDEM 2026 Talk

Watch our FOSDEM 2026 talk for a real-world crash course on generating CRA-ready SBOMs — covering the full pipeline from authoring to enrichment and signing.

[![CRA-Ready SBOMs: A Practical Blueprint for High-Quality Generation — FOSDEM 2026](docs/assets/fosdem-2026-talk-thumbnail.png)](https://sbomify.com/2026/02/04/announcing-sbomify-action-v0-13-the-one-where-we-go-to-fosdem/)

Generate, augment, enrich, and manage SBOMs in your CI/CD pipeline. Works standalone or with [sbomify](https://sbomify.com).

**Recommended**: Use the GitHub Action or Docker image—they include all SBOM generators (Trivy, Syft, cdxgen) pre-installed. For other CI platforms, see [examples below](#other-cicd-platforms). A [pip package](#pip-advanced) is also available for advanced use cases.

**Why generate SBOMs in CI/CD?** Generating SBOMs at build time enables cryptographic signing and attestation, creating a verifiable chain of trust from source to artifact. Learn more about the [SBOM lifecycle](https://sbomify.com/features/generate-collaborate-analyze/).

## Quick Start

```yaml
- uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: requirements.txt
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: false
    ENRICH: true
```

That's it! This generates a CycloneDX SBOM from your lockfile and enriches it with metadata from package registries. For SPDX format, set `SBOM_FORMAT: spdx`.

## Features

- **Generate** SBOMs from lockfiles (Python, Node, Rust, Go, Ruby, Dart, C++) in CycloneDX or SPDX format
- **Generate** SBOMs from Docker images
- **Yocto/OpenEmbedded** — Batch process SPDX SBOMs from Yocto builds (extract, upload, release-tag)
- **Inject** additional packages not in lockfiles (vendored code, runtime deps, system libraries)
- **Augment** with business metadata (supplier, authors, licenses, lifecycle phase) from config file or sbomify
- **VCS Auto-Detection** — Automatically adds repository URL, commit SHA, and branch info from CI environment
- **Enrich** with package metadata from PyPI, pub.dev, crates.io, Conan Center, deps.dev, and more
- **Audit Trail** — Every SBOM modification logged with timestamps for attestation and compliance
- **Upload** to sbomify for collaboration and vulnerability management
- **Tag** SBOMs with product releases
- **Attest** with GitHub's build provenance

## Usage Examples

### Standalone (no sbomify account needed)

```yaml
- uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: poetry.lock
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: false
    COMPONENT_NAME: my-app
    COMPONENT_VERSION: ${{ github.ref_name }}
    ENRICH: true
```

### With sbomify

```yaml
- uses: sbomify/sbomify-action@master
  env:
    TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
    COMPONENT_ID: your-component-id
    LOCK_FILE: requirements.txt
    AUGMENT: true
    ENRICH: true
```

### Docker Image

```yaml
- uses: sbomify/sbomify-action@master
  env:
    DOCKER_IMAGE: my-app:latest
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: false
    ENRICH: true
```

<details>
<summary><strong>More examples</strong> (augmentation, SPDX, attestation, additional packages...)</summary>

### Standalone with Augmentation

Add business metadata without a sbomify account using a local config file:

```yaml
- uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: requirements.txt
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: false
    AUGMENT: true  # Uses sbomify.json in project root
    ENRICH: true
```

See [Augmentation Config File](#augmentation-config-file) for the config format.

### Self-Hosted sbomify

```yaml
- uses: sbomify/sbomify-action@master
  env:
    TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
    COMPONENT_ID: your-component-id
    API_BASE_URL: https://sbomify.yourcompany.com
    LOCK_FILE: requirements.txt
    AUGMENT: true
    ENRICH: true
```

### SPDX Format

Generate SPDX instead of CycloneDX:

```yaml
- uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: requirements.txt
    OUTPUT_FILE: sbom.spdx.json
    SBOM_FORMAT: spdx
    UPLOAD: false
    ENRICH: true
```

### Additional Packages Only (No Lockfile)

Create an SBOM from scratch containing only manually-specified packages—useful for vendored code, system libraries, or manual dependency declarations where no lockfile exists:

```yaml
- uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: none
    ADDITIONAL_PACKAGES: "pkg:pypi/requests@2.31.0,pkg:deb/debian/openssl@3.0.11"
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: false
    ENRICH: true
```

Or use a file for more complex package lists:

```yaml
- uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: none
    ADDITIONAL_PACKAGES_FILE: my-packages.txt
    OUTPUT_FILE: sbom.cdx.json
    SBOM_FORMAT: spdx
    UPLOAD: false
```

Setting `LOCK_FILE` (or `SBOM_FILE`) to `none` creates an empty SBOM and injects the specified additional packages. At least one additional package must be configured via `ADDITIONAL_PACKAGES`, `ADDITIONAL_PACKAGES_FILE`, or `additional_packages.txt`.

### With Attestation

```yaml
- uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: Cargo.lock
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: false
    ENRICH: true

- uses: actions/attest-build-provenance@v1
  with:
    subject-path: sbom.cdx.json
```

</details>

## Configuration

| Variable                   | Required | Description                                                                      |
| -------------------------- | -------- | -------------------------------------------------------------------------------- |
| `LOCK_FILE`                | †        | Path to lockfile, or `none` for additional-packages-only mode                    |
| `SBOM_FILE`                | †        | Path to existing SBOM file, or `none` for additional-packages-only mode          |
| `DOCKER_IMAGE`             | †        | Docker image name                                                                |
| `OUTPUT_FILE`              | No       | Write final SBOM to this path                                                    |
| `SBOM_FORMAT`              | No       | Output format: `cyclonedx` (default) or `spdx`                                   |
| `ENRICH`                   | No       | Add metadata from package registries                                             |
| `TOKEN`                    | ‡        | sbomify API token                                                                |
| `COMPONENT_ID`             | ‡        | sbomify component ID                                                             |
| `AUGMENT`                  | No       | Add metadata from sbomify                                                        |
| `COMPONENT_NAME`           | No       | Override component name in SBOM                                                  |
| `COMPONENT_VERSION`        | No       | Override component version in SBOM                                               |
| `COMPONENT_PURL`           | No       | Add or override component PURL in SBOM                                           |
| `PRODUCT_RELEASE`          | No       | Tag SBOM with product releases (see [Product Releases](#product-releases))       |
| `UPLOAD`                   | No       | Upload SBOM (default: true)                                                      |
| `UPLOAD_DESTINATIONS`      | No       | Comma-separated destinations: `sbomify`, `dependency-track` (default: `sbomify`) |
| `API_BASE_URL`             | No       | Override sbomify API URL for self-hosted instances                               |
| `ADDITIONAL_PACKAGES_FILE` | No       | Custom path to additional packages file                                          |
| `ADDITIONAL_PACKAGES`      | No       | Inline PURLs to inject (comma or newline separated)                              |
| `DISABLE_VCS_AUGMENTATION` | No       | Set to `true` to disable auto-detection of VCS info from CI environment          |
| `SBOMIFY_CACHE_DIR`        | No       | Directory for sbomify license database cache                                     |
| `TRIVY_CACHE_DIR`          | No       | Directory for Trivy cache                                                        |
| `SYFT_CACHE_DIR`           | No       | Directory for Syft cache                                                         |

† **One** of `LOCK_FILE`, `SBOM_FILE`, or `DOCKER_IMAGE` is required (pick one)
‡ Required when uploading to sbomify or using sbomify features (`AUGMENT`, `PRODUCT_RELEASE`)

<details>
<summary><strong>Dependency Track configuration</strong></summary>

When uploading to Dependency Track (`UPLOAD_DESTINATIONS=dependency-track`), configure with `DTRACK_*` prefixed environment variables:

| Variable             | Required | Description                                                              |
| -------------------- | -------- | ------------------------------------------------------------------------ |
| `DTRACK_API_KEY`     | Yes      | Dependency Track API key                                                 |
| `DTRACK_API_URL`     | Yes      | Full API base URL (e.g., `https://dtrack.example.com/api`)               |
| `DTRACK_PROJECT_ID`  | §        | Project UUID (alternative to using `COMPONENT_NAME`/`COMPONENT_VERSION`) |
| `DTRACK_AUTO_CREATE` | No       | Auto-create project if it doesn't exist (default: false)                 |

§ Either `DTRACK_PROJECT_ID` **or** both `COMPONENT_NAME` and `COMPONENT_VERSION` are required

> **Note**: Dependency Track only supports **CycloneDX** format (not SPDX). It uses the global `COMPONENT_NAME` and `COMPONENT_VERSION` for project identification.

#### Dependency Track Example

```yaml
- uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: requirements.txt
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: true
    UPLOAD_DESTINATIONS: dependency-track
    COMPONENT_NAME: my-app
    COMPONENT_VERSION: ${{ github.ref_name }}
    DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}
    DTRACK_API_URL: https://dtrack.example.com/api
    DTRACK_AUTO_CREATE: true
    ENRICH: true
```

#### Upload to Multiple Destinations

```yaml
- uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: requirements.txt
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: true
    UPLOAD_DESTINATIONS: sbomify,dependency-track
    # Component metadata (used by both sbomify and Dependency Track)
    COMPONENT_NAME: my-app
    COMPONENT_VERSION: ${{ github.ref_name }}
    # sbomify config
    TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
    COMPONENT_ID: your-component-id
    # Dependency Track config
    DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}
    DTRACK_API_URL: https://dtrack.example.com/api
    DTRACK_AUTO_CREATE: true
    ENRICH: true
```

</details>

## Supported Lockfiles

| Language   | Files                                                                          |
| ---------- | ------------------------------------------------------------------------------ |
| Python     | `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pyproject.toml` |
| JavaScript | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` |
| Java       | `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`               |
| Go         | `go.mod`, `go.sum`                                                             |
| Rust       | `Cargo.lock`                                                                   |
| Ruby       | `Gemfile.lock`                                                                 |
| PHP        | `composer.json`, `composer.lock`                                               |
| .NET/C#    | `packages.lock.json`                                                           |
| Swift      | `Package.swift`, `Package.resolved`                                            |
| Dart       | `pubspec.lock`                                                                 |
| Elixir     | `mix.lock`                                                                     |
| Scala      | `build.sbt`                                                                    |
| C++        | `conan.lock`                                                                   |
| Terraform  | `.terraform.lock.hcl`                                                          |

## Yocto/OpenEmbedded

Process SPDX SBOMs produced by Yocto/OpenEmbedded builds. The `yocto` subcommand extracts a `.spdx.tar.zst` (or `.tar.gz`) archive, discovers package SBOMs, creates components in sbomify, uploads each SBOM, and tags them with a product release.

```bash
sbomify-action --token $SBOMIFY_TOKEN \
  yocto tmp/deploy/images/qemux86-64/core-image-base.rootfs.spdx.tar.zst \
  --release "my-product:1.0.0"
```

| Option | Required | Description |
| --- | --- | --- |
| `SBOM_INPUT` (positional) | Yes | Path to `.spdx.tar.zst` or `.tar.gz` archive |
| `--token` (root option) | Yes | sbomify API token (pass before `yocto`, or set `TOKEN` env var) |
| `--release` | Yes | Product release in `product_id:version` format |
| `--augment/--no-augment` | No | Run augmentation per SBOM (default: off) |
| `--enrich/--no-enrich` | No | Run enrichment per SBOM (default: off) |
| `--dry-run` | No | Show what would happen without making API calls |
| `--verbose` | No | Enable verbose logging |

**How it works:**

1. Extracts the archive to a temp directory
2. Scans for `*.spdx.json` files and categorizes them (skips `recipe-*` and `runtime-*` documents)
3. For each package SBOM: gets or creates a component, optionally augments and enriches, then uploads
4. Creates a release and tags all uploaded SBOMs with it

**Input format:** SPDX 2.2 only. The archive is typically found at `tmp/deploy/images/{machine}/` in your Yocto build output.

<details>
<summary><strong>GitHub Actions example</strong></summary>

```yaml
- uses: sbomify/sbomify-action@master
  # Build your Yocto image first, then:
- run: |
    sbomify-action --token ${{ secrets.SBOMIFY_TOKEN }} \
      yocto build/deploy/images/qemux86-64/core-image-base.rootfs.spdx.tar.zst \
      --release "my-product:${{ github.ref_name }}" \
      --enrich
```

</details>

## Augmentation vs Enrichment

**Augmentation** (`AUGMENT=true`) adds organizational metadata to your SBOM—supplier info, authors, licenses, and lifecycle phase. This addresses [NTIA Minimum Elements](https://sbomify.com/compliance/ntia-minimum-elements/) and [CISA 2025](https://sbomify.com/compliance/cisa-minimum-elements/) requirements.

Augmentation sources (in priority order):

1. **Local config file** (`sbomify.json`) — No account needed. Local values take precedence.
2. **sbomify API** — Fetches metadata configured in your sbomify component. Requires account.

**Enrichment** (`ENRICH=true`) fetches package metadata from public registries. No account needed.

### Augmentation Config File

Create `sbomify.json` in your project root to provide augmentation metadata:

```json
{
  "lifecycle_phase": "build",
  "supplier": {
    "name": "My Company",
    "url": ["https://example.com"],
    "contacts": [{"name": "Support", "email": "support@example.com"}]
  },
  "authors": [
    {"name": "John Doe", "email": "john@example.com"}
  ],
  "licenses": ["MIT"],
  "security_contact": "https://example.com/.well-known/security.txt",
  "release_date": "2024-06-15",
  "support_period_end": "2026-12-31",
  "end_of_life": "2028-12-31"
}
```

<details>
<summary><strong>Augmentation config field reference</strong></summary>

| Field                | Description                                  | SBOM Mapping                                                                                         |
| -------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `lifecycle_phase`    | Generation context (CISA 2025)               | CycloneDX 1.5+: `metadata.lifecycles[].phase`; SPDX: `creationInfo.creatorComment`                   |
| `supplier`           | Organization that supplies the component     | CycloneDX: `metadata.supplier`; SPDX: `packages[].supplier`                                          |
| `authors`            | List of component authors                    | CycloneDX: `metadata.authors[]`; SPDX: `creationInfo.creators[]`                                     |
| `licenses`           | SPDX license identifiers                     | CycloneDX: `metadata.licenses[]`; SPDX: Document-level licenses                                      |
| `security_contact`   | URL/email for vulnerability reporting (CRA)  | CycloneDX 1.5+: `externalReferences[type=security-contact]`; SPDX: `externalRefs[category=SECURITY]` |
| `release_date`       | ISO-8601 date when component was released    | CycloneDX 1.5+: `metadata.lifecycles[]` + property; SPDX: external ref                               |
| `support_period_end` | ISO-8601 date when security support ends     | CycloneDX 1.5+: `metadata.lifecycles[]` + property; SPDX: `validUntilDate` + external ref            |
| `end_of_life`        | ISO-8601 date when all support ends          | CycloneDX 1.5+: `metadata.lifecycles[]` + property; SPDX: external ref                               |
| `vcs_url`            | Repository URL (overrides CI auto-detection) | CycloneDX: `externalReferences[type=vcs]`; SPDX: `downloadLocation`                                  |
| `vcs_commit_sha`     | Full commit SHA                              | Appended to VCS URL as `@sha`                                                                        |
| `vcs_ref`            | Branch or tag name                           | Added as comment/context                                                                             |

**Valid `lifecycle_phase` values:** `design`, `pre-build`, `build`, `post-build`, `operations`, `discovery`, `decommission`

**Valid `security_contact` formats:**

- `https://example.com/.well-known/security.txt` — security.txt URL (recommended)
- `mailto:security@example.com` — email address
- `https://example.com/security/report` — disclosure procedure URL

**Valid date formats for `release_date`, `support_period_end`, `end_of_life`:** ISO-8601 date string (e.g., `2028-12-31`)

**Lifecycle date fields explained:**

- `release_date` — When the component was publicly released
- `support_period_end` — When security-only support ends (bugfixes stop, only security patches after this)
- `end_of_life` — When all support ends (no more updates of any kind)

**Priority:** Local config values override sbomify API values when both are available.

</details>

<details>
<summary><strong>VCS information (auto-detected)</strong></summary>

When running in CI environments, sbomify automatically detects and adds VCS (Version Control System) information to your SBOM:

| CI Platform         | Auto-Detected Fields                                                       |
| ------------------- | -------------------------------------------------------------------------- |
| GitHub Actions      | Repository URL, commit SHA, branch/tag (supports GitHub Enterprise Server) |
| GitLab CI           | Project URL, commit SHA, ref name (supports self-managed instances)        |
| Bitbucket Pipelines | Repository URL, commit SHA, branch/tag                                     |

**What's added to the SBOM:**

- **CycloneDX**: VCS external reference on root component with `git+https://...@sha` format
- **SPDX**: `downloadLocation` with commit-pinned URL, `sourceInfo` with build context, VCS external reference

**Overriding auto-detected values:**

Add VCS fields to `sbomify.json` to override auto-detected values (useful for self-hosted instances):

```json
{
  "vcs_url": "https://github.mycompany.com/org/repo",
  "vcs_commit_sha": "abc123def456",
  "vcs_ref": "main"
}
```

**Disabling VCS augmentation:**

Set the environment variable to disable VCS information entirely:

```yaml
env:
  DISABLE_VCS_AUGMENTATION: "true"
```

</details>

### Enrichment Data Sources

| Source         | Package Types                                                    | Data                                            |
| -------------- | ---------------------------------------------------------------- | ----------------------------------------------- |
| License DB     | Alpine, Wolfi, Ubuntu, Rocky, Alma, CentOS, Fedora, Amazon Linux | License, description, supplier, homepage        |
| Lifecycle      | Python, PHP, Go, Rust, Django, Rails, Laravel, React, Vue        | CLE (release date, end-of-support, end-of-life) |
| PyPI           | Python                                                           | License, author, homepage                       |
| pub.dev        | Dart                                                             | License, author, homepage, repo                 |
| crates.io      | Rust/Cargo                                                       | License, author, homepage, repo, description    |
| Conan Center   | C/C++ (Conan)                                                    | License, author, homepage, repo, description    |
| Debian Sources | Debian packages                                                  | Maintainer, description, homepage               |
| deps.dev       | Python, npm, Maven, Go, Ruby, NuGet (+ Rust fallback)            | License, homepage, repo                         |
| ecosyste.ms    | All major ecosystems                                             | License, description, maintainer                |
| ClearlyDefined | Python, npm, Cargo, Maven, Ruby, NuGet, Go                       | License, attribution                            |
| Repology       | Linux distros                                                    | License, homepage                               |

<details>
<summary><strong>License database details</strong></summary>

For Linux distro packages, sbomify uses pre-computed databases that provide comprehensive package metadata. The databases are built by pulling data directly from official distro sources (Alpine APKINDEX, Ubuntu/Debian apt repositories, RPM repos) and normalizing it into a consistent format with validated SPDX license expressions.

- **Generated automatically** on each release from official distro repositories
- **Downloaded on-demand** from GitHub Releases during enrichment (checks up to 5 recent releases)
- **Cached locally** (~/.cache/sbomify/license-db/) for faster subsequent runs
- **Normalized** — vendor-specific license strings converted to valid SPDX expressions

**Data provided:**

| Field        | Description                       |
| ------------ | --------------------------------- |
| License      | SPDX-validated license expression |
| Description  | Package summary                   |
| Supplier     | Package maintainer/vendor         |
| Homepage     | Project website URL               |
| Download URL | Package download location         |
| Maintainer   | Name and email                    |

> **Note**: CLE (lifecycle) data is now provided by the dedicated Lifecycle enrichment source. See [Lifecycle Enrichment](#lifecycle-enrichment) below.

**Supported distros:**

| Distro       | Versions            |
| ------------ | ------------------- |
| Alpine       | 3.13–3.21           |
| Wolfi        | rolling             |
| Debian       | 11, 12, 13          |
| Ubuntu       | 20.04, 22.04, 24.04 |
| Rocky Linux  | 8, 9                |
| AlmaLinux    | 8, 9                |
| CentOS       | Stream 8, Stream 9  |
| Fedora       | 39, 40, 41, 42      |
| Amazon Linux | 2, 2023             |

The license database is the **primary source** for Linux distro packages, taking precedence over other enrichment sources. If a package isn't found in the database, sbomify falls back to Repology and ecosyste.ms.

**Local generation** (advanced): If you need a database for an unsupported version or want to generate offline:

```bash
sbomify-license-db --distro alpine --version 3.20 --output alpine-3.20.json.gz
```

> **Note**: Local generation fallback is disabled by default (Ubuntu/Debian can take hours to generate). Set `SBOMIFY_ENABLE_LICENSE_DB_GENERATION=true` to enable it.

</details>

<details>
<summary><strong>Lifecycle enrichment details</strong></summary>

sbomify provides [CLE (Common Lifecycle Enumeration)](https://sbomify.com/compliance/cle/) data including release dates, end-of-support, and end-of-life dates. This enables automated tracking of outdated or unsupported components.

**Supported operating systems:**

| OS           | Tracked Versions    |
| ------------ | ------------------- |
| Debian       | 10, 11, 12          |
| Ubuntu       | 20.04, 22.04, 24.04 |
| Alpine       | 3.13–3.21           |
| Rocky Linux  | 8, 9                |
| AlmaLinux    | 8, 9                |
| CentOS       | Stream 8, Stream 9  |
| Fedora       | 39–42               |
| Amazon Linux | 2, 2023             |

Operating system components (CycloneDX `type: operating-system`) are enriched with lifecycle data based on their name and version.

**Supported runtimes and frameworks:**

| Package | Tracked Versions               | PURL Matching                       |
| ------- | ------------------------------ | ----------------------------------- |
| Python  | 2.7, 3.10–3.14                 | All types (pypi, deb, rpm, apk)     |
| PHP     | 7.4, 8.0–8.5                   | All types (composer, deb, rpm, apk) |
| Go      | 1.22–1.25                      | All types (golang, deb, rpm, apk)   |
| Rust    | 1.90–1.92                      | All types (cargo, deb, rpm, apk)    |
| Django  | 4.2, 5.2, 6.0                  | PyPI only                           |
| Rails   | 7.0–8.1 (+ all component gems) | RubyGems only                       |
| Laravel | 10–13                          | Composer only                       |
| React   | 17–19                          | npm only                            |
| Vue     | 2, 3                           | npm only                            |

**How it works:**

- **OS components**: Detected by CycloneDX `type: operating-system`, matched by name/version
- **Runtimes/frameworks**: Matched by name pattern across all package managers
- Version cycle extracted from full version (e.g., `3.12.7` → `3.12`, `12.12` → `12`)
- Lifecycle properties added: `cdx:lifecycle:milestone:generalAvailability`, `cdx:lifecycle:milestone:endOfSupport`, `cdx:lifecycle:milestone:endOfLife`

> **Note**: Arbitrary OS packages (curl, nginx, openssl, etc.) do not receive lifecycle data. Only the operating system itself and explicitly tracked runtimes/frameworks get CLE data.

**Example enriched OS component:**

```json
{
  "type": "operating-system",
  "name": "debian",
  "version": "12.12",
  "properties": [
    {"name": "cdx:lifecycle:milestone:generalAvailability", "value": "2023-06-10"},
    {"name": "cdx:lifecycle:milestone:endOfSupport", "value": "2026-06-10"},
    {"name": "cdx:lifecycle:milestone:endOfLife", "value": "2028-06-30"}
  ]
}
```

This allows downstream tools to identify components running on unsupported operating systems or runtimes.

</details>

<details>
<summary><strong>Enrichment priority order by ecosystem</strong></summary>

sbomify queries sources in priority order, stopping when data is found:

| Ecosystem         | Primary Source   | Fallback Sources                        |
| ----------------- | ---------------- | --------------------------------------- |
| Python            | PyPI API         | deps.dev → ecosyste.ms → ClearlyDefined |
| JavaScript        | deps.dev         | ecosyste.ms → ClearlyDefined            |
| Rust              | crates.io API    | deps.dev → ecosyste.ms → ClearlyDefined |
| Go                | deps.dev         | ecosyste.ms → ClearlyDefined            |
| Ruby              | deps.dev         | ecosyste.ms → ClearlyDefined            |
| Java/Maven        | deps.dev         | ecosyste.ms → ClearlyDefined            |
| NuGet             | deps.dev         | ecosyste.ms → ClearlyDefined            |
| Dart              | pub.dev API      | ecosyste.ms                             |
| C++ (Conan)       | Conan Center API | ecosyste.ms                             |
| Debian            | Debian Sources   | Repology → ecosyste.ms                  |
| Ubuntu            | License DB       | Repology → ecosyste.ms                  |
| Alpine            | License DB       | Repology → ecosyste.ms                  |
| Wolfi             | License DB       | Repology → ecosyste.ms                  |
| Rocky/Alma/CentOS | License DB       | Repology → ecosyste.ms                  |
| Fedora            | License DB       | Repology → ecosyste.ms                  |
| Amazon Linux      | License DB       | Repology → ecosyste.ms                  |

**Limitations:**

- **Network required**: Enrichment calls external APIs during CI. Not suitable for air-gapped environments.
- **Rate limits**: APIs may rate-limit large SBOMs. sbomify uses caching and backoff, but very large dependency trees (1000+ packages) may see slower enrichment.
- **Best effort**: If a package isn't in any registry (private packages, vendored code), no metadata will be added.

> 📖 See [docs/enrichment_coverage.md](docs/enrichment_coverage.md) for detailed coverage information by ecosystem.

</details>

<details>
<summary><strong>Audit trail</strong></summary>

Every modification made to your SBOM is tracked and recorded for attestation and compliance purposes. The audit trail captures:

- **Overrides**: Component name, version, and PURL changes from CLI/environment
- **Augmentation**: Supplier, manufacturer, authors, licenses, VCS info, lifecycle phase
- **Enrichment**: Per-component metadata additions (description, license, publisher, URLs)
- **Sanitization**: PURL normalizations, URL validations, stub components added

**Output:**

1. **Summary table** (always visible) — Shows counts by category
2. **`audit_trail.txt` file** — Detailed log written alongside your SBOM output
3. **Attestation output** — Full audit trail printed in collapsible GitHub Actions group

**Example:**

```
┌─────────────────────┬───────┐
│ Metric              │ Value │
├─────────────────────┼───────┤
│ Overrides applied   │     3 │
│ Components enriched │    42 │
│ Sanitization fixes  │     5 │
└─────────────────────┴───────┘
```

**audit_trail.txt:**

```
# SBOM Audit Trail
# Generated: 2026-01-18T12:34:56Z
# Input: requirements.txt
# Output: sbom.cdx.json

## Override
[2026-01-18T12:34:56Z] OVERRIDE component.version SET "2.0.0" (source: cli/env)
[2026-01-18T12:34:56Z] OVERRIDE component.name MODIFIED "old-name" -> "my-app" (source: cli/env)

## Enrichment
[2026-01-18T12:34:57Z] ENRICHMENT pkg:pypi/requests@2.31.0 license ADDED (source: pypi)
[2026-01-18T12:34:57Z] ENRICHMENT pkg:pypi/requests@2.31.0 description ADDED (source: pypi)
```

All timestamps are in UTC (ISO 8601 format with Z suffix).

</details>

<details>
<summary><strong>Product releases</strong></summary>

Tag your SBOMs with product releases for version tracking and release management in sbomify.

```yaml
- uses: sbomify/sbomify-action@master
  env:
    TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
    COMPONENT_ID: your-component-id
    LOCK_FILE: requirements.txt
    PRODUCT_RELEASE: '["product_id:v1.0.0"]'
```

**Format:** JSON array of `"product_id:version"` strings. You can tag multiple releases:

```yaml
PRODUCT_RELEASE: '["product_id_1:v1.0.0", "product_id_2:v2.0.0"]'
```

**Behavior:**

- **Get-or-create**: If the release already exists, it's reused. If not, it's created automatically.
- **Tagging**: The uploaded SBOM is associated with each specified release.
- **Partial failures**: If some releases succeed and others fail, the action logs a warning but continues.

> **Note**: Requires `TOKEN` and `COMPONENT_ID` to be set, as this feature interacts with the sbomify API.

</details>

<details>
<summary><strong>Additional packages</strong></summary>

Inject packages not captured by lockfile scanning—vendored code, runtime dependencies, or system libraries.

#### Convention-Based File

If `additional_packages.txt` exists in your working directory, it's automatically detected:

```txt
# additional_packages.txt
# Runtime dependencies not in lockfile
pkg:pypi/requests@2.31.0
pkg:npm/lodash@4.17.21

# System libraries
pkg:deb/debian/openssl@3.0.11
```

**File format:**

- One [PURL](https://github.com/package-url/purl-spec) per line
- Lines starting with `#` are comments
- Empty lines are ignored

#### Custom File Location

```yaml
- uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: requirements.txt
    ADDITIONAL_PACKAGES_FILE: .sbomify/extra-packages.txt
```

#### Inline Packages

For dynamic or programmatic use:

```yaml
- uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: requirements.txt
    ADDITIONAL_PACKAGES: "pkg:pypi/requests@2.31.0,pkg:npm/lodash@4.17.21"
```

#### Build-Time Injection

Append packages across multiple steps:

```yaml
- name: Add Python runtime deps
  run: echo "pkg:pypi/requests@2.31.0" >> additional_packages.txt

- name: Add system libraries
  run: |
    echo "pkg:deb/debian/openssl@3.0.11" >> additional_packages.txt
    echo "pkg:deb/debian/libssl3@3.0.11" >> additional_packages.txt

- name: Generate SBOM
  uses: sbomify/sbomify-action@master
  env:
    LOCK_FILE: requirements.txt
    # No additional config needed - file is auto-detected
```

**Merge behavior:** If both file and inline packages are provided, they are merged and deduplicated. Injected packages flow through augmentation and enrichment like any other component.

#### Standalone Mode (No Lockfile)

Use `LOCK_FILE=none` (or `SBOM_FILE=none`) to create an SBOM containing only additional packages—no lockfile or existing SBOM required. See the [Additional Packages Only example](#additional-packages-only-no-lockfile) above.

</details>

<details>
<summary><strong>Caching</strong></summary>

The sbomify action caches data internally to speed up runs:

- **License databases** (~20-50MB) - Pre-computed metadata for Linux distro packages
- **Trivy cache** - SBOM generation metadata and package databases
- **Syft cache** - Package metadata for SBOM generation

To persist caches across CI runs, configure your CI platform's caching mechanism.

#### GitHub Actions

Use `actions/cache` before calling the sbomify action:

```yaml
- name: Cache sbomify data
  uses: actions/cache@v4
  with:
    path: .sbomify-cache
    key: sbomify-${{ runner.os }}

- uses: sbomify/sbomify-action@master
  env:
    SBOMIFY_CACHE_DIR: ${{ github.workspace }}/.sbomify-cache
    TRIVY_CACHE_DIR: ${{ github.workspace }}/.sbomify-cache/trivy
    SYFT_CACHE_DIR: ${{ github.workspace }}/.sbomify-cache/syft
    LOCK_FILE: requirements.txt
    ENRICH: true
    UPLOAD: false
```

For caching in other CI environments (GitLab, Bitbucket, Docker), see [Other CI/CD Platforms](#other-cicd-platforms).

</details>

<details>
<summary><strong>Other CI/CD platforms</strong> (GitLab, Bitbucket, Docker, pip)</summary>

#### GitLab

```yaml
generate-sbom:
  image: sbomifyhub/sbomify-action
  cache:
    key: sbomify-cache
    paths:
      - .sbomify-cache/
  variables:
    SBOMIFY_CACHE_DIR: "${CI_PROJECT_DIR}/.sbomify-cache/sbomify"
    TRIVY_CACHE_DIR: "${CI_PROJECT_DIR}/.sbomify-cache/trivy"
    SYFT_CACHE_DIR: "${CI_PROJECT_DIR}/.sbomify-cache/syft"
    LOCK_FILE: poetry.lock
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: "false"
    ENRICH: "true"
  script:
    - sbomify-action
```

#### Bitbucket

```yaml
pipelines:
  default:
    - step:
        caches:
          - sbomify
        script:
          - pipe: docker://sbomifyhub/sbomify-action:latest
            variables:
              SBOMIFY_CACHE_DIR: "${BITBUCKET_CLONE_DIR}/.sbomify-cache/sbomify"
              TRIVY_CACHE_DIR: "${BITBUCKET_CLONE_DIR}/.sbomify-cache/trivy"
              SYFT_CACHE_DIR: "${BITBUCKET_CLONE_DIR}/.sbomify-cache/syft"
              LOCK_FILE: poetry.lock
              OUTPUT_FILE: sbom.cdx.json
              UPLOAD: "false"
              ENRICH: "true"

definitions:
  caches:
    sbomify: .sbomify-cache
```

#### Docker

```bash
# Create persistent cache volume
docker volume create sbomify-cache

docker run --rm \
  -v $(pwd):/github/workspace \
  -v sbomify-cache:/cache \
  -w /github/workspace \
  -e SBOMIFY_CACHE_DIR=/cache/sbomify \
  -e TRIVY_CACHE_DIR=/cache/trivy \
  -e SYFT_CACHE_DIR=/cache/syft \
  -e LOCK_FILE=/github/workspace/requirements.txt \
  -e OUTPUT_FILE=/github/workspace/sbom.cdx.json \
  -e UPLOAD=false \
  -e ENRICH=true \
  sbomifyhub/sbomify-action
```

#### pip (Advanced)

For local development or environments where Docker isn't available, install via pip:

```bash
pip install sbomify-action
```

Run without arguments to see available options:

```bash
sbomify-action
```

Or use CLI arguments directly:

```bash
sbomify-action --lock-file requirements.txt --enrich --no-upload -o sbom.cdx.json
```

Environment variables also work (useful for scripts):

```bash
export LOCK_FILE=requirements.txt
export OUTPUT_FILE=sbom.cdx.json
export UPLOAD=false
export ENRICH=true
sbomify-action
```

**Note**: SBOM generation requires external tools (trivy, syft, or cdxgen) to be installed separately. The Docker image includes all tools pre-installed, which is why it's the recommended approach.

</details>

<details>
<summary><strong>SBOM generation internals</strong> (generator selection, format selection, required tools)</summary>

sbomify uses a plugin architecture for SBOM generation, automatically selecting the best generator for each input type and ecosystem.

#### Generator Selection

Generators are tried in priority order. Native tools (optimized for specific ecosystems) are preferred over generic scanners. Each tool supports different ecosystems:

| Priority | Generator           | Supported Ecosystems                                                                                           | Output Formats                  |
| -------- | ------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| 10       | **cyclonedx-py**    | Python only                                                                                                    | CycloneDX 1.0–1.7               |
| 10       | **cargo-cyclonedx** | Rust only                                                                                                      | CycloneDX 1.4–1.6               |
| 20       | **cdxgen**          | Python, JavaScript, **Java/Gradle**, Go, Rust, Ruby, Dart, C++, PHP, .NET, Swift, Elixir, Scala, Docker images | CycloneDX 1.4–1.7               |
| 30       | **Trivy**           | Python, JavaScript, Java/Gradle, Go, Rust, Ruby, C++, PHP, .NET, Docker images                                 | CycloneDX 1.6, SPDX 2.3         |
| 35       | **Syft**            | Python, JavaScript, Go, Rust, Ruby, Dart, C++, PHP, .NET, Swift, Elixir, Terraform, Docker images              | CycloneDX 1.2–1.6, SPDX 2.2–2.3 |

#### How It Works

1. **Python lockfiles** → cyclonedx-py (native, most accurate for Python)
2. **Rust lockfiles** (Cargo.lock) → cargo-cyclonedx (native, most accurate for Rust)
3. **Java lockfiles** (pom.xml, build.gradle, gradle.lockfile) → cdxgen (best Java support)
4. **Dart lockfiles** (pubspec.lock) → cdxgen or Syft (Trivy doesn't support Dart)
5. **Other lockfiles** (package-lock.json, go.mod, etc.) → cdxgen (then Trivy, then Syft as fallbacks)
6. **Docker images** → cdxgen (then Trivy, then Syft as fallbacks)

If the primary generator fails or doesn't support the input, the next one in priority order is tried automatically.

#### Format Selection

Control the output format with the `SBOM_FORMAT` environment variable:

- **CycloneDX** (`SBOM_FORMAT=cyclonedx`): Default format. Uses the latest version supported by the selected generator.
- **SPDX** (`SBOM_FORMAT=spdx`): Uses Trivy (2.3) or Syft (2.2/2.3) depending on availability.

Generated SBOMs are validated against their JSON schemas before output.

#### Required Tools

When installed via pip, sbomify-action requires external SBOM generators. The Docker image includes all tools pre-installed.

| Tool             | Install Command                                                                                 | Notes                                                                                                                          |
| ---------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **cyclonedx-py** | `pip install cyclonedx-bom`                                                                     | Native Python generator; `cyclonedx-py` is the CLI command provided by the `cyclonedx-bom` package (installed as a dependency) |
| **Trivy**        | [Installation guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) | macOS: `brew install trivy`                                                                                                    |
| **Syft**         | [Installation guide](https://github.com/anchore/syft#installation)                              | macOS: `brew install syft`                                                                                                     |
| **cdxgen**       | `npm install -g @cyclonedx/cdxgen`                                                              | Requires Node.js/Bun                                                                                                           |

**Minimum requirement**: At least one generator must be installed for SBOM generation. For Python projects, `cyclonedx-bom` (which provides the `cyclonedx-py` command) is installed as a dependency when you install sbomify-action via pip. For other ecosystems or Docker images, install `trivy`, `syft`, or `cdxgen`.

</details>

<details>
<summary><strong>SBOM quality improvement</strong> (what enrichment adds, before/after example)</summary>

SBOM generators like Trivy and Syft focus on dependency detection—they produce name, version, and PURL, but typically leave metadata fields empty. sbomify queries package registries to fill in these gaps, improving license compliance and supply chain visibility.

#### What's Typically Missing

Scanners detect packages but don't fetch metadata. Here's what a typical Trivy component looks like:

```json
{
  "type": "library",
  "name": "django",
  "version": "5.1",
  "purl": "pkg:pypi/django@5.1"
}
```

After sbomify enrichment, the same component includes supplier, license, and reference URLs:

```json
{
  "type": "library",
  "name": "django",
  "version": "5.1",
  "purl": "pkg:pypi/django@5.1",
  "publisher": "Django Software Foundation",
  "description": "A high-level Python web framework...",
  "licenses": [{"expression": "BSD-3-Clause"}],
  "externalReferences": [
    {"type": "website", "url": "https://www.djangoproject.com/"},
    {"type": "vcs", "url": "https://github.com/django/django"},
    {"type": "distribution", "url": "https://pypi.org/project/Django/"}
  ]
}
```

#### Fields sbomify Adds

sbomify attempts to populate these fields for each component:

| Field                  | Description                        | Coverage                          |
| ---------------------- | ---------------------------------- | --------------------------------- |
| **Supplier/Publisher** | Package maintainer or organization | High for popular registries       |
| **License**            | SPDX license expression            | High (most registries require it) |
| **Description**        | Package summary                    | High                              |
| **Homepage**           | Project website                    | Medium-High                       |
| **Repository**         | Source code URL                    | Medium-High                       |
| **Download URL**       | Registry/distribution link         | High                              |
| **Issue Tracker**      | Bug reporting URL                  | Medium                            |

**Coverage varies by ecosystem.** Popular packages on PyPI, npm, and crates.io have excellent metadata. Linux distros (Alpine, Ubuntu, Rocky, Alma, CentOS, Fedora, Amazon Linux, Wolfi) have high license coverage through pre-computed license databases. sbomify queries multiple sources with fallbacks, but some fields may remain empty for obscure packages.

</details>

## Format Support

- **CycloneDX**: 1.3, 1.4, 1.5, 1.6, 1.7 (JSON)
- **SPDX**: 2.2, 2.3, 3.0.1 (JSON / JSON-LD)

> 📖 See [docs/adr/0001-plugin-architecture.md](docs/adr/0001-plugin-architecture.md) for architecture details.

## Links

- [Documentation](https://sbomify.com/features/generate-collaborate-analyze/)
- [sbomify Platform](https://sbomify.com)
- [Attestation Guide](https://sbomify.com/2024/10/31/github-action-update-and-attestation/)
- [Architecture Decision Records (ADR)](docs/adr/)

## License

Apache-2.0
