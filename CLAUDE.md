# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

sbomify action is an SBOM (Software Bill of Materials) generation, enrichment, augmentation, and management tool for CI/CD pipelines. It supports CycloneDX and SPDX formats, generates SBOMs from lockfiles and Docker images, enriches them with metadata from package registries, and uploads to various destinations.

**Key facts:** Python 3.10+, published to PyPI as `sbomify-action`, also available as Docker image and GitHub Action.

## Development Commands

```bash
# Install dependencies
uv sync --locked --dev

# Run linting
uv run ruff check sbomify_action tests

# Run format check
uv run ruff format --check sbomify_action tests

# Run tests (80% coverage required)
uv run pytest
```

## Architecture

The project uses a **Protocol + Registry + Factory** pattern across four main subsystems (see `docs/adr/0001-plugin-architecture.md`).

### Protocol Interface

Each plugin implements:
- Properties: `name`, `priority`
- Methods: `supports(input) -> bool`, `execute(input, context) -> NormalizedOutput`

### Priority Model (Native-First with Generic Fallback)

| Priority | Category             | Rationale                                   |
|----------|----------------------|---------------------------------------------|
| 1-20     | Native/Authoritative | Direct from ecosystem's official source     |
| 21-50    | Primary Aggregators  | Well-maintained multi-ecosystem services    |
| 51-80    | Local Extraction     | No external API calls, parse available data |
| 81-100   | Fallback Sources     | Rate-limited or less reliable sources       |

### Subsystems

1. **Generation** (`sbomify_action/_generation/`) - Converts lockfiles/Docker images to SBOMs
   - Plugins: `cyclonedx_py`, `cargo_cyclonedx`, `cdxgen`, `trivy`, `syft`

2. **Enrichment** (`sbomify_action/_enrichment/`) - Fetches package metadata from registries
   - Sources: `pypi`, `pubdev`, `debian`, `license_db`, `lifecycle`, `conan`, `cratesio`, `depsdev`, `ecosystems`, `repology`
   - All sources output to `NormalizedMetadata` dataclass

3. **Augmentation** (`sbomify_action/_augmentation/`) - Adds organizational metadata
   - Providers: `json_config` (sbomify.json), `sbomify_api`, `github`, `gitlab`, `bitbucket`
   - Auto-detects VCS info from CI environment

4. **Upload** (`sbomify_action/_upload/`) - Uploads SBOMs to destinations
   - Destinations: `sbomify`, `dependency_track`

**Note:** By relying on third-party sources, SBOM generation is not guaranteed to be deterministic. The same input may produce different outputs depending on external source availability or data changes.

### CLI Pipeline (`sbomify_action/cli/main.py`)

Three-step orchestration: Generate/Validate → Augment → Enrich → Upload

Each step maintains an audit trail with timestamps for compliance.

### Key Modules

- `console.py` - Rich-formatted CLI output, audit trail formatting
- `serialization.py` - CycloneDX/SPDX serialization
- `validation.py` - JSON schema validation for SBOMs
- `additional_packages.py` - Inject additional packages into SBOMs
- `exceptions.py` - Custom exception hierarchy

## Development Rules

- Never edit lockfiles manually - use `uv` for dependency management
- Always run tests before committing
- Maintain 80%+ test coverage
- Use `git --no-pager` for git operations
- Never create summary/documentation files unless explicitly requested

## Python Best Practices

This project targets Python 3.10+. Use modern Python features:

- **Type hints**: Use built-in generics (`list[str]`, `dict[str, int]`) instead of `typing.List`, `typing.Dict`
- **Union types**: Use `X | Y` syntax instead of `Union[X, Y]` or `Optional[X]` (use `X | None`)
- **f-strings**: Always prefer f-strings over `.format()` or `%` formatting
- **Pattern matching**: Use `match`/`case` statements where appropriate for complex conditionals
- **Walrus operator**: Use `:=` for assignment expressions when it improves readability
