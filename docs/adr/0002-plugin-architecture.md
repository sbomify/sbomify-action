# 2. Plugin Architecture for Extensibility

Date: 2025-01-16

## Status

Accepted

## Context

The sbomify action needs to integrate with multiple external services and data sources across different subsystems:

- **Enrichment**: Multiple metadata sources (PyPI, deps.dev, ecosyste.ms, Repology, etc.)
- **Augmentation**: Organizational metadata sources (sbomify API, etc.) - _to migrate_
- **Generation**: Multiple SBOM generators (cyclonedx-py, Trivy, Syft) - _migrated_
- **Upload**: Multiple destinations (sbomify API, GitHub release artifacts, etc.) - _to migrate_

Each subsystem faces similar challenges:

- Different implementations with different capabilities
- Need to select appropriate implementation based on context
- Need fallback strategies when primary options fail
- Need consistent output regardless of which implementation is used
- Implementations should be independently testable

## Decision

Adopt a **Protocol + Registry + Factory** pattern for all extensible subsystems.

### 1. Protocol (Interface Definition)

- Python `Protocol` class defining the contract all plugins must implement
- Properties: `name`, `priority`
- Methods: `supports(input) -> bool`, `execute(input, context) -> NormalizedOutput`

### 2. Registry (Plugin Management)

- Central registry for plugin registration and discovery
- Query plugins by capability (`get_plugins_for(input)`)
- Execute in priority order with optional result merging
- Early stopping when sufficient results obtained

### 3. Normalized Output (Canonical Data Structure)

- Dataclass representing the canonical output format
- Source attribution tracking (which plugin provided which data)
- `merge()` method for combining results from multiple plugins

### 4. Factory Function

- `create_default_registry()` to configure standard plugins
- Allows custom configuration for testing or special use cases

## Priority Model: Native-First with Generic Fallback

A key design principle is **preferring domain-specific (native) implementations over generic ones**:

| Priority Range | Category             | Rationale                                        |
| -------------- | -------------------- | ------------------------------------------------ |
| 1-20           | Native/Authoritative | Direct from the ecosystem's official source      |
| 21-50          | Primary Aggregators  | Well-maintained multi-ecosystem services         |
| 51-80          | Local Extraction     | No external API calls, parse from available data |
| 81-100         | Fallback Sources     | Rate-limited or less reliable sources            |

### Rationale

- Native sources have the most accurate, complete, and up-to-date data
- Generic aggregators may have stale data or incomplete coverage
- Fallbacks provide coverage when native sources are unavailable

### Examples by Subsystem

**Enrichment:**

- Native: PyPI for `pkg:pypi/*`, pub.dev for `pkg:pub/*`, Debian Sources for `pkg:deb/debian/*`
- Generic: ecosyste.ms, deps.dev (cover many ecosystems but less authoritative)
- Fallback: Repology (rate-limited), PURL extraction (no API, limited data)

**Augmentation (to migrate):**

- Native: sbomify API (organizational metadata like supplier, authors, licenses)
- Generic: Environment variables, GitHub variables, JSON config file in repo

**Generation (to migrate):**

- Native: CycloneDX CLI for CycloneDX output, SPDX tools for SPDX output
- Generic: Trivy, Syft (support multiple formats, broad ecosystem coverage)

**Upload (to migrate):**

- Native: sbomify API (our platform)
- Generic: GitHub release artifacts, other storage destinations

## First Implementation: Enrichment

The enrichment subsystem (`sbomify_action/_enrichment/`) demonstrates this pattern:

| Generic Concept   | Enrichment Implementation                    |
| ----------------- | -------------------------------------------- |
| Protocol          | `DataSource` in `protocol.py`                |
| Registry          | `SourceRegistry` in `registry.py`            |
| Normalized Output | `NormalizedMetadata` in `metadata.py`        |
| Factory           | `create_default_registry()` in `enricher.py` |
| Plugins           | 9 sources in `sources/` directory            |

### Directory Structure

```
sbomify_action/_enrichment/
├── __init__.py          # Public exports
├── protocol.py          # DataSource Protocol definition
├── registry.py          # SourceRegistry class
├── metadata.py          # NormalizedMetadata dataclass
├── enricher.py          # Enricher orchestration + factory
└── sources/             # Plugin implementations
    ├── __init__.py
    ├── pypi.py          # Priority 10 - Native
    ├── pubdev.py        # Priority 10 - Native
    ├── debian.py        # Priority 10 - Native
    ├── rpmrepo.py       # Priority 15 - Native
    ├── depsdev.py       # Priority 40 - Aggregator
    ├── ecosystems.py    # Priority 45 - Aggregator
    ├── purl.py          # Priority 70 - Local extraction
    ├── clearlydefined.py # Priority 75 - Fallback
    └── repology.py      # Priority 90 - Fallback
```

## Consequences

### Benefits

- **Extensibility**: Add new implementations by implementing Protocol and registering
- **Testability**: Each plugin is isolated and independently testable
- **Flexibility**: Priority-based execution with fallback strategies
- **Consistency**: Normalized output ensures uniform data regardless of source
- **Attribution**: Track which plugin provided which data

### Trade-offs

- Additional abstraction layer adds some complexity
- Need to maintain consistent Protocol interface across plugins
- Priority tuning may require iteration
- **Non-deterministic output**: By relying on third-party sources and lookup order, SBOM generation is no longer guaranteed to be deterministic. The same input may produce different outputs depending on external source availability, response data changes, or network conditions

## Subsystems to Migrate

- **Augmentation**: `MetadataSource` protocol with sbomify API, environment variables, GitHub variables, JSON config file
- **Generation**: `Generator` protocol with cyclonedx-py, Trivy, Syft implementations
- **Upload**: `Destination` protocol with sbomify API, GitHub release artifacts implementations
