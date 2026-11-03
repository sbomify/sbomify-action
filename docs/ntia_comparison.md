## SBOM Quality Improvement

SBOM generators like Trivy and Syft produce minimal component data—typically just name, version, and PURL.
sbomify enriches every component with metadata from authoritative package registries, making your SBOMs
more useful for vulnerability management, license compliance, and supply chain analysis.

### NTIA Minimum Elements

sbomify helps you achieve compliance with the [NTIA Minimum Elements for SBOM](https://sbomify.com/compliance/ntia-minimum-elements/),
the foundational US baseline for SBOM data fields. The table below shows how sbomify contributes to each required element:

| NTIA Element                | CycloneDX Field                             | SPDX Field                       | Provided By  |
| --------------------------- | ------------------------------------------- | -------------------------------- | ------------ |
| **Supplier Name**           | `components[].publisher` or `supplier.name` | `packages[].supplier`            | Enrichment   |
| **Component Name**          | `components[].name`                         | `packages[].name`                | Generator    |
| **Component Version**       | `components[].version`                      | `packages[].versionInfo`         | Generator    |
| **Unique Identifiers**      | `components[].purl`                         | `packages[].externalRefs[].purl` | Generator    |
| **Dependency Relationship** | `dependencies[]`                            | `relationships[]`                | Generator    |
| **SBOM Author**             | `metadata.authors[]`                        | `creationInfo.creators[]`        | Augmentation |
| **Timestamp**               | `metadata.timestamp`                        | `creationInfo.created`           | Generator    |

For the complete field mapping across CycloneDX and SPDX versions, see the
[Schema Crosswalk](https://sbomify.com/compliance/schema-crosswalk/).

### Enrichment: Beyond NTIA Minimums

Beyond the NTIA minimum elements, sbomify enriches each component with **7 additional metadata fields**
from authoritative package registries. These fields improve SBOM utility for vulnerability management,
license compliance, and supply chain analysis:

| Ecosystem        | Scanner | Metadata Fields |           |           |
| ---------------- | ------- | --------------- | --------- | --------- |
|                  |         | **Before**      | **After** | **Added** |
| Python (pip)     | Trivy   | 0/7             | 7/7 ✅    | +7 fields |
| Python (pip)     | Syft    | 0/7             | 7/7 ✅    | +7 fields |
| Debian (deb)     | Trivy   | 0/7             | 7/7 ✅    | +7 fields |
| Alpine (apk)     | Trivy   | 1/7             | 7/7 ✅    | +6 fields |
| JavaScript (npm) | Trivy   | 0/7             | 7/7 ✅    | +7 fields |
| Rust (cargo)     | Trivy   | 0/7             | 7/7 ✅    | +7 fields |
| Go (mod)         | Trivy   | 0/7             | 7/7 ✅    | +7 fields |
| Ruby (gem)       | Trivy   | 0/7             | 7/7 ✅    | +7 fields |
| Dart (pub)       | Trivy   | 0/7             | 7/7 ✅    | +7 fields |

### Field-by-Field Breakdown

Legend: ✅ Present in scanner output | 🔧 Added by sbomify

| Ecosystem        | Supplier | License | Description | Homepage | Repository | Download | Issues |
| ---------------- | -------- | ------- | ----------- | -------- | ---------- | -------- | ------ |
| Python (pip)     | 🔧       | 🔧      | 🔧          | 🔧       | 🔧         | 🔧       | 🔧     |
| Debian (deb)     | 🔧       | 🔧      | 🔧          | 🔧       | 🔧         | 🔧       | 🔧     |
| Alpine (apk)     | 🔧       | ✅      | 🔧          | 🔧       | 🔧         | 🔧       | 🔧     |
| JavaScript (npm) | 🔧       | 🔧      | 🔧          | 🔧       | 🔧         | 🔧       | 🔧     |
| Rust (cargo)     | 🔧       | 🔧      | 🔧          | 🔧       | 🔧         | 🔧       | 🔧     |
| Go (mod)         | 🔧       | 🔧      | 🔧          | 🔧       | 🔧         | 🔧       | 🔧     |
| Ruby (gem)       | 🔧       | 🔧      | 🔧          | 🔧       | 🔧         | 🔧       | 🔧     |
| Dart (pub)       | 🔧       | 🔧      | 🔧          | 🔧       | 🔧         | 🔧       | 🔧     |

### Data Sources

sbomify queries multiple authoritative sources in priority order:

| Ecosystem      | Primary Source | Fallback Sources      |
| -------------- | -------------- | --------------------- |
| Python         | PyPI API       | deps.dev, ecosyste.ms |
| JavaScript     | deps.dev       | ecosyste.ms           |
| Rust           | deps.dev       | ecosyste.ms           |
| Go             | deps.dev       | ecosyste.ms           |
| Ruby           | deps.dev       | ecosyste.ms           |
| Java/Maven     | deps.dev       | ecosyste.ms           |
| Dart           | pub.dev API    | ecosyste.ms           |
| Debian/Ubuntu  | Debian Sources | Repology, ecosyste.ms |
| Alpine         | Repology       | ecosyste.ms           |
| Red Hat/Fedora | Repology       | ecosyste.ms           |

### Before and After

**Trivy output (4 fields):**

```json
{
  "type": "library",
  "name": "django",
  "version": "5.1",
  "purl": "pkg:pypi/django@5.1"
}
```

**After sbomify enrichment (11 fields):**

```json
{
  "type": "library",
  "name": "django",
  "version": "5.1",
  "purl": "pkg:pypi/django@5.1",
  "publisher": "Django Software Foundation",
  "description": "A high-level Python web framework that encourages rapid development and clean, pragmatic design.",
  "licenses": [
    {
      "expression": "BSD-3-Clause"
    }
  ],
  "externalReferences": [
    {
      "type": "website",
      "url": "https://www.djangoproject.com/"
    },
    {
      "type": "vcs",
      "url": "https://github.com/django/django"
    },
    {
      "type": "distribution",
      "url": "https://pypi.org/project/Django/"
    },
    {
      "type": "issue-tracker",
      "url": "https://code.djangoproject.com/"
    }
  ]
}
```

### CISA 2025 Additional Fields

The [CISA 2025 Minimum Elements](https://sbomify.com/compliance/cisa-minimum-elements/) draft introduces
additional fields beyond NTIA 2021. sbomify supports these where applicable:

| CISA 2025 Field        | CycloneDX Field                      | SPDX Field                    | Status                         |
| ---------------------- | ------------------------------------ | ----------------------------- | ------------------------------ |
| **Component Hash**     | `components[].hashes[]`              | `packages[].checksums[]`      | From generators                |
| **License**            | `components[].licenses[]`            | `packages[].licenseDeclared`  | Enrichment adds                |
| **Tool Name/Version**  | `metadata.tools`                     | `creationInfo.creators[]`     | Generator and sbomify-action   |
| **Generation Context** | `metadata.lifecycles[].phase` (1.5+) | `creationInfo.creatorComment` | From input; config overrides   |

_Generated: 2025-12-17 — Run `uv run scripts/generate_ntia_comparison.py` to update_
