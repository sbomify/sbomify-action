# Design: TEA CLI Subcommand (`sbomify-action tea`)

**Date:** 2026-03-05
**Status:** Approved
**Approach:** A — TEA CLI Subcommand (lightweight wrapper around libtea)

## Overview

Add a `sbomify-action tea` subcommand group that exposes TEA (Transparency Exchange API) capabilities in CI/CD pipelines. This wraps the `libtea` library (read-only TEA client) without modifying any existing sbomify-action subsystems.

## Rationale

- Lowest coupling — libtea stays a dependency, no deep changes to enrichment/upload/processors
- Immediate value — users get TEA access in their pipelines today
- Natural expansion point — deep pipeline integration (Approach B) can be layered on later
- Matches libtea's strength (read-only queries, discovery, conformance)

## Command Structure

```
sbomify-action tea [GLOBAL OPTIONS] SUBCOMMAND [OPTIONS]

Global Options:
  --base-url TEXT     TEA server base URL (env: TEA_BASE_URL)
  --domain TEXT       Domain for .well-known/tea discovery (env: TEA_DOMAIN)
  --token TEXT        Bearer token (env: TEA_TOKEN)
  --json              Output as JSON instead of formatted text
  --timeout FLOAT     Request timeout in seconds (default: 30)
```

### Subcommands

#### `tea discover`
Resolve a TEI URN to product releases.
```
sbomify-action tea discover --tei "urn:tei:purl:example.com:pkg:pypi/requests@2.31"
```
- Calls `client.discover(tei)`
- Outputs list of DiscoveryInfo (product_release_uuid + servers)

#### `tea fetch`
Download an SBOM/artifact from a TEA server.
```
sbomify-action tea fetch --product-release-uuid <uuid> -o sbom.json
sbomify-action tea fetch --tei "urn:tei:..." -o sbom.json
sbomify-action tea fetch --component-release-uuid <uuid> -o sbom.json
```
- Resolves TEI -> gets latest collection -> finds BOM artifact -> downloads with checksum verification
- `--artifact-type` option (BOM, VEX, ATTESTATION, etc.) defaults to BOM
- Prefers `application/vnd.cyclonedx+json`, falls back to `application/spdx+json`
- Output file can be fed into `sbomify-action --input-file sbom.json`

#### `tea search`
Search products or releases by identifier.
```
sbomify-action tea search --purl "pkg:pypi/requests@2.31"
sbomify-action tea search --cpe "cpe:2.3:a:python:requests:2.31:*"
sbomify-action tea search --type products --purl "pkg:pypi/requests"
sbomify-action tea search --type releases --purl "pkg:pypi/requests@2.31"
```
- `--type` defaults to `releases`
- Calls `client.search_products()` or `client.search_product_releases()`

#### `tea inspect`
Deep-dive into a product release.
```
sbomify-action tea inspect --product-release-uuid <uuid>
sbomify-action tea inspect --tei "urn:tei:..."
```
- Gets product release -> components -> latest collection -> artifacts -> CLE
- Full picture: what's in this release, artifacts available, lifecycle status

#### `tea conformance`
Run TEA spec compliance suite against a server.
```
sbomify-action tea conformance --base-url https://tea.example.com/v1
sbomify-action tea conformance --base-url https://tea.example.com/v1 --tei "urn:tei:..."
```
- Wraps libtea's `run_conformance()` (28 checks)
- Exit code 1 if any check fails (CI gate)

## Architecture

### Files

**New (2):**
- `sbomify_action/cli/tea.py` — Click group with 5 subcommands
- `tests/test_tea_cli.py` — Tests using CliRunner, mocking TeaClient

**Modified (1):**
- `sbomify_action/cli/main.py` — Add `cli.add_command(tea_group)`

### Key Decisions

- Shared helper `_build_client(base_url, domain, token, timeout)` validates inputs and creates TeaClient
- Rich tables by default, `--json` flag for machine-readable CI output
- libtea exceptions (`TeaError` hierarchy) caught and mapped to clean CLI errors + `sys.exit(1)`
- `tea fetch` exit code: 0 success, 1 failure
- `tea conformance` exit code: 0 all pass, 1 any failure

### Testing

- Mock `TeaClient` at class level (libtea provides `TeaClientProtocol`)
- `click.testing.CliRunner` for all subcommand tests
- No network calls — all tests fast

## Future: Approach B (Deep Pipeline Integration)

After this ships and we get user feedback, layer on:
- TEA enrichment source in `_enrichment/sources/tea.py`
- TEA verification processor in `_processors/processors/tea_verification.py`
- TEA upload destination in `_upload/destinations/tea.py` (requires implementing write API)
