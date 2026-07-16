# TEA CLI Subcommand Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `sbomify-action tea` subcommand group that exposes TEA (Transparency Exchange API) capabilities in CI/CD pipelines.

**Architecture:** Re-export libtea's existing Click CLI group (`libtea.cli.app`) as `sbomify-action tea`, then add one custom `fetch` convenience command that combines discovery + collection lookup + artifact download into a single step. libtea already implements discover, search, inspect, conformance, download, get-cle, and all Rich/JSON formatting.

**Tech Stack:** Click (CLI), libtea 0.4.0+ (TEA client), Rich (formatting via libtea's `_cli_fmt`)

---

### Task 1: Register libtea CLI as `sbomify-action tea`

**Files:**
- Create: `sbomify_action/cli/tea.py`
- Modify: `sbomify_action/cli/main.py` (add 2 lines at bottom, near other `add_command` calls)

**Step 1: Write the failing test**

Create `tests/test_tea_cli.py`:

```python
"""Tests for the TEA CLI subcommand group."""

import unittest

from click.testing import CliRunner

from sbomify_action.cli.main import cli


class TestTeaGroup(unittest.TestCase):
    """Test that the tea subcommand group is registered."""

    def setUp(self):
        self.runner = CliRunner()

    def test_tea_help(self):
        """tea --help should show the TEA CLI help text."""
        result = self.runner.invoke(cli, ["tea", "--help"])
        assert result.exit_code == 0
        assert "TEA" in result.output or "tea" in result.output.lower()

    def test_tea_discover_help(self):
        """tea discover --help should show discover subcommand help."""
        result = self.runner.invoke(cli, ["tea", "discover", "--help"])
        assert result.exit_code == 0
        assert "TEI" in result.output or "tei" in result.output.lower()

    def test_tea_conformance_help(self):
        """tea conformance --help should show conformance subcommand help."""
        result = self.runner.invoke(cli, ["tea", "conformance", "--help"])
        assert result.exit_code == 0
        assert "conformance" in result.output.lower()

    def test_tea_search_products_help(self):
        """tea search-products --help should be available."""
        result = self.runner.invoke(cli, ["tea", "search-products", "--help"])
        assert result.exit_code == 0

    def test_tea_inspect_help(self):
        """tea inspect --help should be available."""
        result = self.runner.invoke(cli, ["tea", "inspect", "--help"])
        assert result.exit_code == 0

    def test_tea_download_help(self):
        """tea download --help should be available."""
        result = self.runner.invoke(cli, ["tea", "download", "--help"])
        assert result.exit_code == 0
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_tea_cli.py -v`
Expected: FAIL — `tea` subcommand not registered yet

**Step 3: Write minimal implementation**

Create `sbomify_action/cli/tea.py`:

```python
"""TEA (Transparency Exchange API) CLI subcommand group.

Re-exports libtea's CLI as ``sbomify-action tea``, providing access to
TEA server discovery, search, inspect, download, and conformance testing
directly from the sbomify-action CLI.

Available subcommands (from libtea):
    discover          Resolve a TEI URN to product release UUIDs
    search-products   Search products by identifier (PURL, CPE, TEI)
    search-releases   Search product releases by identifier
    get-product       Get a product by UUID
    get-release       Get a product or component release by UUID
    get-collection    Get a collection (latest or by version)
    get-product-releases  List releases for a product
    get-component     Get a component by UUID
    get-component-releases  List releases for a component
    list-collections  List collection versions for a release
    get-cle           Get Common Lifecycle Enumeration data
    get-artifact      Get artifact metadata by UUID
    download          Download an artifact file with checksum verification
    inspect           Full flow: TEI -> discovery -> releases -> artifacts
    conformance       Run TEA spec conformance checks against a server

All subcommands accept --base-url/--domain for server selection,
--token/--auth for authentication, and --json for machine-readable output.
"""

from libtea.cli import app as tea_group

__all__ = ["tea_group"]
```

Modify `sbomify_action/cli/main.py` — add near the bottom where `yocto` and `init` commands are registered (after line ~2291):

```python
from .tea import tea_group

cli.add_command(tea_group, "tea")
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_tea_cli.py -v`
Expected: All 6 tests PASS

**Step 5: Run linting**

Run: `uv run ruff check sbomify_action/cli/tea.py tests/test_tea_cli.py && uv run ruff format --check sbomify_action/cli/tea.py tests/test_tea_cli.py`
Expected: No errors

**Step 6: Commit**

```bash
git add sbomify_action/cli/tea.py tests/test_tea_cli.py sbomify_action/cli/main.py
git commit -m "feat: add 'sbomify-action tea' subcommand group

Re-exports libtea's CLI as a subcommand, providing TEA server
discovery, search, inspect, download, and conformance testing
directly from sbomify-action."
```

---

### Task 2: Add custom `fetch` convenience command

The `fetch` command combines TEI discovery + collection lookup + BOM artifact selection + download into one step. This doesn't exist in libtea's CLI (which has separate `inspect` and `download` commands).

**Files:**
- Modify: `sbomify_action/cli/tea.py` (add fetch command to the group)
- Modify: `tests/test_tea_cli.py` (add fetch tests)

**Step 1: Write the failing test**

Add to `tests/test_tea_cli.py`:

```python
from unittest.mock import MagicMock, patch
from pathlib import Path


class TestTeaFetch(unittest.TestCase):
    """Test the custom fetch convenience command."""

    def setUp(self):
        self.runner = CliRunner()

    def test_fetch_help(self):
        """tea fetch --help should show fetch subcommand help."""
        result = self.runner.invoke(cli, ["tea", "fetch", "--help"])
        assert result.exit_code == 0
        assert "fetch" in result.output.lower() or "download" in result.output.lower()

    @patch("sbomify_action.cli.tea._build_client")
    def test_fetch_by_tei(self, mock_build):
        """tea fetch --tei should discover, find BOM, and download."""
        from libtea.models import (
            ArtifactFormat,
            ArtifactType,
            Artifact,
            Collection,
            CollectionBelongsTo,
            DiscoveryInfo,
            TeaServerInfo,
        )

        mock_client = MagicMock()
        mock_build.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_build.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.discover.return_value = [
            DiscoveryInfo(
                product_release_uuid="pr-uuid-1",
                servers=[TeaServerInfo(root_url="https://tea.example.com/v1", versions=["0.3.0-beta.2"], priority=1.0)],
            )
        ]
        mock_client.get_product_release_collection_latest.return_value = Collection(
            uuid="col-uuid",
            version=1,
            date=None,
            belongs_to=CollectionBelongsTo.PRODUCT_RELEASE,
            update_reason=None,
            artifacts=[
                Artifact(
                    uuid="art-uuid",
                    name="sbom",
                    type=ArtifactType.BOM,
                    distribution_types=None,
                    formats=[
                        ArtifactFormat(
                            media_type="application/vnd.cyclonedx+json",
                            description=None,
                            url="https://cdn.example.com/sbom.json",
                            signature_url=None,
                            checksums=None,
                        )
                    ],
                )
            ],
        )
        mock_client.download_artifact.return_value = Path("/tmp/sbom.json")

        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                cli,
                ["tea", "fetch", "--base-url", "https://tea.example.com/v1", "--tei", "urn:tei:purl:example.com:pkg:pypi/lib@1.0", "-o", "sbom.json"],
            )
            assert result.exit_code == 0, f"Output: {result.output}"

    def test_fetch_requires_tei_or_uuid(self):
        """tea fetch should fail if neither --tei nor --product-release-uuid is given."""
        result = self.runner.invoke(
            cli,
            ["tea", "fetch", "--base-url", "https://tea.example.com/v1", "-o", "sbom.json"],
        )
        assert result.exit_code != 0
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_tea_cli.py::TestTeaFetch -v`
Expected: FAIL — `fetch` command doesn't exist yet

**Step 3: Write minimal implementation**

Add to `sbomify_action/cli/tea.py`:

```python
import sys
from pathlib import Path

import click

from libtea.cli import _build_client, _error, app as tea_group
from libtea.exceptions import TeaError
from libtea.models import ArtifactType

__all__ = ["tea_group"]

# Media type preference order for BOM artifacts
_BOM_MEDIA_TYPES = [
    "application/vnd.cyclonedx+json",
    "application/spdx+json",
    "application/json",
]


def _select_best_format(formats, preferred_media_types=_BOM_MEDIA_TYPES):
    """Select the best artifact format by media type preference."""
    for preferred in preferred_media_types:
        for fmt in formats:
            if fmt.media_type and preferred in fmt.media_type:
                return fmt
    # Fallback: first format with a URL
    for fmt in formats:
        if fmt.url:
            return fmt
    return None


@tea_group.command()
@click.option("--tei", default=None, help="TEI URN to discover and fetch SBOM for")
@click.option("--product-release-uuid", default=None, help="Product release UUID to fetch from")
@click.option("--component-release-uuid", default=None, help="Component release UUID to fetch from")
@click.option(
    "--artifact-type",
    type=click.Choice([t.value for t in ArtifactType], case_sensitive=False),
    default=ArtifactType.BOM.value,
    help="Artifact type to download (default: BOM)",
)
@click.option("-o", "--output", "output_path", required=True, type=click.Path(), help="Output file path")
@click.option("--base-url", envvar="TEA_BASE_URL", default=None, help="TEA server base URL")
@click.option("--domain", default=None, help="Domain for .well-known/tea discovery")
@click.option("--token", envvar="TEA_TOKEN", default=None, help="Bearer token")
@click.option("--auth", envvar="TEA_AUTH", default=None, help="Basic auth as USER:PASSWORD")
@click.option("--timeout", type=click.FloatRange(min=0.1), default=30.0, help="Request timeout")
@click.option("--use-http", is_flag=True, help="Use HTTP instead of HTTPS")
@click.option("--port", type=int, default=None, help="Port for well-known resolution")
@click.option("--allow-private-ips", is_flag=True, help="Allow private IPs")
def fetch(
    tei,
    product_release_uuid,
    component_release_uuid,
    artifact_type,
    output_path,
    base_url,
    domain,
    token,
    auth,
    timeout,
    use_http,
    port,
    allow_private_ips,
):
    """Fetch an SBOM from a TEA server in one step.

    Combines discovery, collection lookup, artifact selection, and download.
    Provide --tei for automatic discovery or --product-release-uuid /
    --component-release-uuid for direct lookup.

    \b
    Examples:
      sbomify-action tea fetch --tei "urn:tei:purl:example.com:pkg:pypi/requests@2.31" -o sbom.json
      sbomify-action tea fetch --product-release-uuid abc-123 -o sbom.json --base-url https://tea.example.com/v1
    """
    if not tei and not product_release_uuid and not component_release_uuid:
        _error("Must specify --tei, --product-release-uuid, or --component-release-uuid")

    target_type = ArtifactType(artifact_type)
    dest = Path(output_path)

    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
        ) as client:
            # Step 1: Resolve product release UUID
            pr_uuid = product_release_uuid
            cr_uuid = component_release_uuid

            if tei and not pr_uuid and not cr_uuid:
                discoveries = client.discover(tei)
                if not discoveries:
                    _error(f"No product releases found for TEI: {tei}")
                pr_uuid = discoveries[0].product_release_uuid
                print(f"Discovered product release: {pr_uuid}", file=sys.stderr)

            # Step 2: Get latest collection
            if pr_uuid:
                collection = client.get_product_release_collection_latest(pr_uuid)
            elif cr_uuid:
                collection = client.get_component_release_collection_latest(cr_uuid)
            else:
                _error("Internal error: no UUID resolved")

            # Step 3: Find matching artifact
            matching = [a for a in collection.artifacts if a.type == target_type]
            if not matching:
                available = {a.type.value for a in collection.artifacts if a.type}
                _error(f"No {target_type.value} artifact found. Available types: {', '.join(sorted(available)) or 'none'}")

            artifact = matching[0]

            # Step 4: Select best format
            if not artifact.formats:
                _error(f"Artifact '{artifact.name}' has no downloadable formats")

            fmt = _select_best_format(artifact.formats)
            if not fmt or not fmt.url:
                _error(f"No downloadable format found for artifact '{artifact.name}'")

            print(f"Downloading {artifact.name} ({fmt.media_type}) ...", file=sys.stderr)

            # Step 5: Download with checksum verification
            result_path = client.download_artifact(
                fmt.url,
                dest,
                verify_checksums=fmt.checksums,
            )
            print(f"Saved to {result_path}", file=sys.stderr)

    except TeaError as exc:
        _error(str(exc))
    except OSError as exc:
        _error(f"I/O error: {exc}")
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_tea_cli.py -v`
Expected: All tests PASS (both TestTeaGroup and TestTeaFetch)

**Step 5: Run linting**

Run: `uv run ruff check sbomify_action/cli/tea.py tests/test_tea_cli.py && uv run ruff format --check sbomify_action/cli/tea.py tests/test_tea_cli.py`
Expected: No errors

**Step 6: Commit**

```bash
git add sbomify_action/cli/tea.py tests/test_tea_cli.py
git commit -m "feat: add 'tea fetch' convenience command

Single-step SBOM fetching: TEI discovery -> collection lookup ->
BOM artifact selection -> download with checksum verification."
```

---

### Task 3: Run full test suite and verify no regressions

**Step 1: Run all tests**

Run: `uv run pytest -v`
Expected: All existing tests PASS, all new TEA tests PASS, coverage >= 80%

**Step 2: Run full lint**

Run: `uv run ruff check sbomify_action tests && uv run ruff format --check sbomify_action tests`
Expected: No errors

**Step 3: Verify CLI end-to-end**

Run: `uv run sbomify-action tea --help`
Expected: Shows TEA group help with all subcommands listed

Run: `uv run sbomify-action tea fetch --help`
Expected: Shows fetch command help with --tei, --product-release-uuid, -o options

Run: `uv run sbomify-action tea conformance --help`
Expected: Shows conformance command help

**Step 4: Commit if any fixups needed**

```bash
git add -u
git commit -m "fix: address lint/test issues from TEA CLI integration"
```
