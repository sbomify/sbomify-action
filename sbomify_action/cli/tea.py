"""TEA (Transparency Exchange API) CLI subcommand group.

Re-exports libtea's CLI as ``sbomify-action tea``, plus a custom ``fetch``
command that combines discovery + collection lookup + artifact download.
"""

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import click
import libtea.cli as _libtea_cli
from libtea.cli import app as tea_group
from libtea.exceptions import TeaError
from libtea.models import ArtifactFormat, ArtifactType

# Bind private helpers via the module to avoid hard-failing imports if a
# future libtea version removes them. We own libtea and these are stable,
# but this provides a clear error message if the API changes.
try:
    _build_client = _libtea_cli._build_client  # type: ignore[attr-defined]
    _error = _libtea_cli._error  # type: ignore[attr-defined]
except AttributeError as _exc:
    _compat_err = str(_exc)

    def _error(message: str) -> None:  # type: ignore[misc]
        raise SystemExit(f"Incompatible libtea version: {_compat_err}. {message}")

    def _build_client(*args: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
        _error("Required helper _build_client is missing from libtea.cli.")


__all__ = ["tea_group"]

_BOM_MEDIA_TYPES = (
    "application/vnd.cyclonedx+json",
    "application/spdx+json",
    "application/json",
)


def _select_best_format(
    formats: Sequence[ArtifactFormat],
    preferred_media_types: tuple[str, ...] = _BOM_MEDIA_TYPES,
) -> ArtifactFormat | None:
    """Select the best artifact format by media type preference."""
    for preferred in preferred_media_types:
        for fmt in formats:
            if fmt.media_type and fmt.media_type == preferred and fmt.url:
                return fmt
    for fmt in formats:
        if fmt.url:
            return fmt
    return None


@tea_group.command()  # type: ignore[untyped-decorator]
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
@click.option(
    "--token",
    envvar="TEA_TOKEN",
    default=None,
    help="Bearer token (prefer TEA_TOKEN env var to avoid shell history exposure)",
)
@click.option(
    "--auth",
    envvar="TEA_AUTH",
    default=None,
    help="Basic auth as USER:PASSWORD (prefer TEA_AUTH env var to avoid shell history exposure)",
)
@click.option("--timeout", type=click.FloatRange(min=0.1), default=30.0, help="Request timeout")
@click.option("--use-http", is_flag=True, help="Use HTTP instead of HTTPS")
@click.option("--port", type=int, default=None, help="Port for well-known resolution")
@click.option("--allow-private-ips", is_flag=True, help="Allow private IPs (WARNING: weakens SSRF protections)")
def fetch(
    tei: str | None,
    product_release_uuid: str | None,
    component_release_uuid: str | None,
    artifact_type: str,
    output_path: str,
    base_url: str | None,
    domain: str | None,
    token: str | None,
    auth: str | None,
    timeout: float,
    use_http: bool,
    port: int | None,
    allow_private_ips: bool,
) -> None:
    """Fetch an SBOM from a TEA server in one step.

    Combines discovery, collection lookup, artifact selection, and download.
    Provide --tei for automatic discovery or --product-release-uuid /
    --component-release-uuid for direct lookup.

    \b
    Examples:
      sbomify-action tea fetch --tei "urn:tei:purl:example.com:pkg:pypi/requests@2.31" -o sbom.json
      sbomify-action tea fetch --product-release-uuid abc-123 -o sbom.json --base-url https://tea.example.com/v1
    """
    identifiers = sum(1 for x in (tei, product_release_uuid, component_release_uuid) if x)
    if identifiers == 0:
        _error("Must specify --tei, --product-release-uuid, or --component-release-uuid")
    if identifiers > 1:
        _error("Only one of --tei, --product-release-uuid, or --component-release-uuid may be specified")

    if allow_private_ips:
        print("WARNING: --allow-private-ips weakens SSRF protections for artifact downloads", file=sys.stderr)

    target_type = ArtifactType(artifact_type)
    dest = Path(output_path)

    try:
        with _build_client(
            base_url, token, domain, timeout, use_http, port, auth, tei=tei, allow_private_ips=allow_private_ips
        ) as client:
            pr_uuid = product_release_uuid
            cr_uuid = component_release_uuid

            if tei and not pr_uuid and not cr_uuid:
                discoveries = client.discover(tei)
                if not discoveries:
                    _error(f"No product releases found for TEI: {tei}")
                pr_uuid = discoveries[0].product_release_uuid
                print(f"Discovered product release: {pr_uuid}", file=sys.stderr)

            collection = None
            if pr_uuid:
                collection = client.get_product_release_collection_latest(pr_uuid)
            elif cr_uuid:
                collection = client.get_component_release_collection_latest(cr_uuid)
            else:
                _error("Internal error: no UUID resolved")

            assert collection is not None  # unreachable: _error() is NoReturn
            matching = [a for a in collection.artifacts if a.type == target_type]
            if not matching:
                available = {a.type.value for a in collection.artifacts if a.type}
                _error(
                    f"No {target_type.value} artifact found. Available types: {', '.join(sorted(available)) or 'none'}"
                )

            artifact = matching[0]
            if not artifact.formats:
                _error(f"Artifact '{artifact.name}' has no downloadable formats")

            fmt = _select_best_format(artifact.formats)
            if not fmt:
                _error(f"No downloadable format found for artifact '{artifact.name}'")
                return  # unreachable: _error is NoReturn, but helps mypy narrow fmt

            print(f"Downloading {artifact.name} ({fmt.media_type or 'unknown'}) ...", file=sys.stderr)

            assert fmt.url is not None  # guaranteed by _select_best_format
            result_path = client.download_artifact(
                fmt.url, dest, verify_checksums=list(fmt.checksums) if fmt.checksums else None
            )
            print(f"Saved to {result_path}", file=sys.stderr)

    except TeaError as exc:
        _error(str(exc))
    except OSError as exc:
        _error(f"I/O error: {exc}")
