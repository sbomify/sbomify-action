"""TEA (Transparency Exchange API) CLI subcommand group.

Re-exports libtea's CLI as ``sbomify-action tea``, plus a custom ``fetch``
command that combines discovery + collection lookup + artifact download.
"""

import sys
from pathlib import Path

import click

# _build_client and _error are private helpers in libtea's CLI module.
# We own libtea and intentionally couple to these; they are stable.
# _error() is typed NoReturn and raises SystemExit(1).
from libtea.cli import _build_client, _error
from libtea.cli import app as tea_group
from libtea.exceptions import TeaError
from libtea.models import ArtifactType

__all__ = ["tea_group"]

_BOM_MEDIA_TYPES = (
    "application/vnd.cyclonedx+json",
    "application/spdx+json",
    "application/json",
)


def _select_best_format(formats, preferred_media_types=_BOM_MEDIA_TYPES):
    """Select the best artifact format by media type preference."""
    for preferred in preferred_media_types:
        for fmt in formats:
            if fmt.media_type and preferred in fmt.media_type:
                return fmt
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
            pr_uuid = product_release_uuid
            cr_uuid = component_release_uuid

            if tei and not pr_uuid and not cr_uuid:
                discoveries = client.discover(tei)
                if not discoveries:
                    _error(f"No product releases found for TEI: {tei}")
                pr_uuid = discoveries[0].product_release_uuid
                print(f"Discovered product release: {pr_uuid}", file=sys.stderr)

            if pr_uuid:
                collection = client.get_product_release_collection_latest(pr_uuid)
            elif cr_uuid:
                collection = client.get_component_release_collection_latest(cr_uuid)
            else:
                _error("Internal error: no UUID resolved")

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
            if not fmt or not fmt.url:
                _error(f"No downloadable format found for artifact '{artifact.name}'")

            print(f"Downloading {artifact.name} ({fmt.media_type}) ...", file=sys.stderr)

            result_path = client.download_artifact(fmt.url, dest, verify_checksums=fmt.checksums)
            print(f"Saved to {result_path}", file=sys.stderr)

    except TeaError as exc:
        _error(str(exc))
    except OSError as exc:
        _error(f"I/O error: {exc}")
