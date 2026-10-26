#!/usr/bin/env python3
"""Record the sbom-tools release in this action's sbomify product release.

The action's own SBOMs describe what is in the image. They do not describe
the bundles the image downloads at run time, which come from sbomify/sbom-tools
and are pinned in tools.toml. Those bundles are SBOM'd by sbom-tools' own
workflow, each under its own component, at the sbom-tools release as the
version. This script ties the two together, in two steps that bracket the
SBOM upload in .github/workflows/sboms.yml:

``create``
    Creates the product release before the action's SBOM jobs get-or-create
    it, so that it is created with a description that names the toolchain,
    rather than the generic one the action would give it. An existing release
    is left as it is.

``link``
    Tags the sbom-tools bundle SBOMs for that toolchain release into the same
    product release, so the release lists everything a user of this version
    runs, not only what the image contains.

Authenticates by OIDC trusted publishing against one of this repository's own
components, so it needs ``permissions: id-token: write`` and nothing else.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbomify_action.exceptions import SbomifyError  # noqa: E402
from sbomify_action.oidc import obtain_sbomify_token_via_oidc  # noqa: E402
from sbomify_action.release_version import is_prerelease  # noqa: E402
from sbomify_action.sbomify_api import SbomifyApiClient  # noqa: E402
from sbomify_action.tool_manifest import pinned_tools_release  # noqa: E402

TOOLS_REPO = "sbomify/sbom-tools"

#: The bundle SBOMs sbom-tools uploads are syft's CycloneDX output.
BUNDLE_SBOM_FORMAT = "cyclonedx"


def describe(version: str, tools_release: str) -> str:
    return f"sbomify-action {version}. Runtime toolchain: {TOOLS_REPO} {tools_release}."


def create(client: SbomifyApiClient, product_id: str, version: str, tools_release: str) -> str:
    """Get-or-create the release; only a release created here gets the description."""
    if release_id := client.get_release_id(product_id, version):
        print(f"Release {version} already exists ({release_id}); leaving its description alone")
        return release_id
    release_id = client.create_release(
        product_id,
        version,
        description=describe(version, tools_release),
        is_prerelease=True if is_prerelease(version) else None,
    )
    print(f"Created release {version} ({release_id}) with toolchain {tools_release}")
    return release_id


def link(
    client: SbomifyApiClient,
    product_id: str,
    version: str,
    tools_version: str,
    components: dict[str, str],
    *,
    strict: bool,
) -> int:
    """Tag each bundle's SBOM at ``tools_version`` into the release.

    Returns the number of bundles whose SBOM could not be found. With
    ``strict`` that is an error: a release that silently leaves out its
    toolchain is the gap this exists to close.
    """
    release_id = client.get_release_id(product_id, version)
    if not release_id:
        raise SbomifyError(f"Release {version} does not exist on product {product_id}")

    missing = 0
    for bundle, component_id in sorted(components.items()):
        sbom_id = client.find_component_sbom(component_id, tools_version, BUNDLE_SBOM_FORMAT)
        if not sbom_id:
            missing += 1
            level = "error" if strict else "warning"
            print(
                f"::{level}::No {bundle} bundle SBOM at {tools_version} on component {component_id}. "
                f"Has {TOOLS_REPO}'s sboms workflow run for it?"
            )
            continue
        client.tag_sbom_with_release(sbom_id, release_id)
        print(f"Tagged {bundle} bundle SBOM {sbom_id} ({tools_version}) into release {version}")
    return missing


def _components(pairs: list[str]) -> dict[str, str]:
    components: dict[str, str] = {}
    for pair in pairs:
        bundle, sep, component_id = pair.partition("=")
        if not sep or not bundle or not component_id:
            raise argparse.ArgumentTypeError(f"expected BUNDLE=COMPONENT_ID, got {pair!r}")
        components[bundle] = component_id
    return components


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["create", "link"])
    parser.add_argument("--api-base-url", required=True)
    parser.add_argument("--audience", default=None, help="OIDC audience (default: derived from the API URL)")
    parser.add_argument("--auth-component", required=True, help="a component of this repo to authenticate as")
    parser.add_argument("--product-id", required=True)
    parser.add_argument("--version", required=True, help="the product release version")
    parser.add_argument(
        "--tools-release",
        default=None,
        help="sbom-tools release the version fetches from (default: the pin in tools.toml)",
    )
    parser.add_argument(
        "--tools-version",
        default=None,
        help="component version the bundle SBOMs were uploaded under (default: --tools-release)",
    )
    parser.add_argument("--component", action="append", default=[], metavar="BUNDLE=COMPONENT_ID")
    parser.add_argument("--strict", action="store_true", help="fail when a bundle SBOM is missing")
    args = parser.parse_args(argv)

    tools_release = args.tools_release or pinned_tools_release()
    try:
        token = obtain_sbomify_token_via_oidc(args.auth_component, args.api_base_url, args.audience)
        client = SbomifyApiClient(args.api_base_url, token)
        if args.command == "create":
            create(client, args.product_id, args.version, tools_release)
            return 0
        components = _components(args.component)
        if not components:
            parser.error("link needs at least one --component")
        missing = link(
            client,
            args.product_id,
            args.version,
            args.tools_version or tools_release,
            components,
            strict=args.strict,
        )
    except SbomifyError as e:
        print(f"::error::{e}")
        return 1
    return 1 if missing and args.strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
