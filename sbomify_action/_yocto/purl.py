"""Yocto PURL generation and injection for SPDX 2.2 and SPDX 3 SBOMs."""

import json
from typing import Any

from packageurl import PackageURL

from sbomify_action.logging_config import logger

#: PURL type for a package that came out of a Yocto build.
#:
#: There is no Yocto package registry, and this type is not in the PURL spec:
#: we mint it here so a recipe has a stable identifier at all. Anything that
#: would take it to a registry has to know that, or it spends a network round
#: trip per recipe on a lookup that cannot succeed.
YOCTO_PURL_TYPE = "yocto"
YOCTO_PURL_PREFIX = f"pkg:{YOCTO_PURL_TYPE}/"


def generate_yocto_purl(name: str, version: str | None = None) -> str:
    """Build a ``pkg:yocto/<name>@<version>`` PURL string.

    Args:
        name: Package name (BPN).
        version: Package version (PV). Empty string treated as None.

    Returns:
        PURL string, e.g. ``pkg:yocto/busybox@1.36.1``.
    """
    return str(
        PackageURL(
            type=YOCTO_PURL_TYPE,
            name=name,
            version=version if version else None,
        )
    )


def _has_yocto_purl_spdx22(package_data: dict[str, Any]) -> bool:
    """Check if an SPDX 2.2 package already has a ``pkg:yocto/`` external ref."""
    for ref in package_data.get("externalRefs", []):
        if (
            ref.get("referenceType") == "purl"
            and isinstance(ref.get("referenceLocator"), str)
            and ref["referenceLocator"].startswith(YOCTO_PURL_PREFIX)
        ):
            return True
    return False


def inject_yocto_purls_spdx22(spdx_file: str) -> int:
    """Inject yocto PURLs into SPDX 2.2 packages missing one.

    Reads *spdx_file* as JSON, iterates ``packages[]``, and appends a
    ``pkg:yocto/<name>@<version>`` external ref for any package that does
    not already have a yocto PURL.  Writes the file back in-place.

    Returns:
        Number of PURLs injected.
    """
    with open(spdx_file, encoding="utf-8") as f:
        data = json.load(f)

    injected = 0
    for pkg in data.get("packages", []):
        if _has_yocto_purl_spdx22(pkg):
            continue

        name = pkg.get("name")
        if not name:
            continue

        version = pkg.get("versionInfo") or None
        purl = generate_yocto_purl(name, version)

        refs = pkg.setdefault("externalRefs", [])
        refs.append(
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        )
        injected += 1

    if injected:
        with open(spdx_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logger.debug(f"Injected {injected} yocto PURL(s) into {spdx_file}")

    return injected


def inject_yocto_purls_spdx3(spdx3_file: str) -> int:
    """Inject yocto PURLs into SPDX 3 Package elements missing one.

    Reads *spdx3_file* as JSON-LD, iterates ``@graph`` for Package /
    software_Package elements, and sets ``packageUrl`` for those without
    an existing value.  Writes the file back in-place.

    Returns:
        Number of PURLs injected.
    """
    with open(spdx3_file, encoding="utf-8") as f:
        data = json.load(f)

    injected = 0
    for element in data.get("@graph", []):
        if not isinstance(element, dict):
            continue

        el_type = element.get("type") or element.get("@type")
        if el_type not in ("software_Package", "Package"):
            continue

        existing = element.get("packageUrl")
        if existing:
            continue

        name = element.get("name")
        if not name:
            continue

        version = element.get("packageVersion") or None
        element["packageUrl"] = generate_yocto_purl(name, version)
        injected += 1

    if injected:
        with open(spdx3_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logger.debug(f"Injected {injected} yocto PURL(s) into {spdx3_file}")

    return injected
