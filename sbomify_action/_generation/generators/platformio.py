"""Read the libraries PlatformIO installed for a project.

Priority: 10 (native, authoritative)

No other generator understands PlatformIO: cdxgen, syft and trivy have no
cataloger for it, so an Arduino or ESP32 project had no way to produce an SBOM
short of hand-munging each library's `library.json` into CycloneDX.

The input is `platformio.ini`, and what is read is the `.piopm` metadata
PlatformIO's package manager wrote for each library under `.pio/libdeps/` --
see `sbomify_action._platformio`. That directory exists only after
`pio pkg install` (or a build), so in CI this runs after the build step.

SPDX is written directly rather than converted from CycloneDX: syft's
conversion credits itself as the creator, adds an empty package for the
document root and renames registry libraries to `owner/Name`.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sbomify_action import __version__
from sbomify_action._platformio import (
    PLATFORMIO_INI,
    FrameworkPackage,
    InstalledLibrary,
    Manifest,
    declared_lib_deps,
    libdeps_dir,
    resolve,
)
from sbomify_action.logging_config import logger
from sbomify_action.serialization import _canonical_spdx_license_id, _is_compound_expression

from ..protocol import (
    CYCLONEDX_VERSIONS,
    SPDX_VERSIONS,
    FormatVersion,
    GenerationInput,
)
from ..result import GenerationResult

CYCLONEDX_DEFAULT_VERSION = "1.6"
SPDX_DEFAULT_VERSION = "2.3"

#: The ids SPDX deprecated in favour of an explicit -only.
_DEPRECATED_GNU = re.compile(r"^((?:A|L)?GPL-\d\.\d)(\+)?$")


def _licence(value: str | None) -> tuple[str, str] | None:
    """("id" | "expression" | "name", value) for a manifest's licence string."""
    if not value:
        return None
    value = value.strip()
    if match := _DEPRECATED_GNU.match(value):
        value = f"{match.group(1)}-{'or-later' if match.group(2) else 'only'}"
    if canonical := _canonical_spdx_license_id(value):
        if match := _DEPRECATED_GNU.match(canonical):
            canonical = f"{match.group(1)}-only"
        return "id", canonical
    if _is_compound_expression(value):
        return "expression", value
    return "name", value


def _describe(component: dict[str, Any], manifest: Manifest, supplier: str | None) -> None:
    """The author-declared fields: description, licence, authors, links."""
    if manifest.description:
        component["description"] = manifest.description
    if supplier:
        component["supplier"] = {"name": supplier}
    if manifest.authors:
        component["authors"] = [
            {"name": name, **({"email": email} if email else {})} for name, email in manifest.authors
        ]
    if licence := _licence(manifest.license):
        kind, value = licence
        component["licenses"] = [{"expression": value}] if kind == "expression" else [{"license": {kind: value}}]
    references = component.setdefault("externalReferences", [])
    for kind, url in (("vcs", manifest.repository), ("website", manifest.homepage)):
        if url and all(reference["url"] != url for reference in references):
            references.append({"type": kind, "url": url})
    if not references:
        del component["externalReferences"]


def _component(library: InstalledLibrary) -> dict[str, Any]:
    purl = library.purl
    component: dict[str, Any] = {
        "type": "library",
        "name": library.name,
        "purl": purl,
        "bom-ref": purl,
    }
    if version := library.stable_version:
        component["version"] = version
    if library.owner:
        component["group"] = library.owner
    if library.uri:
        reference_type = "vcs" if library.from_git else "distribution"
        component["externalReferences"] = [{"type": reference_type, "url": library.uri}]
    _describe(component, library.manifest, library.supplier)
    return component


def _framework_component(package: FrameworkPackage) -> dict[str, Any]:
    purl = package.purl
    component: dict[str, Any] = {
        "type": package.kind,
        "name": package.name,
        "version": package.version,
        "purl": purl,
        "bom-ref": purl,
    }
    if package.owner:
        component["group"] = package.owner
    if package.cpe:
        component["cpe"] = package.cpe
    if package.uri:
        component["externalReferences"] = [{"type": "distribution", "url": package.uri}]
    _describe(component, package.manifest, package.owner)
    return component


def _spdx_id(ref: str, used: set[str]) -> str:
    base = "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.\-]+", "-", ref).strip("-")[:120]
    candidate, counter = base, 1
    while candidate in used:
        counter += 1
        candidate = f"{base}-{counter}"
    used.add(candidate)
    return candidate


_SPDX_PURPOSE = {"library": "LIBRARY", "framework": "FRAMEWORK", "firmware": "FIRMWARE", "platform": "OTHER"}


def _spdx_package(component: dict[str, Any], spdx_id: str, spec_version: str) -> dict[str, Any]:
    package: dict[str, Any] = {
        "SPDXID": spdx_id,
        "name": component["name"],
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    if "version" in component:
        package["versionInfo"] = component["version"]
    if spec_version != "2.2":
        package["primaryPackagePurpose"] = _SPDX_PURPOSE.get(component["type"], "OTHER")
    references = component.get("externalReferences") or []
    for reference in references:
        if reference["type"] in ("distribution", "vcs"):
            location = reference["url"]
            if reference["type"] == "vcs" and not location.startswith("git+"):
                location = f"git+{location}"
            package["downloadLocation"] = location
            break
    homepage = next((r["url"] for r in references if r["type"] == "website"), None)
    if homepage:
        package["homepage"] = homepage
    if "description" in component:
        package["description"] = component["description"]
    if supplier := component.get("supplier", {}).get("name"):
        package["supplier"] = f"Organization: {supplier}"
    if authors := component.get("authors"):
        author = authors[0]
        package["originator"] = f"Person: {author['name']}" + (f" ({author['email']})" if "email" in author else "")
    for licence in component.get("licenses", []):
        declared = licence.get("expression") or licence.get("license", {}).get("id")
        if declared:
            package["licenseDeclared"] = declared
        elif name := licence.get("license", {}).get("name"):
            package["licenseDeclared"] = "LicenseRef-" + re.sub(r"[^A-Za-z0-9.\-]+", "-", name).strip("-")
            package["licenseComments"] = f"Declared by the author as: {name}"
    external = []
    if "purl" in component:
        external.append(
            {"referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": component["purl"]}
        )
    if "cpe" in component:
        external.append(
            {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": component["cpe"]}
        )
    if external:
        package["externalRefs"] = external
    return package


def _to_spdx(document: dict[str, Any], spec_version: str) -> dict[str, Any]:
    """The same graph as SPDX: one package per component, DEPENDS_ON edges."""
    root = document["metadata"]["component"]
    used: set[str] = set()
    ids = {root["bom-ref"]: _spdx_id(f"root-{root['name']}", used)}
    for component in document["components"]:
        ids[component["bom-ref"]] = _spdx_id(component["bom-ref"], used)
    packages = [_spdx_package(root, ids[root["bom-ref"]], spec_version)]
    packages += [_spdx_package(c, ids[c["bom-ref"]], spec_version) for c in document["components"]]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": ids[root["bom-ref"]],
        }
    ]
    for entry in document["dependencies"]:
        for target in entry.get("dependsOn", []):
            relationships.append(
                {
                    "spdxElementId": ids[entry["ref"]],
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": ids[target],
                }
            )
    extracted = {}
    for package in packages:
        if package["licenseDeclared"].startswith("LicenseRef-"):
            extracted[package["licenseDeclared"]] = {
                "licenseId": package["licenseDeclared"],
                "extractedText": package.pop("licenseComments").removeprefix("Declared by the author as: "),
            }
    spdx: dict[str, Any] = {
        "spdxVersion": f"SPDX-{spec_version}",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": root["name"],
        "documentNamespace": f"https://sbomify.com/spdx/platformio/{root['name']}-{uuid.uuid4()}",
        "creationInfo": {
            "created": document["metadata"]["timestamp"],
            "creators": [f"Tool: sbomify-action-{__version__}"],
        },
        "packages": packages,
        "relationships": relationships,
    }
    if extracted:
        spdx["hasExtractedLicensingInfos"] = list(extracted.values())
    return spdx


class PlatformIOGenerator:
    """Native reader for a PlatformIO project's installed libraries."""

    @property
    def name(self) -> str:
        return "platformio"

    @property
    def command(self) -> str:
        return ""  # nothing to run: PlatformIO already recorded the answer

    @property
    def priority(self) -> int:
        return 10

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(format="cyclonedx", versions=CYCLONEDX_VERSIONS, default_version=CYCLONEDX_DEFAULT_VERSION),
            FormatVersion(format="spdx", versions=SPDX_VERSIONS, default_version=SPDX_DEFAULT_VERSION),
        ]

    def supports(self, input: GenerationInput) -> bool:
        if not input.is_lock_file or input.lock_file_name != PLATFORMIO_INI:
            return False
        if input.output_format not in ("cyclonedx", "spdx"):
            return False
        allowed = SPDX_VERSIONS if input.output_format == "spdx" else CYCLONEDX_VERSIONS
        return not (input.spec_version and input.spec_version not in allowed)

    def generate(self, input: GenerationInput) -> GenerationResult:
        assert input.lock_file is not None  # guaranteed by supports()
        source = Path(input.lock_file)
        resolution = resolve(source)
        if resolution.uninstalled or not (resolution.libraries or resolution.frameworks):
            if libdeps_dir(source) is None:
                message = (
                    f"{source.name} sets libdeps_dir or workspace_dir to a value that cannot be "
                    "resolved here; set PLATFORMIO_LIBDEPS_DIR to where the libraries were installed."
                )
            elif resolution.uninstalled:
                message = (
                    f"{source.name} declares lib_deps for env:{', env:'.join(resolution.uninstalled)} but none "
                    "are installed. Run `pio pkg install` (or build) before generating the SBOM."
                )
            elif not resolution.environments and declared_lib_deps(source):
                message = (
                    f"{source.name} declares lib_deps but none are installed. "
                    "Run `pio pkg install` (or build) before generating the SBOM."
                )
            elif not resolution.environments:
                message = (
                    f"{source.name} declares no lib_deps, and no environment has been installed or built "
                    "(and no default_envs names one). Run `pio pkg install -e <env>` first."
                )
            else:
                message = (
                    f"{source.name}: env:{', env:'.join(resolution.environments)} uses no libraries, and its "
                    "platform is not installed. Run `pio pkg install` (or build) before generating the SBOM."
                )
            return GenerationResult.failure_result(
                error_message=message,
                sbom_format=input.output_format,
                spec_version=input.spec_version or "",
                generator_name=self.name,
            )

        version = input.spec_version or (
            SPDX_DEFAULT_VERSION if input.output_format == "spdx" else CYCLONEDX_DEFAULT_VERSION
        )
        cyclonedx_version = CYCLONEDX_DEFAULT_VERSION if input.output_format == "spdx" else version
        project = source.resolve().parent.name or "platformio-project"
        root_ref = f"root-{project}"
        components = [_component(library) for library in resolution.libraries]
        components += [_framework_component(package) for package in resolution.frameworks]
        tools: Any = {
            "components": [
                {"type": "application", "group": "sbomify", "name": "sbomify action", "version": __version__}
            ]
        }
        if cyclonedx_version == "1.4":
            tools = [{"vendor": "sbomify", "name": "sbomify action", "version": __version__}]
        document: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": cyclonedx_version,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tools": tools,
                "component": {
                    "type": "firmware",
                    "name": project,
                    "bom-ref": root_ref,
                },
            },
            "components": components,
            # Direct dependencies are what lib_deps names plus the platform
            # and frameworks; the edges below them come from each library's
            # own manifest, resolved against what was installed for it.
            "dependencies": [{"ref": root_ref, "dependsOn": resolution.direct}]
            + [
                {"ref": component["bom-ref"], "dependsOn": resolution.edges.get(component["bom-ref"], [])}
                for component in components
            ],
        }
        output = Path(input.output_file)
        output.parent.mkdir(parents=True, exist_ok=True)
        logger.info(
            f"Read {len(resolution.libraries)} PlatformIO libraries and {len(resolution.frameworks)} platform and "
            f"framework packages for env:{', env:'.join(resolution.environments)} in {source.name}"
        )
        if input.output_format == "spdx":
            output.write_text(json.dumps(_to_spdx(document, version), indent=2), encoding="utf-8")
        else:
            output.write_text(json.dumps(document, indent=2), encoding="utf-8")

        return GenerationResult.success_result(
            output_file=str(output),
            sbom_format=input.output_format,
            spec_version=version,
            generator_name=self.name,
        )
