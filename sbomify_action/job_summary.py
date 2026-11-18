"""What a finished run reports back to the CI system.

A green run used to look the same whether it produced 400 enriched components
or none. This writes a short Markdown summary and a few step outputs through
the active platform, which on GitHub Actions means the run page and
``steps.<id>.outputs``; everywhere else both are no-ops.

The summary holds aggregates only -- counts, one link, a five-row table -- so
it stays a few hundred bytes whatever the SBOM's size, far under the 1 MiB
GitHub allows a step.
"""

import json
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any

from . import format_display_name
from ._runtime import get_platform
from ._upload.destinations.sbomify import component_url
from .console import get_audit_trail
from .logging_config import logger, warning_annotations
from .validation import detect_sbom_format_and_version

if TYPE_CHECKING:
    from .cli.main import Config
    from .drift import Drift


def _spdx_value(value: Any) -> bool:
    """True for an SPDX field that states something, not NOASSERTION or NONE."""
    return bool(value) and value not in ("NOASSERTION", "NONE")


# The component fields NTIA, CISA and BSI TR-03183 all ask for, located as the
# schema crosswalk on sbomify.com maps them.
_CYCLONEDX: dict[str, Callable[[dict[str, Any]], bool]] = {
    "Supplier": lambda c: bool((c.get("supplier") or {}).get("name")),
    "License": lambda c: bool(c.get("licenses")),
    "Version": lambda c: bool(c.get("version")),
    "PURL": lambda c: bool(c.get("purl")),
    "Hashes": lambda c: bool(c.get("hashes")),
}
_SPDX: dict[str, Callable[[dict[str, Any]], bool]] = {
    "Supplier": lambda p: _spdx_value(p.get("supplier")),
    "License": lambda p: _spdx_value(p.get("licenseDeclared")) or _spdx_value(p.get("licenseConcluded")),
    "Version": lambda p: bool(p.get("versionInfo")),
    "PURL": lambda p: any(r.get("referenceType") == "purl" for r in p.get("externalRefs") or []),
    "Hashes": lambda p: bool(p.get("checksums")),
}


def _walk(components: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Every CycloneDX component, nested ones included."""
    for component in components:
        yield component
        yield from _walk(component.get("components") or [])


def _read(path: str) -> dict[str, Any]:
    """The document at ``path``, or an empty dict if it is not a JSON object."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _coverage(doc: dict[str, Any]) -> dict[str, int] | None:
    if doc.get("bomFormat") == "CycloneDX":
        checks, components = _CYCLONEDX, list(_walk(doc.get("components") or []))
    elif "spdxVersion" in doc:
        checks, components = _SPDX, doc.get("packages") or []
    else:
        # ponytail: no counts for SPDX 3 or VEX; add SPDX 3 once the action generates it
        return None
    return {"components": len(components), **{name: sum(map(check, components)) for name, check in checks.items()}}


def field_coverage(path: str) -> dict[str, int] | None:
    """How many components carry each key field, under ``components`` the total.

    None for anything but a CycloneDX or SPDX 2 document, and for anything
    malformed: this only feeds the summary, so it must never fail a run.
    """
    try:
        return _coverage(_read(path))
    except Exception:
        return None


def _cell(counts: dict[str, int], name: str) -> str:
    total = counts["components"]
    return f"{counts[name]} of {total} ({counts[name] / total:.0%})" if total else "-"


def sbom_outputs(output_file: str, sbom_format: str, components: int | None) -> dict[str, str]:
    """The step outputs naming the SBOM: set when the collapse gate fails the run too."""
    outputs = {"sbom-file": output_file, "sbom-format": sbom_format}
    if components is not None:
        outputs["component-count"] = str(components)
    return outputs


def publish_run_summary(
    config: "Config",
    sbom_format: str,
    before: dict[str, int] | None,
    sbom_id: str | None,
    drift: "Drift | None" = None,
) -> None:
    """Write the job summary and step outputs for a finished SBOM run.

    Never raises: the SBOM is written and uploaded by now, and a summary that
    could not be written is not worth failing the build over.
    """
    try:
        formatter = get_platform().log_formatter()
        doc = _read(config.output_file)
        after = _coverage(doc)
        spec_version = detect_sbom_format_and_version(doc)[1]
        url = component_url(config.api_base_url, config.component_id) if sbom_id and config.component_id else None

        outputs = sbom_outputs(config.output_file, sbom_format, after["components"] if after else None)
        if sbom_id:
            outputs["sbom-id"] = sbom_id
        if url:
            outputs["component-url"] = url
        for name, value in outputs.items():
            formatter.set_output(name, value)

        lines = ["### sbomify", ""]
        lines.append(f"- **Format:** {format_display_name(sbom_format)} {spec_version or ''}".rstrip())
        lines.append(f"- **File:** `{config.output_file}`")
        if after:
            enriched, fields = get_audit_trail().enrichment_counts()
            off = "" if config.enrich else " (registry enrichment is off: set `ENRICH=true`)"
            lines.append(f"- **Components:** {after['components']}")
            lines.append(f"- **Enriched:** {enriched} of {after['components']} components, {fields} fields added{off}")
        if config.upload:
            destinations = [
                f"sbomify ([view component]({url}))" if d == "sbomify" and url else d
                for d in config.upload_destinations or []
            ]
            lines.append(f"- **Uploaded to:** {', '.join(destinations)}")
        else:
            lines.append("- **Uploaded to:** nowhere (`UPLOAD=false`)")
        count, shown = warning_annotations.count, warning_annotations.annotated
        if count > shown:
            lines.append(f"- **Warnings:** {count} ({shown} as annotations, +{count - shown} more in the log)")
        else:
            lines.append(f"- **Warnings:** {count}")

        if after and after["components"]:
            columns = ["Before enrichment", "After"] if before else ["Components"]
            lines += ["", f"| Field | {' | '.join(columns)} |", "|---|" + "---:|" * len(columns)]
            for name in _CYCLONEDX:
                cells = [_cell(before, name), _cell(after, name)] if before else [_cell(after, name)]
                lines.append(f"| {name} | {' | '.join(cells)} |")
        if drift:
            lines += ["", drift.markdown()]

        formatter.job_summary("\n".join(lines) + "\n")
    except Exception as e:
        logger.warning(f"Could not write the run summary: {e}")
