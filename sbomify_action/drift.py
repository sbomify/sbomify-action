"""What changed in the SBOM since the previous release.

A run that produced an empty SBOM, where the same input had produced 246
components the time before (#384), went green like any other. Comparing each
run against the previous SBOM gives the job summary something worth reading on
every release, and makes a collapse like that visible.

The previous SBOM is PREVIOUS_SBOM when set, otherwise -- when the run uploads
to sbomify -- the newest SBOM of the same format already on the component.
Neither is required: with no previous SBOM there is simply no section, and a
previous SBOM that cannot be had costs a warning, never the run.
"""

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from packageurl import PackageURL

from . import format_display_name
from ._runtime import get_platform
from .exceptions import ForbiddenError
from .job_summary import _read, _spdx_value, _walk, sbom_outputs
from .logging_config import logger
from .sbomify_api import SbomifyApiClient

if TYPE_CHECKING:
    from .cli.main import Config

#: Entries listed per category; the counts above them cover the rest.
LIST_CAP = 25

#: The collapse gate needs this many components in the previous SBOM: small counts move by legitimate amounts.
COLLAPSE_FLOOR = 10

_WHY = (
    "That usually means generation broke, not that the dependencies went away, and an SBOM "
    "missing them reads as dependencies removed: a false statement to anyone relying on it "
    "for the NTIA minimum elements or EU CRA compliance."
)

Previous = tuple[dict[str, Any], str]
"""A previous SBOM and, for the summary, where it came from."""


@dataclass
class _Package:
    """Every copy of one package in an SBOM: npm trees routinely hold several versions."""

    name: str
    versions: set[str] = field(default_factory=set)
    suppliers: set[str | None] = field(default_factory=set)
    licenses: set[frozenset[str]] = field(default_factory=set)


def _key(purl: Any, name: str) -> str:
    """Identity across versions: the PURL without version, qualifiers or subpath, else the name.

    Qualifiers go too: a distro point release rewrites ``distro=debian-12.5``
    on every deb PURL without changing which package it is.
    """
    if purl:
        try:
            parsed = PackageURL.from_string(str(purl))
            return str(PackageURL(type=parsed.type, namespace=parsed.namespace, name=parsed.name).to_string())
        except ValueError:
            pass
    return name


def _cyclonedx_license(entry: Any) -> str | None:
    if not isinstance(entry, dict):
        return None
    license_ = entry.get("license") or {}
    return entry.get("expression") or license_.get("id") or license_.get("name")


def _cyclonedx(component: dict[str, Any]) -> tuple[str, str, str, str | None, frozenset[str]]:
    name = "/".join(part for part in (component.get("group"), component.get("name")) if part)
    licenses = frozenset(filter(None, map(_cyclonedx_license, component.get("licenses") or [])))
    supplier = (component.get("supplier") or {}).get("name") or None
    return _key(component.get("purl"), name), name, component.get("version") or "", supplier, licenses


def _spdx(package: dict[str, Any]) -> tuple[str, str, str, str | None, frozenset[str]]:
    name = package.get("name") or ""
    purl = next(
        (r.get("referenceLocator") for r in package.get("externalRefs") or [] if r.get("referenceType") == "purl"), None
    )
    # "Organization: Example Ltd" names the same supplier as CycloneDX's bare "Example Ltd".
    supplier = str(package["supplier"]).split(": ", 1)[-1] if _spdx_value(package.get("supplier")) else None
    declared = next((package[f] for f in ("licenseDeclared", "licenseConcluded") if _spdx_value(package.get(f))), None)
    return _key(purl, name), name, package.get("versionInfo") or "", supplier, frozenset([declared] if declared else [])


def _packages(doc: dict[str, Any]) -> tuple[int, dict[str, _Package]] | None:
    """Component count and packages by identity, or None for anything but CycloneDX and SPDX 2.

    Counted the way the job summary counts them, so the two numbers agree.
    ponytail: an SPDX root package is counted and diffed like any other, so
    comparing an SPDX SBOM with a CycloneDX one lists it once as added or
    removed; exclude documentDescribes if that ever matters.
    """
    if doc.get("bomFormat") == "CycloneDX":
        rows = [_cyclonedx(c) for c in _walk(doc.get("components") or [])]
    elif "spdxVersion" in doc:
        rows = [_spdx(p) for p in doc.get("packages") or []]
    else:
        return None
    packages: dict[str, _Package] = {}
    for key, name, version, supplier, licenses in rows:
        package = packages.setdefault(key, _Package(name))
        package.versions.add(version)
        package.suppliers.add(supplier)
        package.licenses.add(licenses)
    return len(rows), packages


def _label(package: _Package) -> str:
    versions = ", ".join(sorted(v for v in package.versions if v))
    return f"{package.name}@{versions}" if versions else package.name


def _versions(package: _Package) -> str:
    """Every version, an empty one as ``(none)``: blank beside an arrow, it is easy to miss."""
    return ", ".join(sorted(v or "(none)" for v in package.versions))


def _purl(key: str, package: _Package) -> str:
    """The PURL a package is keyed by, or ``(none)`` when it fell back to its name."""
    return "(none)" if key == package.name else key


def _code(text: str) -> str:
    """A code span the text cannot close early: a component name is whatever the SBOM says."""
    return "`" + " ".join(text.replace("`", "'").split()) + "`"


@dataclass
class Drift:
    """The difference between the previous SBOM and this run's."""

    source: str
    before: int
    after: int
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    purls: list[str] = field(default_factory=list)
    suppliers: int = 0
    licenses: int = 0

    @property
    def collapsed(self) -> bool:
        """More than half the previous SBOM's components are gone, from at least COLLAPSE_FLOOR."""
        return self.before >= COLLAPSE_FLOOR and self.after * 2 < self.before

    def collapse_message(self, failing: bool) -> str:
        """Why a collapse matters, for the log."""
        fell = f"This SBOM lists {self.after} components, down from {self.before} in {self.source}. {_WHY}"
        if failing:
            return (
                f"{fell} Failing the run so it is not published. If the drop is real, set FAIL_ON_SBOM_COLLAPSE=false."
            )
        return f"{fell} Continuing because FAIL_ON_SBOM_COLLAPSE=false."

    def markdown(self, failed: bool = False) -> str:
        lines = [
            "#### Changes since the previous SBOM",
            "",
            f"Compared with {self.source}.",
            "",
        ]
        if self.collapsed:
            what = "Run failed: the" if failed else "The"
            then = (
                "Nothing was uploaded. If the drop is real, set `FAIL_ON_SBOM_COLLAPSE=false`."
                if failed
                else "`FAIL_ON_SBOM_COLLAPSE=false`, so the run went on."
            )
            lines += [f"> **{what} component count fell by more than half.** {_WHY} {then}", ""]
        lines += [
            f"- **Components:** {self.before} → {self.after}",
            f"- **Added:** {len(self.added)} · **Removed:** {len(self.removed)}"
            f" · **Version changed:** {len(self.changed)} · **PURL changed:** {len(self.purls)}",
            f"- **Supplier changed:** {self.suppliers} · **License changed:** {self.licenses}",
        ]
        for title, entries in (
            ("Added", self.added),
            ("Removed", self.removed),
            ("Version changed", self.changed),
            ("PURL changed", self.purls),
        ):
            if not entries:
                continue
            lines += ["", f"<details><summary>{title} ({len(entries)})</summary>", ""]
            lines += [f"- {_code(entry)}" for entry in entries[:LIST_CAP]]
            if len(entries) > LIST_CAP:
                lines.append(f"- …and {len(entries) - LIST_CAP} more")
            lines += ["", "</details>"]
        return "\n".join(lines)


def publish_collapse(drift: Drift, config: "Config", sbom_format: str) -> None:
    """The job summary and step outputs for a run the collapse gate stopped. Never raises.

    The outputs still name the SBOM, so an ``if: failure()`` step can keep it for inspection.
    """
    try:
        formatter = get_platform().log_formatter()
        for name, value in sbom_outputs(config.output_file, sbom_format, drift.after).items():
            formatter.set_output(name, value)
        formatter.job_summary(f"### sbomify\n\n{drift.markdown(failed=True)}\n")
    except Exception as e:
        logger.warning(f"Could not write the run summary: {e}")


def compare_with_previous(previous: Previous, current_path: str) -> Drift | None:
    """Diff the previous SBOM against the one at ``current_path``.

    None when the current document is not CycloneDX or SPDX 2 (the summary has
    no counts for those either); a warning and None when the previous one is
    not, since someone chose it. Never raises: a previous SBOM is whatever the
    user downloaded, and a malformed one costs the section, not the run.
    """
    try:
        return _compare(previous, current_path)
    except Exception as e:
        logger.warning(f"No drift report: could not compare with {previous[1]}: {e}")
        return None


def _compare(previous: Previous, current_path: str) -> Drift | None:
    previous_doc, source = previous
    current = _packages(_read(current_path))
    if current is None:
        return None
    before = _packages(previous_doc)
    if before is None:
        logger.warning(f"No drift report: {source} is not a CycloneDX or SPDX 2 JSON document")
        return None
    (before_count, old), (after_count, new) = before, current
    added, removed = sorted(new.keys() - old.keys()), sorted(old.keys() - new.keys())

    # A component that lost or gained its PURL is keyed by name on one side only. Pairing the
    # leftovers by name makes a generator that stopped emitting PURLs read as that, not as
    # every such package removed and added again.
    # ponytail: any two same-named leftovers pair, so npm `debug` swapped for PyPI `debug`
    # reads as a PURL change too; require a PURL-less side if that ever misleads.
    unpaired: dict[str, list[str]] = {}
    for k in added:
        unpaired.setdefault(new[k].name, []).append(k)
    moved: list[tuple[str, str]] = []
    for k in removed:
        if candidates := unpaired.get(old[k].name):
            moved.append((k, candidates.pop(0)))
    pairs = sorted([(k, k) for k in old.keys() & new.keys()] + moved, key=lambda pair: pair[1])
    gone, came = {o for o, _ in moved}, {n for _, n in moved}

    def both(attribute: str) -> int:
        return sum(getattr(old[o], attribute) != getattr(new[n], attribute) for o, n in pairs)

    return Drift(
        source=source,
        before=before_count,
        after=after_count,
        added=[_label(new[k]) for k in added if k not in came],
        removed=[_label(old[k]) for k in removed if k not in gone],
        changed=[
            f"{new[n].name} {_versions(old[o])} → {_versions(new[n])}"
            for o, n in pairs
            if old[o].versions != new[n].versions
        ],
        purls=[f"{_label(new[n])}: {_purl(o, old[o])} → {_purl(n, new[n])}" for o, n in pairs if o != n],
        suppliers=both("suppliers"),
        licenses=both("licenses"),
    )


def load_previous_sbom(config: "Config", sbom_format: str) -> Previous | None:
    """The SBOM to compare this run against, or None.

    Called before enrichment rather than beside the comparison, so an
    OIDC-minted token is still fresh: enrichment can outlast its 15 minutes.
    """
    if path := config.previous_sbom:
        if not os.path.isfile(path):
            # The usual first release: the step meant to download it found nothing.
            # Relative to WORKING_DIR, which the CLI chdir'd into: say where that led.
            logger.info(f"No drift report: PREVIOUS_SBOM ({os.path.abspath(path)}) does not exist")
            return None
        if not (doc := _read(path)):
            logger.warning(f"No drift report: PREVIOUS_SBOM ({path}) is not a JSON document")
            return None
        return doc, _code(path)

    if not (config.uploads_to_sbomify and config.token and config.component_id):
        return None
    try:
        client = SbomifyApiClient(config.api_base_url, config.token)
        latest = client.latest_component_sbom(config.component_id, sbom_format)
        if latest is None:
            return None  # the component's first SBOM
        doc = client.download_sbom(str(latest["id"]))
    except ForbiddenError:
        logger.info(
            "No drift report: this token can upload to the component but not read its SBOMs back "
            "(OIDC trusted publishing on a private component, or a publish-only token). "
            "Set PREVIOUS_SBOM to an earlier release's SBOM to compare against that instead."
        )
        return None
    except Exception as e:
        logger.warning(f"No drift report: could not fetch the previous SBOM from sbomify: {e}")
        return None
    version = f" (version {_code(str(latest['version']))})" if latest.get("version") else ""
    return doc, f"the last {format_display_name(sbom_format)} SBOM uploaded to sbomify{version}"
