"""SPDX 3 JSON-LD parser, writer, and helpers.

This module provides operations for SPDX 3.0.x documents using the
``spdx_tools.spdx3`` model classes (``Payload``, ``SpdxDocument``,
``Package``, etc.).

The ``spdx_tools`` library ships a writer
(:func:`spdx_tools.spdx3.writer.json_ld.json_ld_writer.write_payload`)
but **no parser** for SPDX 3 JSON-LD.  We implement a parser that reads
JSON-LD into model objects, and a thin writer wrapper that uses the
official 3.0.1 context URL (the library bundles a local ``context.json``
instead).
"""

import copy
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from semantic_version import Version
from spdx_tools.spdx.casing_tools import snake_case_to_camel_case as _s2c
from spdx_tools.spdx3.model import (
    CreationInfo,
    ExternalIdentifier,
    ExternalIdentifierType,
    ExternalReference,
    ExternalReferenceType,
    Hash,
    HashAlgorithm,
    Organization,
    Person,
    ProfileIdentifierType,
    Relationship,
    RelationshipType,
    SoftwareAgent,
    SpdxDocument,
    Tool,
)
from spdx_tools.spdx3.model.licensing import (
    CustomLicense,
    DisjunctiveLicenseSet,
    ListedLicense,
    NoAssertionLicense,
    NoneLicense,
)
from spdx_tools.spdx3.model.software import SoftwarePurpose
from spdx_tools.spdx3.model.software.file import File as SpdxFile
from spdx_tools.spdx3.model.software.package import Package
from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx3.writer.json_ld.json_ld_converter import (
    convert_payload_to_json_ld_list_of_elements,
)

from .logging_config import logger

# Explicitly re-export spdx_tools model types used by other modules
# (enrichment.py, augmentation.py) so mypy strict mode doesn't flag
# them as implicit re-exports.
__all__ = [
    "ExternalReference",
    "ExternalReferenceType",
    "Organization",
    "Person",
    "Tool",
]


class Spdx3Payload(Payload):  # type: ignore[misc]
    """Thin wrapper around :class:`Payload` that carries passthrough elements.

    Elements whose ``type`` is not handled by the parser (e.g. security,
    build, licensing types) are stored verbatim so the writer can
    re-attach them to the output without data loss.
    """

    def __init__(self) -> None:
        super().__init__()
        self.passthrough_elements: list[dict[str, Any]] = []
        # 3.0.1 moved dataLicense onto SpdxDocument and replaced CreationInfo's
        # profile with Element.profileConformance. spdx-tools 0.8.5 models the
        # pre-3.0.1 draft and has no slot for either, so they ride here instead
        # of being dropped on the floor.
        self.document_data_license: str | None = None
        self.document_profile_conformance: list[str] = []
        # The @context the input declared. 3.0 and 3.0.1 are both in the wild
        # (syft, Microsoft sbom-tool, JFrog Xray and Zephyr emit 3.0), and
        # relabelling one as the other leaves the context disagreeing with the
        # creationInfo's specVersion, which no producer wrote and no consumer
        # can resolve.
        self.context_url: str | None = None
        # Values 3.0.1 defines and spdx-tools 0.8.5 does not, keyed by spdxId
        # and written back verbatim. A typed field cannot hold a string its
        # enum does not know, so without this the purposes Yocto emits
        # (`specification`, `filesystemImage`) are dropped and 37 of 3.0.1's
        # 59 relationship types, both licence relationships included, come out
        # as `other`.
        self.kept_raw_fields: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SPDX3_CONTEXT_URL = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

# Regex to detect spdx.org/rdf/3.x context
_SPDX3_CONTEXT_RE = re.compile(r"spdx\.org/rdf/3")

#: What a version looks like in a context URL. Both regexes below are built
#: from it, because a context this module preserves and a version it cannot
#: read off that same context is the disagreement it exists to prevent.
#:
#: Two parts or three: spdx.org/rdf/3.0/ is a real context, served and
#: byte-identical to the 3.0.1 one today, so a document can legitimately
#: carry a version with no patch number.
_SPDX3_VERSION = r"\d+\.\d+(?:\.\d+)?"

# Regex to extract version from context URL
_SPDX3_VERSION_RE = re.compile(rf"spdx\.org/rdf/({_SPDX3_VERSION})/")

#: The one the schemas pin, with a ``const``. Anything else under
#: ``spdx.org/rdf/3`` identifies a document as SPDX 3 without being a context
#: the writer may echo back: ``spdx.org/rdf/3.0.1/terms/Core/`` is a terms
#: IRI, and writing it as ``@context`` fails the schema it came from.
_SPDX3_CONTEXT_URL_RE = re.compile(rf"https?://spdx\.org/rdf/{_SPDX3_VERSION}/spdx-context\.jsonld")

# Map JSON-LD @type → model class
_TYPE_ALIASES: dict[str, str] = {
    "software_Package": "Package",
    "software_File": "File",
    "software_Snippet": "Snippet",
    "software_Sbom": "Sbom",
}

# Reverse mapping: model class name → JSON-LD type prefix (e.g. "Package" → "software_Package")
_REVERSE_TYPE_ALIASES: dict[str, str] = {v: k for k, v in _TYPE_ALIASES.items()}

# Property names the spdx_tools converter outputs WITHOUT the software_ prefix,
# but the SPDX 3.0.1 JSON-LD context REQUIRES the prefix.  Used by the writer
# to fix serialized output and by the parser to accept both forms.
# Maps: converter_name → context_name
_SOFTWARE_PROPERTY_RENAMES: dict[str, str] = {
    "packageVersion": "software_packageVersion",
    "downloadLocation": "software_downloadLocation",
    "packageUrl": "software_packageUrl",
    "homepage": "software_homePage",
    "sourceInfo": "software_sourceInfo",
    "copyrightText": "software_copyrightText",
    "primaryPurpose": "software_primaryPurpose",
    "additionalPurpose": "software_additionalPurpose",
    "attributionText": "software_attributionText",
    "contentIdentifier": "software_contentIdentifier",
}

# Map HashAlgorithm enum names (upper) to enum values
_HASH_ALGORITHMS: dict[str, HashAlgorithm] = {a.name.lower(): a for a in HashAlgorithm}

# The spdx_tools writer serializes enum names via snake_case_to_camel_case
# (producing camelCase strings).  We build lookup dicts that accept both the
# camelCase and raw snake_case forms.  _s2c is imported at module top.

# Map ExternalReferenceType enum names
_EXT_REF_TYPES: dict[str, ExternalReferenceType] = {}
for _e in ExternalReferenceType:
    _EXT_REF_TYPES[_s2c(_e.name).lower()] = _e
    _EXT_REF_TYPES[_e.name.lower()] = _e

# Map ExternalIdentifierType
_EXT_ID_TYPES: dict[str, ExternalIdentifierType] = {}
for _e in ExternalIdentifierType:
    _EXT_ID_TYPES[_s2c(_e.name).lower()] = _e
    _EXT_ID_TYPES[_e.name.lower()] = _e

# Map RelationshipType, and back again: the spelling a type is written with
# is needed to tell an element's own relationships apart after parsing.
_REL_TYPES: dict[str, RelationshipType] = {}
_REL_TYPE_NAMES: dict[RelationshipType, str] = {}
for _e in RelationshipType:
    _REL_TYPES[_s2c(_e.name).lower()] = _e
    _REL_TYPES[_e.name.lower()] = _e
    _REL_TYPE_NAMES[_e] = _s2c(_e.name)

# Map SoftwarePurpose
_SW_PURPOSES: dict[str, SoftwarePurpose] = {}
for _e in SoftwarePurpose:
    _SW_PURPOSES[_s2c(_e.name).lower()] = _e
    _SW_PURPOSES[_e.name.lower()] = _e

# Map ProfileIdentifierType
_PROFILE_TYPES: dict[str, ProfileIdentifierType] = {}
for _e in ProfileIdentifierType:
    _PROFILE_TYPES[_s2c(_e.name).lower()] = _e
    _PROFILE_TYPES[_e.name.lower()] = _e

# Cleanup temporary loop variables (avoid polluting module namespace)
del _e, _s2c


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def is_spdx3(data: dict[str, Any]) -> bool:
    """Return ``True`` if *data* looks like an SPDX 3.x JSON-LD document.

    Checks for ``@context`` containing ``spdx.org/rdf/3``.
    """
    ctx = data.get("@context")
    if isinstance(ctx, str):
        return bool(_SPDX3_CONTEXT_RE.search(ctx))
    if isinstance(ctx, list):
        return any(isinstance(c, str) and _SPDX3_CONTEXT_RE.search(c) for c in ctx)
    if isinstance(ctx, dict):
        # e.g. {"@vocab": "https://spdx.org/rdf/3.0.1/terms/Core/", ...}
        for v in ctx.values():
            if isinstance(v, str) and _SPDX3_CONTEXT_RE.search(v):
                return True
    return False


def _stated_spec_version(node: Any, from_creation_info: bool = False) -> str | None:
    """The ``specVersion`` a CreationInfo in *node* states.

    Only from a CreationInfo, either one that names its type or one reached as
    a ``creationInfo`` value. That is the only place 3.0.1 puts the property,
    and this answer chooses the schema the whole document is held to, so a
    ``specVersion`` sitting on anything else must not speak for it.
    """
    if isinstance(node, dict):
        if from_creation_info or (node.get("type") or node.get("@type")) == "CreationInfo":
            stated = node.get("specVersion")
            if isinstance(stated, str) and stated.strip():
                return stated.strip()
        for key, value in node.items():
            found = _stated_spec_version(value, key == "creationInfo")
            if found:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _stated_spec_version(item, from_creation_info)
            if found:
                return found
    return None


def _document_spec_version(data: dict[str, Any]) -> str | None:
    """The ``specVersion`` the SpdxDocument itself states, inline or by reference.

    A graph can hold several CreationInfos, and they need not agree: a merged
    document, or one whose producer copied in an element written elsewhere,
    carries the other document's version on that element. Taking the first one
    the scan reaches then lets an element speak for the whole document, and
    which element that is depends on serialization order.
    """
    graph = data.get("@graph", data)
    if isinstance(graph, dict):
        graph = [graph]
    if not isinstance(graph, list):
        return None
    elements = [e for e in graph if isinstance(e, dict)]
    by_id = {e.get("@id") or e.get("spdxId"): e for e in elements if e.get("@id") or e.get("spdxId")}
    for element in elements:
        if (element.get("type") or element.get("@type")) != "SpdxDocument":
            continue
        creation_info = element.get("creationInfo")
        if isinstance(creation_info, str):
            creation_info = by_id.get(creation_info)
        stated = _stated_spec_version(creation_info, from_creation_info=True)
        if stated:
            return stated
    return None


def extract_spdx3_version(data: dict[str, Any]) -> str | None:
    """The SPDX 3 spec version the document claims. e.g. ``"3.0.1"``.

    The document's own ``specVersion`` comes first. ``CreationInfo_props``
    requires it and every Element requires a creationInfo, so a conformant
    document always states it, and it is the normative claim rather than a
    hint.

    The ``@context`` is the fallback, and only a fallback, because it can be
    an unversioned alias: ``spdx.org/rdf/3.0/`` resolves and is byte-identical
    to the 3.0.1 context today, so what it means depends on when the document
    was written. A document carrying only that and no specVersion is already
    invalid, which is the only case this order leaves ambiguous.
    """
    stated = _document_spec_version(data) or _stated_spec_version(data.get("@graph", data))
    if stated:
        return stated

    ctx = data.get("@context")
    candidates: list[str] = []
    if isinstance(ctx, str):
        candidates = [ctx]
    elif isinstance(ctx, list):
        candidates = [c for c in ctx if isinstance(c, str)]
    elif isinstance(ctx, dict):
        candidates = [v for v in ctx.values() if isinstance(v, str)]

    for c in candidates:
        m = _SPDX3_VERSION_RE.search(c)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Parser  (JSON-LD → Payload)
# ---------------------------------------------------------------------------


def _get_sw(elem: dict[str, Any], unprefixed: str, prefixed: str | None = None) -> Any:
    """Return value from *elem* trying *unprefixed* then *software_*-prefixed key.

    Needed because the spdx_tools converter writes ``packageVersion`` while
    the SPDX 3.0.1 context defines ``software_packageVersion``.  Real SBOMs
    (Yocto / OpenEmbedded) use the spec-correct prefixed form.
    """
    if unprefixed in elem:
        return elem[unprefixed]
    if prefixed is None:
        prefixed = f"software_{unprefixed}"
    return elem.get(prefixed)


def _parse_creation_info(ci_dict: dict[str, Any]) -> CreationInfo:
    """Parse a nested ``creationInfo`` dict into a :class:`CreationInfo`."""
    spec_str = ci_dict.get("specVersion", "3.0.1")
    spec_version = Version(spec_str)

    created_str = ci_dict.get("created")
    if created_str:
        # Handle ISO-8601 with or without timezone
        created_str = created_str.replace("Z", "+00:00")
        created = datetime.fromisoformat(created_str)
        # Ensure timezone-aware to avoid TypeError when mixed with aware datetimes
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
    else:
        created = datetime.now(timezone.utc)

    created_by = ci_dict.get("createdBy", [])
    if isinstance(created_by, str):
        created_by = [created_by]

    created_using = ci_dict.get("createdUsing", [])
    if isinstance(created_using, str):
        created_using = [created_using]

    # Parse profile list
    raw_profiles = ci_dict.get("profile", [])
    if isinstance(raw_profiles, str):
        raw_profiles = [raw_profiles]
    profiles: list[ProfileIdentifierType] = []
    for p in raw_profiles:
        key = p.lower() if isinstance(p, str) else ""
        if key in _PROFILE_TYPES:
            profiles.append(_PROFILE_TYPES[key])

    data_license = ci_dict.get("dataLicense", "CC0-1.0")
    comment = ci_dict.get("comment")

    return CreationInfo(
        spec_version=spec_version,
        created=created,
        created_by=created_by,
        profile=profiles,
        data_license=data_license,
        created_using=created_using,
        comment=comment,
    )


def _parse_external_reference(ref_dict: dict[str, Any]) -> ExternalReference:
    """Parse an external reference dict."""
    # SPDX 3.0.1 schema uses "externalRefType"; accept both forms for compatibility
    ref_type_str = ref_dict.get("externalRefType") or ref_dict.get("externalReferenceType", "")
    ref_type = _EXT_REF_TYPES.get(ref_type_str.lower(), ExternalReferenceType.OTHER)

    locator = ref_dict.get("locator", [])
    if isinstance(locator, str):
        locator = [locator]

    return ExternalReference(
        external_reference_type=ref_type,
        locator=locator,
        content_type=ref_dict.get("contentType"),
        comment=ref_dict.get("comment"),
    )


def _parse_external_identifier(eid_dict: dict[str, Any]) -> ExternalIdentifier:
    """Parse an external identifier dict."""
    eid_type_str = eid_dict.get("externalIdentifierType", "")
    eid_type = _EXT_ID_TYPES.get(eid_type_str.lower(), ExternalIdentifierType.OTHER)

    return ExternalIdentifier(
        external_identifier_type=eid_type,
        identifier=eid_dict.get("identifier", ""),
        comment=eid_dict.get("comment"),
    )


def _parse_hash(h_dict: dict[str, Any]) -> Hash:
    """Parse a hash/integrity dict."""
    alg_str = h_dict.get("algorithm", "").lower()
    algorithm = _HASH_ALGORITHMS.get(alg_str, HashAlgorithm.OTHER)
    return Hash(algorithm=algorithm, hash_value=h_dict.get("hashValue", ""))


def _parse_common_fields(
    elem: dict[str, Any], creation_info_map: dict[str, CreationInfo] | None = None
) -> dict[str, Any]:
    """Extract fields common to all Element subclasses."""
    result: dict[str, Any] = {}

    spdx_id = elem.get("@id") or elem.get("spdxId")
    if not spdx_id:
        spdx_id = f"urn:spdx.dev:{uuid.uuid4()}"
        logger.warning(f"Element missing @id/spdxId, generated fallback: {spdx_id}")
    result["spdx_id"] = spdx_id

    creation_info_raw = elem.get("creationInfo")
    if isinstance(creation_info_raw, dict):
        result["creation_info"] = _parse_creation_info(creation_info_raw)
    elif isinstance(creation_info_raw, str):
        # IRI reference to a CreationInfo element in the graph
        if creation_info_map and creation_info_raw in creation_info_map:
            result["creation_info"] = creation_info_map[creation_info_raw]
        else:
            result["creation_info"] = make_spdx3_creation_info()

    for field_name in ("name", "summary", "description", "comment", "extension"):
        if field_name in elem:
            result[field_name] = elem[field_name]

    # External references — SPDX 3.0.1 schema uses "externalRef"; accept both forms.
    # Items can be dicts (embedded objects) or strings (IRIs); only parse dicts.
    ext_refs_raw = elem.get("externalRef") or elem.get("externalReference", [])
    if isinstance(ext_refs_raw, dict):
        ext_refs_raw = [ext_refs_raw]
    if ext_refs_raw:
        result["external_reference"] = [_parse_external_reference(r) for r in ext_refs_raw if isinstance(r, dict)]

    # External identifiers — items can be dicts or IRI strings; only parse dicts.
    ext_ids_raw = elem.get("externalIdentifier", [])
    if isinstance(ext_ids_raw, dict):
        ext_ids_raw = [ext_ids_raw]
    if ext_ids_raw:
        result["external_identifier"] = [_parse_external_identifier(r) for r in ext_ids_raw if isinstance(r, dict)]

    # Verified using (hashes)
    hashes_raw = elem.get("verifiedUsing", [])
    if isinstance(hashes_raw, dict):
        hashes_raw = [hashes_raw]
    if hashes_raw:
        parsed_hashes = []
        for h in hashes_raw:
            if isinstance(h, dict) and ("algorithm" in h or "hashValue" in h):
                parsed_hashes.append(_parse_hash(h))
        if parsed_hashes:
            result["verified_using"] = parsed_hashes

    return result


def _parse_software_artifact_fields(elem: dict[str, Any], fields: dict[str, Any]) -> None:
    """Parse fields specific to SoftwareArtifact subclasses (Package, File).

    Each software-profile property is looked up with both the unprefixed name
    (as output by the spdx_tools converter) and the ``software_``-prefixed name
    (as required by the SPDX 3.0.1 JSON-LD context and used by real tools).
    """
    for unprefixed, py_key in [
        ("contentIdentifier", "content_identifier"),
        ("copyrightText", "copyright_text"),
        ("attributionText", "attribution_text"),
    ]:
        val = _get_sw(elem, unprefixed)
        if val is not None:
            fields[py_key] = val

    # suppliedBy / originatedBy — Core properties, no software_ prefix needed
    for json_key, py_key in [
        ("suppliedBy", "supplied_by"),
        ("originatedBy", "originated_by"),
    ]:
        val = elem.get(json_key)
        if val is not None:
            fields[py_key] = [val] if isinstance(val, str) else list(val)

    # Primary purpose
    pp = _get_sw(elem, "primaryPurpose")
    if pp:
        pp_key = pp.lower()
        if pp_key in _SW_PURPOSES:
            fields["primary_purpose"] = _SW_PURPOSES[pp_key]
        else:
            logger.debug("primaryPurpose %r is not in the library's enum; keeping the raw value", pp)

    # Additional purposes
    aps = _get_sw(elem, "additionalPurpose") or []
    if isinstance(aps, str):
        aps = [aps]
    if aps:
        fields["additional_purpose"] = [_SW_PURPOSES[a.lower()] for a in aps if a.lower() in _SW_PURPOSES]

    # Dates — Core properties, no software_ prefix needed
    for json_key, py_key in [
        ("builtTime", "built_time"),
        ("releaseTime", "release_time"),
        ("validUntilTime", "valid_until_time"),
    ]:
        date_str = elem.get(json_key)
        if date_str:
            date_str = date_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(date_str)
            # Ensure timezone-aware to avoid TypeError when mixed with aware datetimes
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            fields[py_key] = dt

    # Standards — context uses "standardName", spdx_tools may output "standard"
    stds = elem.get("standardName") or elem.get("standard", [])
    if isinstance(stds, str):
        stds = [stds]
    if stds:
        fields["standard"] = stds


def _parse_package(elem: dict[str, Any], ci_map: dict[str, CreationInfo] | None = None) -> Package:
    """Parse a Package element."""
    fields = _parse_common_fields(elem, ci_map)
    _parse_software_artifact_fields(elem, fields)

    # Package-specific fields — accept both unprefixed and software_-prefixed
    # Note: "homepage" maps to "software_homePage" in the context (different casing)
    for unprefixed, prefixed, py_key in [
        ("packageVersion", "software_packageVersion", "package_version"),
        ("downloadLocation", "software_downloadLocation", "download_location"),
        ("packageUrl", "software_packageUrl", "package_url"),
        ("homepage", "software_homePage", "homepage"),
        ("sourceInfo", "software_sourceInfo", "source_info"),
    ]:
        val = _get_sw(elem, unprefixed, prefixed)
        if val is not None:
            fields[py_key] = val

    # Ensure required 'name' field
    if "name" not in fields:
        fields["name"] = "unknown"

    return Package(**fields)


def _parse_file(elem: dict[str, Any], ci_map: dict[str, CreationInfo] | None = None) -> SpdxFile:
    """Parse a File element."""
    fields = _parse_common_fields(elem, ci_map)
    _parse_software_artifact_fields(elem, fields)

    # Ensure required 'name' field
    if "name" not in fields:
        fields["name"] = "unknown"

    return SpdxFile(**fields)


def _parse_spdx_document(elem: dict[str, Any], ci_map: dict[str, CreationInfo] | None = None) -> SpdxDocument:
    """Parse an SpdxDocument element."""
    fields = _parse_common_fields(elem, ci_map)

    element_list = elem.get("element", [])
    if isinstance(element_list, str):
        element_list = [element_list]

    root_element = elem.get("rootElement", [])
    if isinstance(root_element, str):
        root_element = [root_element]

    fields["element"] = element_list
    fields["root_element"] = root_element

    # Ensure required 'name' field
    if "name" not in fields:
        fields["name"] = "unknown"

    return SpdxDocument(**fields)


def _keep(payload: "Spdx3Payload", elem: dict[str, Any], kept: dict[str, Any]) -> None:
    """Stash raw fields to write back verbatim, keyed by the element's id."""
    spdx_id = elem.get("@id") or elem.get("spdxId")
    if kept and isinstance(spdx_id, str) and spdx_id:
        payload.kept_raw_fields.setdefault(spdx_id, {}).update(kept)


def _capture_unmodelled_relationship_type(payload: "Spdx3Payload", elem: dict[str, Any]) -> None:
    """Keep a relationship type the library's enum predates.

    spdx-tools 0.8.5 holds 62 relationship types and 37 of 3.0.1's 59 are not
    among them, both licence relationships included. Its parser maps anything
    it does not recognise to ``other``, which is itself a legal value, so the
    rewritten document passes the schema while saying something different from
    what the producer wrote: a package's declared licence, a static link and a
    prerequisite all come back as an unspecified relationship to the same
    target.
    """
    rel_type = elem.get("relationshipType")
    if isinstance(rel_type, str) and rel_type and rel_type.lower() not in _REL_TYPES:
        _keep(payload, elem, {"relationshipType": rel_type})


def _capture_unmodelled_purposes(payload: "Spdx3Payload", elem: dict[str, Any]) -> None:
    """Keep purpose values the library's enum predates.

    spdx-tools 0.8.5 models a pre-3.0.1 SoftwarePurpose, so a value the
    producer wrote and the schema accepts would otherwise be logged and
    dropped. Measured on the published Yocto 6.0.3 image SBOM: 38 packages
    lost their primaryPurpose, the image itself among them.
    """
    kept: dict[str, Any] = {}

    primary = _get_sw(elem, "primaryPurpose")
    if isinstance(primary, str) and primary.lower() not in _SW_PURPOSES:
        kept["software_primaryPurpose"] = primary

    additional = _get_sw(elem, "additionalPurpose") or []
    if isinstance(additional, str):
        additional = [additional]
    if isinstance(additional, list):
        unknown = [a for a in additional if isinstance(a, str) and a.lower() not in _SW_PURPOSES]
        if unknown:
            # The whole list, not just the strangers. Restoring is a plain
            # overwrite of the serialized value, so keeping only the unknown
            # ones dropped every purpose the library did understand:
            # ["library", "specification"] came back as ["specification"].
            kept["software_additionalPurpose"] = [a for a in additional if isinstance(a, str)]

    _keep(payload, elem, kept)


#: Where SPDX publishes the licence list. A bare id in the draft location means
#: this licence; 3.0.1 just spells it as an IRI.
_SPDX_LICENSE_BASE = "https://spdx.org/licenses/"


def _as_license_iri(value: str) -> str:
    """A licence the way 3.0.1 spells it.

    The draft location holds a bare id, `"CC0-1.0"`, and `dataLicense` on
    SpdxDocument resolves to a licence IRI. Writing the bare id back produced a
    document that failed the schema, so carrying the value forward has to carry
    its spelling forward too. A rewrite rather than an invention: the id and the
    IRI name the same licence, and anything that already looks like an IRI is
    left exactly as the producer wrote it.
    """
    stripped = value.strip()
    if not stripped or "://" in stripped or stripped.startswith("urn:"):
        return stripped
    return _SPDX_LICENSE_BASE + stripped


def _capture_document_fields(
    payload: "Spdx3Payload", elem: dict[str, Any], raw_creation_infos: dict[str, dict[str, Any]] | None = None
) -> None:
    """Carry the two document-level fields the draft model cannot hold.

    ``dataLicense`` and ``profileConformance`` are both read from the
    SpdxDocument, which is where 3.0.1 puts them, and from the CreationInfo as
    a fallback, which is where this repo's older fixtures and spdx-tools both
    put them.
    """
    data_license = elem.get("dataLicense")
    if not isinstance(data_license, str) or not data_license:
        # The draft location, which this repo's older fixtures use. Read from
        # the raw dict, never from the parsed CreationInfo: the model defaults
        # data_license to "CC0-1.0", and writing that onto a document whose
        # author declared none both invents a claim and fails the schema, which
        # wants a licence IRI rather than a short identifier.
        ci = elem.get("creationInfo")
        # Either shape. JSON-LD lets a document inline its CreationInfo or
        # point at a standalone one, and this repo's own fixtures point:
        # "creationInfo": "_:creationinfo". Reading only the inline form meant
        # a legacy dataLicense on the referenced element was stripped by the
        # normalisation and never put back.
        if isinstance(ci, str) and raw_creation_infos:
            ci = raw_creation_infos.get(ci)
        data_license = ci.get("dataLicense") if isinstance(ci, dict) else None
    if isinstance(data_license, str) and data_license:
        payload.document_data_license = _as_license_iri(data_license)

    profiles = elem.get("profileConformance")
    if not profiles:
        # The draft location again. spdx-tools puts conformance on the
        # CreationInfo as ``profile``, real producers emit it there, and the
        # normalisation strips it from every CreationInfo on the way out. Read
        # here it survives as the property 3.0.1 actually has; not read, the
        # document silently stops claiming a conformance its author wrote.
        ci = elem.get("creationInfo")
        if isinstance(ci, str) and raw_creation_infos:
            ci = raw_creation_infos.get(ci)
        profiles = ci.get("profile") if isinstance(ci, dict) else None
    if isinstance(profiles, str):
        profiles = [profiles]
    if isinstance(profiles, list):
        payload.document_profile_conformance = [p for p in profiles if isinstance(p, str)]


def _parse_relationship(elem: dict[str, Any], ci_map: dict[str, CreationInfo] | None = None) -> Relationship:
    """Parse a Relationship element."""
    fields = _parse_common_fields(elem, ci_map)

    from_element = elem.get("from", elem.get("fromElement", ""))
    fields["from_element"] = from_element

    to = elem.get("to", [])
    if isinstance(to, str):
        to = [to]
    fields["to"] = to

    rel_type_str = elem.get("relationshipType", "")
    rel_type = _REL_TYPES.get(rel_type_str.lower(), RelationshipType.OTHER)
    fields["relationship_type"] = rel_type

    return Relationship(**fields)


def _parse_agent(
    elem: dict[str, Any], cls: type, ci_map: dict[str, CreationInfo] | None = None
) -> Organization | Person | SoftwareAgent | Tool:
    """Parse an Organization, Person, SoftwareAgent, or Tool element."""
    fields = _parse_common_fields(elem, ci_map)
    return cls(**fields)


def parse_spdx3_file(file_path: str) -> Spdx3Payload:
    """Parse an SPDX 3 JSON-LD file into an :class:`Spdx3Payload`.

    Maps ``@graph`` elements by their ``type`` (``@type``) to the
    corresponding ``spdx_tools.spdx3.model`` classes.

    Args:
        file_path: Path to the SPDX 3 JSON-LD ``.json`` file.

    Returns:
        Populated :class:`Spdx3Payload` with all parsed elements.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        json.JSONDecodeError: If the file isn't valid JSON.
        ValueError: If the file isn't SPDX 3 JSON-LD.
    """
    path = Path(file_path)
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not is_spdx3(data):
        raise ValueError(f"File does not appear to be SPDX 3 JSON-LD: {file_path}")

    return parse_spdx3_data(data)


def _declared_context(context: Any) -> str | None:
    """The SPDX 3 context URL a document declares, whatever shape it is in.

    JSON-LD allows a string, a list or an object, and a document that wraps its
    context in a list is as conformant as one that does not.

    What comes back is written straight out as the ``@context`` of what the
    action produces, so only the schema-pinned context URL counts. A document
    can carry other ``spdx.org/rdf/3`` URLs, and echoing one of those back
    would relabel a conformant input as something no schema accepts.
    """
    candidates: list[str]
    if isinstance(context, str):
        candidates = [context]
    elif isinstance(context, list):
        candidates = [c for c in context if isinstance(c, str)]
    elif isinstance(context, dict):
        candidates = [v for v in context.values() if isinstance(v, str)]
    else:
        return None
    for candidate in candidates:
        cleaned = candidate.strip()
        if not _SPDX3_CONTEXT_URL_RE.fullmatch(cleaned):
            continue
        # The schemas pin @context to the https form, so what an http one
        # names is the version, not the scheme it happens to be written with.
        if cleaned.startswith("http://"):
            cleaned = "https://" + cleaned[len("http://") :]
        return cleaned
    return None


def parse_spdx3_data(data: dict[str, Any]) -> Spdx3Payload:
    """Parse SPDX 3 JSON-LD data (already loaded) into an :class:`Spdx3Payload`.

    Handles both ``@graph``-based documents and top-level element documents
    (where the root object itself is the element, without ``@graph``).
    """
    graph = data.get("@graph", [])

    # Handle non-@graph form: top-level object is itself an element
    if not graph and ("type" in data or "@type" in data):
        graph = [data]

    # First pass: collect CreationInfo elements keyed by IRI so that
    # elements referencing them via string can be resolved.
    ci_map: dict[str, CreationInfo] = {}
    # The same elements unparsed, for the fields the draft model has no slot
    # for: a document that references its CreationInfo rather than inlining it
    # keeps its legacy dataLicense there, and the parsed object cannot carry it.
    raw_creation_infos: dict[str, dict[str, Any]] = {}
    for elem in graph:
        if not isinstance(elem, dict):
            continue
        elem_type = elem.get("type") or elem.get("@type", "")
        if elem_type == "CreationInfo":
            ci_id = elem.get("@id") or elem.get("spdxId")
            if ci_id:
                ci_map[ci_id] = _parse_creation_info(elem)
                raw_creation_infos[ci_id] = elem

    # Second pass: parse all other elements
    payload = Spdx3Payload()
    # Matching is_spdx3 and extract_spdx3_version, both of which read every
    # shape JSON-LD allows here. Taking the string form alone left context_url
    # None for a list or dict context, and the writer then fell back to the
    # current release: the relabelling this is here to prevent.
    payload.context_url = _declared_context(data.get("@context"))

    for elem in graph:
        if not isinstance(elem, dict):
            continue

        elem_type = elem.get("type") or elem.get("@type", "")
        # Normalize aliases
        elem_type = _TYPE_ALIASES.get(elem_type, elem_type)

        try:
            if elem_type == "SpdxDocument":
                payload.add_element(_parse_spdx_document(elem, ci_map))
                _capture_document_fields(payload, elem, raw_creation_infos)
            elif elem_type == "Package":
                payload.add_element(_parse_package(elem, ci_map))
                _capture_unmodelled_purposes(payload, elem)
            elif elem_type == "File":
                payload.add_element(_parse_file(elem, ci_map))
                _capture_unmodelled_purposes(payload, elem)
            elif elem_type == "Organization":
                payload.add_element(_parse_agent(elem, Organization, ci_map))
            elif elem_type == "Person":
                payload.add_element(_parse_agent(elem, Person, ci_map))
            elif elem_type == "Tool":
                payload.add_element(_parse_agent(elem, Tool, ci_map))
            elif elem_type == "SoftwareAgent":
                payload.add_element(_parse_agent(elem, SoftwareAgent, ci_map))
            elif elem_type == "Relationship":
                payload.add_element(_parse_relationship(elem, ci_map))
                _capture_unmodelled_relationship_type(payload, elem)
            elif elem_type == "CreationInfo":
                # Already parsed in first pass; preserve standalone CreationInfo
                # elements (those with @id) so passthrough elements referencing
                # them by IRI string survive the roundtrip.
                if elem.get("@id") or elem.get("spdxId"):
                    payload.passthrough_elements.append(elem)
            else:
                logger.debug(f"Passing through unhandled SPDX 3 element type: {elem_type}")
                payload.passthrough_elements.append(elem)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            spdx_id = elem.get("@id") or elem.get("spdxId", "unknown")
            logger.warning(f"Failed to parse SPDX 3 element {spdx_id} (type={elem_type}): {e}")
            payload.passthrough_elements.append(elem)

    return payload


# ---------------------------------------------------------------------------
# Writer  (Payload → JSON-LD file)
# ---------------------------------------------------------------------------


def _normalize_serialized_element(elem: dict[str, Any]) -> None:
    """Fix spdx_tools converter output to match SPDX 3.0.1 JSON-LD context.

    Modifies *elem* **in place**:

    1. ``@type`` → ``type``, ``@id`` → ``spdxId``  (context aliases)
    2. Restore type prefixes: ``Package`` → ``software_Package``, etc.
    3. Rename software-profile properties to their ``software_``-prefixed
       form as required by the JSON-LD context.
    4. Recurse into nested dicts (creationInfo, verifiedUsing, etc.)
    """
    # --- key normalization: @type → type, @id → spdxId ---
    if "@type" in elem:
        elem["type"] = elem.pop("@type")
    if "@id" in elem:
        elem["spdxId"] = elem.pop("@id")

    # --- type prefix restoration ---
    etype = elem.get("type", "")
    if etype in _REVERSE_TYPE_ALIASES:
        elem["type"] = _REVERSE_TYPE_ALIASES[etype]

    # --- software property prefix ---
    for old_key, new_key in _SOFTWARE_PROPERTY_RENAMES.items():
        if old_key in elem:
            elem[new_key] = elem.pop(old_key)

    # --- other property renames (non-software) ---
    # spdx_tools outputs "standard" but context defines "standardName"
    if "standard" in elem:
        elem["standardName"] = elem.pop("standard")

    # spdx_tools writes the draft spelling; 3.0.1 renamed the property, the
    # class and the type field, and rejects the old names outright.
    if "externalReference" in elem:
        elem["externalRef"] = elem.pop("externalReference")

    # An artifact has exactly one supplier in 3.0.1; originatedBy is the set.
    # spdx-tools models both as lists, so a supplier the action worked out is
    # written as a one-element array the schema refuses.
    supplied_by = elem.get("suppliedBy")
    if isinstance(supplied_by, list):
        if len(supplied_by) > 1:
            logger.warning(
                "Element %s names %d suppliers; 3.0.1 allows one, keeping the first",
                elem.get("spdxId") or elem.get("@id"),
                len(supplied_by),
            )
        if supplied_by:
            elem["suppliedBy"] = supplied_by[0]
        else:
            del elem["suppliedBy"]

    _strip_draft_creation_info_fields(elem)

    # --- recurse into nested dicts / lists ---
    for value in elem.values():
        if isinstance(value, dict):
            _normalize_nested_dict(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _normalize_nested_dict(item)


#: What 3.0.1 allows on a CreationInfo. ``dataLicense`` moved to SpdxDocument
#: and ``profile`` became Element.profileConformance; spdx-tools 0.8.5 still
#: emits both, and ``CreationInfo_props`` is ``unevaluatedProperties: false``,
#: so either one invalidates every element carrying that CreationInfo.
_CREATION_INFO_DRAFT_ONLY = ("dataLicense", "profile")


def _strip_draft_creation_info_fields(d: dict[str, Any]) -> None:
    """Drop the pre-3.0.1 CreationInfo keys, if this dict is one."""
    if d.get("type") != "CreationInfo" and "specVersion" not in d:
        return
    for key in _CREATION_INFO_DRAFT_ONLY:
        d.pop(key, None)


def _normalize_nested_dict(d: dict[str, Any]) -> None:
    """Normalize ``@type`` → ``type`` in a nested dict (creationInfo, Hash, etc.)."""
    if "@type" in d:
        d["type"] = d.pop("@type")
    if d.get("type") == "ExternalReference":
        d["type"] = "ExternalRef"
    if "externalReferenceType" in d:
        d["externalRefType"] = d.pop("externalReferenceType")
    _strip_draft_creation_info_fields(d)
    # Recurse for deeper nesting (e.g. ExternalIdentifier inside verifiedUsing)
    for value in d.values():
        if isinstance(value, dict):
            _normalize_nested_dict(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _normalize_nested_dict(item)


def _normalize_passthrough_element(elem: dict[str, Any]) -> None:
    """Normalize keys on a passthrough element for output consistency.

    Like :func:`_normalize_serialized_element` but only touches keys
    (``@type`` → ``type``, ``@id`` → ``spdxId``).  ``@id`` is only
    renamed when the value is an IRI; blank-node identifiers (``_:…``)
    are left as ``@id`` because ``spdxId`` must be an IRI per the spec.
    """
    if "@type" in elem:
        elem["type"] = elem.pop("@type")
    if "@id" in elem:
        id_val = elem["@id"]
        if isinstance(id_val, str) and not id_val.startswith("_:"):
            elem["spdxId"] = elem.pop("@id")
    _strip_draft_creation_info_fields(elem)
    # Recurse into nested dicts (e.g. inline creationInfo, externalIdentifier)
    for value in elem.values():
        if isinstance(value, dict):
            _normalize_nested_dict(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _normalize_nested_dict(item)


def _restore_kept_raw_fields(payload: Payload, element_list: list[dict[str, Any]]) -> None:
    """Put back every value the library's enums could not hold."""
    if not isinstance(payload, Spdx3Payload) or not payload.kept_raw_fields:
        return
    for elem in element_list:
        spdx_id = elem.get("spdxId") or elem.get("@id")
        kept = payload.kept_raw_fields.get(spdx_id) if isinstance(spdx_id, str) else None
        if kept:
            elem.update(kept)


def _restore_document_fields(payload: Payload, element_list: list[dict[str, Any]]) -> None:
    """Write dataLicense and profileConformance onto the SpdxDocument.

    3.0.1 puts both there; the draft model spdx-tools 0.8.5 implements has no
    slot for either, so the parser stashed them on the payload. A document
    that declared no profileConformance does not gain one: claiming a profile
    asserts that every contained element meets its restrictions.
    """
    if not isinstance(payload, Spdx3Payload):
        return
    for elem in element_list:
        if elem.get("type") != "SpdxDocument":
            continue
        if payload.document_data_license:
            elem["dataLicense"] = payload.document_data_license
        if payload.document_profile_conformance:
            elem["profileConformance"] = list(payload.document_profile_conformance)
        return


#: The pre-3.0.1 licence fields spdx-tools 0.8.5 still models, and the
#: relationship type 3.0.1 expresses each of them as.
_DRAFT_LICENSE_FIELDS = {
    "declaredLicense": "hasDeclaredLicense",
    "concludedLicense": "hasConcludedLicense",
}

#: How a licence set composes its members into one expression string.
_LICENSE_SET_JOINERS = {
    "ConjunctiveLicenseSet": " AND ",
    "DisjunctiveLicenseSet": " OR ",
}

#: The agent the action names as the creator of elements it mints itself.
#: Stable, so two runs over the same input produce the same identifier rather
#: than a fresh uuid on every diff.
_ACTION_AGENT_ID = "https://sbomify.com/agents/sbomify-action"


def _binds_looser_than(text: str, joiner: str) -> bool:
    """Whether *text* carries an operator outside parentheses that is not *joiner*.

    SPDX binds AND tighter than OR, so joining members without parentheses
    silently re-reads the expression: a disjunction inside a conjunction comes
    back as "MIT OR Apache-2.0 AND GPL-2.0-only", which grants MIT on its own
    and is a different licence claim from the one the producer wrote.

    Depth-aware because a member may already be parenthesised, and
    space-delimited because an SPDX id cannot contain a space.
    """
    depth = 0
    for index, character in enumerate(text):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif depth == 0:
            for operator in _LICENSE_SET_JOINERS.values():
                if operator != joiner and text.startswith(operator, index):
                    return True
    return False


def _license_expression_text(value: Any) -> str | None:
    """The expression a serialized spdx-tools licence object denotes.

    ``None`` for NoAssertion and None: a relationship pointing at nothing
    asserts less than no relationship at all, and the reader treats both the
    same way.
    """
    if isinstance(value, str):
        return value.strip() or None
    if not isinstance(value, dict):
        return None
    ltype = value.get("type") or value.get("@type") or ""
    joiner = _LICENSE_SET_JOINERS.get(ltype)
    if joiner is not None:
        members = value.get("member") or value.get("members") or []
        if isinstance(members, (str, dict)):
            members = [members]
        kept = []
        for member in members:
            text = _license_expression_text(member)
            if not text:
                continue
            if _binds_looser_than(text, joiner):
                text = f"({text})"
            kept.append(text)
        return joiner.join(kept) if kept else None
    if ltype in ("NoAssertionLicense", "NoneLicense"):
        return None
    # licenseName before licenseId: the only objects that reach here are the
    # ones spdx3_license_from_string builds, and for anything that is not a
    # bare identifier it puts the verbatim expression in the name and a
    # synthesised "LicenseRef-MIT-OR-Apache-2.0" in the id. The library has no
    # LicenseExpression class to hold an expression properly, so reading the
    # id would publish that placeholder as the licence.
    for key in ("simplelicensing_licenseExpression", "licenseExpression", "licenseName", "licenseId"):
        text = value.get(key)
        if isinstance(text, str) and text.strip():
            return text.strip()
    return None


def _minted_license_id(kind: str, subject: str, relationship_type: str, expression: str) -> str:
    """A stable id for a licence element derived from a draft licence field.

    A fresh uuid4 here made writing the same payload twice produce different
    ids for the same assertion, so a document rewritten with no change to its
    licences still came back with a diff to read and discard. What the element
    says is what names it: same subject, same relationship, same expression,
    same id.
    """
    seed = "\x1f".join((kind, subject, relationship_type, expression))
    return f"urn:spdx.dev:{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


def _licenses_as_relationships(element_list: list[dict[str, Any]]) -> None:
    """Express the licence fields the way 3.0.1 does, as relationships.

    3.0.1 has no ``declaredLicense`` or ``concludedLicense`` property: it
    states a licence as a Relationship from the artifact to a licensing
    element. spdx-tools 0.8.5 still models both as fields, and every
    properties block is ``unevaluatedProperties: false``, so one of them
    invalidates the whole package.

    Being invalid is the smaller half. Left as a field, the licence is also
    unreadable: a reader that follows the spec, sbomify's own included, looks
    for the relationship and finds nothing, so the licence the action just
    worked out is one nobody downstream can see.
    """
    document = next((e for e in element_list if e.get("type") == "SpdxDocument"), None)
    added: list[dict[str, Any]] = []
    for elem in element_list:
        for field, relationship_type in _DRAFT_LICENSE_FIELDS.items():
            if field not in elem:
                continue
            expression = _license_expression_text(elem.pop(field))
            subject = elem.get("spdxId") or elem.get("@id")
            if not expression or not isinstance(subject, str):
                continue
            # Same provenance as the element being described, so this adds no
            # CreationInfo of its own to account for. Omitted rather than set
            # to null when that element has none: creationInfo is required on
            # every Element, and a null fails differently from an absence.
            provenance = {"creationInfo": elem["creationInfo"]} if elem.get("creationInfo") else {}
            license_id = _minted_license_id("expression", subject, relationship_type, expression)
            added.append(
                {
                    "type": "simplelicensing_LicenseExpression",
                    "spdxId": license_id,
                    **provenance,
                    "simplelicensing_licenseExpression": expression,
                }
            )
            added.append(
                {
                    "type": "Relationship",
                    "spdxId": _minted_license_id("relationship", subject, relationship_type, expression),
                    **provenance,
                    "relationshipType": relationship_type,
                    "from": subject,
                    "to": [license_id],
                }
            )
    if not added:
        return
    element_list.extend(added)
    # Only when the document already lists its elements: a document that did
    # not carry the key was not making that claim, and gaining it here would
    # assert a completeness nobody wrote.
    if document and isinstance(document.get("element"), list):
        document["element"].extend(e["spdxId"] for e in added)


def _creation_infos_in(node: Any) -> list[dict[str, Any]]:
    """Every CreationInfo reachable from *node*, standalone or inline."""
    found: list[dict[str, Any]] = []
    if isinstance(node, dict):
        if node.get("type") == "CreationInfo" or "specVersion" in node:
            found.append(node)
        for value in node.values():
            found.extend(_creation_infos_in(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_creation_infos_in(item))
    return found


def _document_creation_info_first(element_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every CreationInfo in *element_list*, the SpdxDocument's one leading.

    Serialization order otherwise decides which element speaks for a document
    that holds several disagreeing CreationInfos.
    """
    ordered: list[dict[str, Any]] = []
    document = next((e for e in element_list if e.get("type") == "SpdxDocument"), None)
    if document is not None:
        creation_info = document.get("creationInfo")
        if isinstance(creation_info, str):
            creation_info = next(
                (e for e in element_list if (e.get("@id") or e.get("spdxId")) == creation_info),
                None,
            )
        if isinstance(creation_info, dict):
            ordered.append(creation_info)
    ordered.extend(_creation_infos_in(element_list))
    return ordered


def _three_part_spec_version(from_context: str, element_list: list[dict[str, Any]]) -> str:
    """A ``specVersion`` the schema accepts, from a context that may be short.

    ``spdx.org/rdf/3.0/`` is a real context, so the version read off a URL can
    be two parts, and ``specVersion`` is a semver pattern that two parts do not
    match. The producer's own CreationInfo answers first: a document written
    against 3.0.1 under the 3.0 context is saying 3.0.1, and taking its word
    keeps what the action mints on the version the rest of the document is on.
    Only a document that states no patch number anywhere settles on ``.0``.

    The SpdxDocument is asked before the rest of the graph, for the reason
    :func:`extract_spdx3_version` asks it: a merged document carries another
    document's version on the element it took, and the answer here picks both
    the ``@context`` that gets written and the schema the result is held to.
    """
    if from_context.count(".") == 2:
        return from_context
    for creation_info in _document_creation_info_first(element_list):
        if _ACTION_AGENT_ID in (creation_info.get("createdBy") or []):
            continue
        stated = creation_info.get("specVersion")
        if isinstance(stated, str) and stated.startswith(f"{from_context}.") and stated.count(".") == 2:
            return stated
    return f"{from_context}.0"


def _fully_qualified_context(context_url: str, declared: str | None) -> str:
    """The context URL for *declared*, when the document offered a line alias.

    ``spdx.org/rdf/3.0/spdx-context.jsonld`` is served and byte-identical to
    the 3.0.1 one, so a producer may legitimately point at it, but the schemas
    pin ``@context`` with a const to a fully qualified URL and reject the
    alias. Writing it through meant the action emitted documents its own
    validation step then refused.

    Resolving it states no more than the document already did: the version
    comes from the document's own CreationInfos, and the two URLs address the
    same context.
    """
    if not declared:
        return context_url
    match = _SPDX3_VERSION_RE.search(context_url)
    if not match or match.group(1) == declared:
        return context_url
    return f"https://spdx.org/rdf/{declared}/spdx-context.jsonld"


def _align_minted_spec_versions(element_list: list[dict[str, Any]], context_url: str | None) -> str | None:
    """Make what the action mints declare the document's own spec version.

    :func:`make_spdx3_creation_info` hardcodes 3.0.1 because it has no document
    to ask. Since the writer preserves the ``@context`` the input declared, a
    3.0 document came back carrying 3.0.1 on every element the action added:
    the context and specVersion disagreement this module exists to prevent,
    walking back in through the minting path.

    Only the ones the action minted are touched, and they are identifiable
    precisely because make_spdx3_creation_info names the action as their
    creator. A CreationInfo the producer wrote keeps whatever it says.

    Returns the version everything minted now states, so the caller can hold
    the ``@context`` to the same answer.
    """
    if not context_url:
        return None
    match = _SPDX3_VERSION_RE.search(context_url)
    if not match:
        return None
    declared = _three_part_spec_version(match.group(1), element_list)
    for creation_info in _creation_infos_in(element_list):
        if _ACTION_AGENT_ID in (creation_info.get("createdBy") or []):
            creation_info["specVersion"] = declared
    return declared


def _add_the_action_agent(element_list: list[dict[str, Any]]) -> None:
    """Put the agent in the graph, if anything the action minted names it.

    ``CreationInfo_props`` requires createdBy with ``minItems: 1``, so an
    element the action adds with no creator named fails outright, and
    augmentation and enrichment add a Tool, an Organization and a Person each.
    :func:`make_spdx3_creation_info` names this agent; without the element
    itself in the graph the reference dangles.

    The agent is a SoftwareAgent rather than a Tool because 3.0.1 is strict
    about it: createdBy takes an Agent, and Tool is not one. Its own
    CreationInfo names itself, which is the bootstrap the spec's own examples
    use.

    A CreationInfo that arrived without a createdBy is left as it arrived.
    The action does not know who created that element, and naming itself
    there would state provenance nobody wrote.
    """
    naming = [ci for ci in _creation_infos_in(element_list) if _ACTION_AGENT_ID in (ci.get("createdBy") or [])]
    if not naming or any(e.get("spdxId") == _ACTION_AGENT_ID for e in element_list):
        return
    # Both taken from a CreationInfo that names the agent, so it declares
    # neither a different spec version nor a different moment from the
    # elements it is named on.
    #
    # The timestamp especially: minting one here made two runs over the same
    # input differ by a line, which is a diff a user has to read and discard
    # every time. The agent describes elements that were created at the
    # document's own moment, so that is the honest value as well as the stable
    # one. Only a document that states no time at all falls back to now.
    spec_version = next(
        (ci["specVersion"] for ci in naming if isinstance(ci.get("specVersion"), str)),
        "3.0.1",
    )
    created = next(
        (ci["created"] for ci in naming if isinstance(ci.get("created"), str) and ci["created"]),
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    element_list.append(
        {
            "type": "SoftwareAgent",
            "spdxId": _ACTION_AGENT_ID,
            "name": "sbomify-action",
            "creationInfo": {
                "type": "CreationInfo",
                "specVersion": spec_version,
                "created": created,
                "createdBy": [_ACTION_AGENT_ID],
            },
        }
    )


def write_spdx3_file(
    payload: Payload,
    file_path: str,
    context_url: str | None = None,
) -> None:
    """Write a :class:`Payload` to a JSON-LD ``.json`` file.

    Uses ``spdx_tools``' converter to serialize model objects, then wraps
    them with a ``@context``.

    Args:
        payload: The SPDX 3 payload to write.
        file_path: Output file path (will be overwritten).
        context_url: JSON-LD ``@context`` URL. Defaults to the one the input
            document declared, so a 3.0 document is not relabelled 3.0.1, and
            to the current release for a document built from nothing.
    """
    if context_url is None:
        context_url = getattr(payload, "context_url", None) or SPDX3_CONTEXT_URL

    element_list = convert_payload_to_json_ld_list_of_elements(payload)

    # Post-process serialized elements to fix spdx_tools converter output:
    # 1. Normalize @type→type, @id→spdxId (context aliases)
    # 2. Restore type prefixes (e.g. "Package" → "software_Package")
    # 3. Add software_ prefix to property names (e.g. "packageVersion" → "software_packageVersion")
    for elem in element_list:
        _normalize_serialized_element(elem)

    # Re-attach passthrough elements that were not parsed into model objects.
    # Deep-copy to avoid mutating the originals (normalization modifies in place,
    # so calling write_spdx3_file twice on the same payload would corrupt data).
    # Preserve blank-node @id values (e.g. "_:CreationInfo0") since spdxId must
    # be an IRI per the spec.
    passthrough = payload.passthrough_elements if isinstance(payload, Spdx3Payload) else []
    if passthrough:
        passthrough_copy = copy.deepcopy(passthrough)
        for elem in passthrough_copy:
            _normalize_passthrough_element(elem)
        element_list.extend(passthrough_copy)

    _restore_kept_raw_fields(payload, element_list)
    _restore_document_fields(payload, element_list)
    _licenses_as_relationships(element_list)
    _add_the_action_agent(element_list)
    # After the agent, so the one it mints for itself is aligned too.
    declared = _align_minted_spec_versions(element_list, context_url)
    context_url = _fully_qualified_context(context_url, declared)

    complete_dict = {"@context": context_url, "@graph": element_list}

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(complete_dict, f, indent=2)

    logger.debug(f"Wrote SPDX 3 JSON-LD to {file_path}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_spdx3_document(payload: Payload) -> SpdxDocument | None:
    """Find the :class:`SpdxDocument` element in a payload."""
    for element in payload.get_full_map().values():
        if isinstance(element, SpdxDocument):
            return element
    return None


def get_spdx3_packages(payload: Payload) -> list[Package]:
    """Return all :class:`Package` elements from a payload."""
    return [e for e in payload.get_full_map().values() if isinstance(e, Package)]


def get_spdx3_root_package(payload: Payload) -> Package | None:
    """Find the root package (referenced by ``SpdxDocument.root_element``).

    Returns the first Package found among the document's ``root_element``
    references, or ``None``.
    """
    doc = get_spdx3_document(payload)
    if doc is None:
        return None

    for root_id in doc.root_element:
        try:
            element = payload.get_element(root_id)
            if isinstance(element, Package):
                return element
        except KeyError:
            continue

    # Fallback: return first package
    packages = get_spdx3_packages(payload)
    return packages[0] if packages else None


def spdx3_ids_stating_a_license(payload: Payload, relationship_type: str = "hasDeclaredLicense") -> set[str]:
    """Every spdxId that already states a licence through *relationship_type*.

    One pass over the payload, for callers asking about many packages.
    :func:`spdx3_license_relationships` answers for one and returns the
    relationship objects, which a caller replacing a licence needs; asking it
    per package walks the whole payload each time, and an enrichment run over
    a large document is packages times elements of that.
    """
    kept = payload.kept_raw_fields if isinstance(payload, Spdx3Payload) else {}
    stating: set[str] = set()
    for element in payload.get_full_map().values():
        if not isinstance(element, Relationship):
            continue
        raw = kept.get(element.spdx_id, {}).get("relationshipType")
        name = raw or _REL_TYPE_NAMES.get(element.relationship_type)
        if name == relationship_type and isinstance(element.from_element, str):
            stating.add(element.from_element)
    return stating


def spdx3_license_relationships(
    payload: Payload,
    spdx_id: str,
    relationship_type: str = "hasDeclaredLicense",
) -> list[Relationship]:
    """The relationships through which *spdx_id* already states a licence.

    3.0.1 states a licence as a Relationship and spdx-tools has no field for
    it, so a package whose author declared one parses with declared_license
    unset. Read as "no licence", that is how the action came to add a second,
    possibly contradicting declaration to a package that already had one.
    """
    kept = payload.kept_raw_fields if isinstance(payload, Spdx3Payload) else {}
    found = []
    for element in payload.get_full_map().values():
        if not isinstance(element, Relationship) or element.from_element != spdx_id:
            continue
        raw = kept.get(element.spdx_id, {}).get("relationshipType")
        # The raw value when the library's enum could not hold it, which is
        # the case for every licence relationship in 3.0.1; the enum's own
        # spelling otherwise, so this keeps working if that changes.
        if (raw or _REL_TYPE_NAMES.get(element.relationship_type)) == relationship_type:
            found.append(element)
    return found


def make_spdx3_creation_info(
    created_by: list[str] | None = None,
) -> CreationInfo:
    """Create a standard :class:`CreationInfo` for SPDX 3 documents."""
    return CreationInfo(
        spec_version=Version("3.0.1"),
        created=datetime.now(timezone.utc),
        # Not an empty list: createdBy is required with minItems 1, so an
        # element minted without a creator named fails the schema and takes
        # every element sharing its CreationInfo down with it.
        created_by=created_by or [_ACTION_AGENT_ID],
        profile=[ProfileIdentifierType.CORE, ProfileIdentifierType.SOFTWARE],
        data_license="CC0-1.0",
    )


def make_spdx3_spdx_id(prefix: str = "urn:spdx.dev:") -> str:
    """Generate a unique SPDX ID for SPDX 3 elements."""
    return f"{prefix}{uuid.uuid4()}"


def spdx3_license_from_string(license_str: str) -> ListedLicense | CustomLicense | NoAssertionLicense | NoneLicense:
    """Convert a license string to an SPDX 3 licensing model object.

    Handles SPDX license identifiers, NOASSERTION, and NONE.
    For complex expressions, wraps in a CustomLicense.
    """
    if not license_str or license_str.upper() == "NOASSERTION":
        return NoAssertionLicense()
    if license_str.upper() == "NONE":
        return NoneLicense()

    # If it looks like a simple SPDX ID (no spaces, no operators), use ListedLicense
    if " " not in license_str and "(" not in license_str:
        return ListedLicense(
            license_id=license_str,
            license_name=license_str,
            license_text="",
        )

    # Complex expression — wrap as custom
    # SPDX license IDs allow only [a-zA-Z0-9.-] after "LicenseRef-"
    sanitized = re.sub(r"[^a-zA-Z0-9.\-]", "-", license_str)
    return CustomLicense(
        license_id=f"LicenseRef-{sanitized}",
        license_name=license_str,
        license_text=license_str,
    )


def spdx3_licenses_from_list(
    license_ids: list[str],
) -> DisjunctiveLicenseSet | ListedLicense | CustomLicense | NoAssertionLicense | NoneLicense:
    """Convert a list of license ID strings to an SPDX 3 license field.

    Single license → :class:`ListedLicense`.
    Multiple → :class:`DisjunctiveLicenseSet`.
    """
    if not license_ids:
        return NoAssertionLicense()

    members = [spdx3_license_from_string(lid) for lid in license_ids]
    if len(members) == 1:
        return members[0]

    # Filter out NoAssertion/None for the set
    valid = [m for m in members if not isinstance(m, (NoAssertionLicense, NoneLicense))]
    if not valid:
        return NoAssertionLicense()
    if len(valid) == 1:
        return valid[0]

    return DisjunctiveLicenseSet(member=valid)
