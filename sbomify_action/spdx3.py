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

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SPDX3_CONTEXT_URL = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

# Regex to detect spdx.org/rdf/3.x context
_SPDX3_CONTEXT_RE = re.compile(r"spdx\.org/rdf/3")

# Regex to extract version from context URL
_SPDX3_VERSION_RE = re.compile(r"spdx\.org/rdf/(\d+\.\d+\.\d+)/")

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

# The spdx_tools writer serialises enum names via snake_case_to_camel_case
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

# Map RelationshipType
_REL_TYPES: dict[str, RelationshipType] = {}
for _e in RelationshipType:
    _REL_TYPES[_s2c(_e.name).lower()] = _e
    _REL_TYPES[_e.name.lower()] = _e

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


def is_spdx3(data: dict) -> bool:
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


def extract_spdx3_version(data: dict) -> str | None:
    """Extract the SPDX 3 spec version from the ``@context`` URL.

    Returns e.g. ``"3.0.1"`` or ``None``.
    """
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


def _get_sw(elem: dict, unprefixed: str, prefixed: str | None = None):
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


def _parse_creation_info(ci_dict: dict) -> CreationInfo:
    """Parse a nested ``creationInfo`` dict into a :class:`CreationInfo`."""
    spec_str = ci_dict.get("specVersion", "3.0.1")
    spec_version = Version(spec_str)

    created_str = ci_dict.get("created")
    if created_str:
        # Handle ISO-8601 with or without timezone
        created_str = created_str.replace("Z", "+00:00")
        created = datetime.fromisoformat(created_str)
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


def _parse_external_reference(ref_dict: dict) -> ExternalReference:
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


def _parse_external_identifier(eid_dict: dict) -> ExternalIdentifier:
    """Parse an external identifier dict."""
    eid_type_str = eid_dict.get("externalIdentifierType", "")
    eid_type = _EXT_ID_TYPES.get(eid_type_str.lower(), ExternalIdentifierType.OTHER)

    return ExternalIdentifier(
        external_identifier_type=eid_type,
        identifier=eid_dict.get("identifier", ""),
        comment=eid_dict.get("comment"),
    )


def _parse_hash(h_dict: dict) -> Hash:
    """Parse a hash/integrity dict."""
    alg_str = h_dict.get("algorithm", "").lower()
    algorithm = _HASH_ALGORITHMS.get(alg_str, HashAlgorithm.OTHER)
    return Hash(algorithm=algorithm, hash_value=h_dict.get("hashValue", ""))


def _parse_common_fields(elem: dict, creation_info_map: dict[str, CreationInfo] | None = None) -> dict:
    """Extract fields common to all Element subclasses."""
    result: dict = {}

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


def _parse_software_artifact_fields(elem: dict, fields: dict) -> None:
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
            logger.warning("Unrecognized primaryPurpose value %r; omitting", pp)

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
            fields[py_key] = datetime.fromisoformat(date_str)

    # Standards — context uses "standardName", spdx_tools may output "standard"
    stds = elem.get("standardName") or elem.get("standard", [])
    if isinstance(stds, str):
        stds = [stds]
    if stds:
        fields["standard"] = stds


def _parse_package(elem: dict, ci_map: dict[str, CreationInfo] | None = None) -> Package:
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


def _parse_file(elem: dict, ci_map: dict[str, CreationInfo] | None = None) -> SpdxFile:
    """Parse a File element."""
    fields = _parse_common_fields(elem, ci_map)
    _parse_software_artifact_fields(elem, fields)

    # Ensure required 'name' field
    if "name" not in fields:
        fields["name"] = "unknown"

    return SpdxFile(**fields)


def _parse_spdx_document(elem: dict, ci_map: dict[str, CreationInfo] | None = None) -> SpdxDocument:
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


def _parse_relationship(elem: dict, ci_map: dict[str, CreationInfo] | None = None) -> Relationship:
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


def _parse_agent(elem: dict, cls: type, ci_map: dict[str, CreationInfo] | None = None) -> Organization | Person | Tool:
    """Parse an Organization, Person, or Tool element."""
    fields = _parse_common_fields(elem, ci_map)
    return cls(**fields)


def parse_spdx3_file(file_path: str) -> Payload:
    """Parse an SPDX 3 JSON-LD file into a :class:`Payload`.

    Maps ``@graph`` elements by their ``type`` (``@type``) to the
    corresponding ``spdx_tools.spdx3.model`` classes.

    Args:
        file_path: Path to the SPDX 3 JSON-LD ``.json`` file.

    Returns:
        Populated :class:`Payload` with all parsed elements.

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


def parse_spdx3_data(data: dict) -> Payload:
    """Parse SPDX 3 JSON-LD data (already loaded) into a :class:`Payload`.

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
    for elem in graph:
        if not isinstance(elem, dict):
            continue
        elem_type = elem.get("type") or elem.get("@type", "")
        if elem_type == "CreationInfo":
            ci_id = elem.get("@id") or elem.get("spdxId")
            if ci_id:
                ci_map[ci_id] = _parse_creation_info(elem)

    # Second pass: parse all other elements
    payload = Payload()
    passthrough: list[dict] = []

    for elem in graph:
        if not isinstance(elem, dict):
            continue

        elem_type = elem.get("type") or elem.get("@type", "")
        # Normalise aliases
        elem_type = _TYPE_ALIASES.get(elem_type, elem_type)

        try:
            if elem_type == "SpdxDocument":
                payload.add_element(_parse_spdx_document(elem, ci_map))
            elif elem_type == "Package":
                payload.add_element(_parse_package(elem, ci_map))
            elif elem_type == "File":
                payload.add_element(_parse_file(elem, ci_map))
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
            elif elem_type == "CreationInfo":
                # Already parsed in first pass; preserve standalone CreationInfo
                # elements (those with @id) so passthrough elements referencing
                # them by IRI string survive the roundtrip.
                if elem.get("@id") or elem.get("spdxId"):
                    passthrough.append(elem)
            else:
                logger.debug(f"Passing through unhandled SPDX 3 element type: {elem_type}")
                passthrough.append(elem)
        except Exception as e:
            spdx_id = elem.get("@id") or elem.get("spdxId", "unknown")
            logger.warning(f"Failed to parse SPDX 3 element {spdx_id} (type={elem_type}): {e}")
            passthrough.append(elem)

    # Attach passthrough elements so the writer can re-emit them verbatim.
    payload._passthrough_elements = passthrough  # type: ignore[attr-defined]

    return payload


# ---------------------------------------------------------------------------
# Writer  (Payload → JSON-LD file)
# ---------------------------------------------------------------------------


def _normalize_serialized_element(elem: dict) -> None:
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

    # --- recurse into nested dicts / lists ---
    for value in elem.values():
        if isinstance(value, dict):
            _normalize_nested_dict(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _normalize_nested_dict(item)


def _normalize_nested_dict(d: dict) -> None:
    """Normalize ``@type`` → ``type`` in a nested dict (creationInfo, Hash, etc.)."""
    if "@type" in d:
        d["type"] = d.pop("@type")
    # Recurse for deeper nesting (e.g. ExternalIdentifier inside verifiedUsing)
    for value in d.values():
        if isinstance(value, dict):
            _normalize_nested_dict(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _normalize_nested_dict(item)


def _normalize_passthrough_element(elem: dict) -> None:
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
    # Recurse into nested dicts (e.g. inline creationInfo, externalIdentifier)
    for value in elem.values():
        if isinstance(value, dict):
            _normalize_nested_dict(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _normalize_nested_dict(item)


def write_spdx3_file(
    payload: Payload,
    file_path: str,
    context_url: str = SPDX3_CONTEXT_URL,
) -> None:
    """Write a :class:`Payload` to a JSON-LD ``.json`` file.

    Uses ``spdx_tools``' converter to serialise model objects, then wraps
    them with the official ``@context`` URL.

    Args:
        payload: The SPDX 3 payload to write.
        file_path: Output file path (will be overwritten).
        context_url: JSON-LD ``@context`` URL.
    """
    element_list = convert_payload_to_json_ld_list_of_elements(payload)

    # Post-process serialized elements to fix spdx_tools converter output:
    # 1. Normalize @type→type, @id→spdxId (context aliases)
    # 2. Restore type prefixes (e.g. "Package" → "software_Package")
    # 3. Add software_ prefix to property names (e.g. "packageVersion" → "software_packageVersion")
    for elem in element_list:
        _normalize_serialized_element(elem)

    # Re-attach passthrough elements that were not parsed into model objects.
    # Normalize their keys for consistency, but preserve blank-node @id values
    # (e.g. "_:CreationInfo0") since spdxId must be an IRI per the spec.
    passthrough = getattr(payload, "_passthrough_elements", [])
    if passthrough:
        for elem in passthrough:
            _normalize_passthrough_element(elem)
        element_list.extend(passthrough)

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


def make_spdx3_creation_info(
    created_by: list[str] | None = None,
) -> CreationInfo:
    """Create a standard :class:`CreationInfo` for SPDX 3 documents."""
    return CreationInfo(
        spec_version=Version("3.0.1"),
        created=datetime.now(timezone.utc),
        created_by=created_by or [],
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
