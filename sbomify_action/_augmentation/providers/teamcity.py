"""Deprecated home of the TeamCity provider.

The extraction logic moved to ``sbomify_action._runtime.platforms.teamcity``,
where TeamCity is a CI platform like any other. Everything is re-exported here,
including the private parsing helpers, because they were reachable from this
path and this project does not break imports.

Prefer the new location; this module is a forwarding shim.
"""

from ..._runtime.platforms.teamcity import (
    TeamCityPlatform,
    _decode_properties_bytes,
    _load_teamcity_properties,
    _looks_like_git_root,
    _merge_surrogates,
    _normalize_root_id_for_env,
    _parse_java_properties,
    _read_properties_file,
    _select_commit_sha,
    _select_ref,
    _select_repo_url,
    _split_key_value,
    _unescape,
    _url_looks_like_git,
)
from .._runtime_shims import TeamCityProvider

# The private helpers are listed deliberately: they were importable from this
# module, so they stay importable from it.
__all__ = [
    "TeamCityPlatform",
    "TeamCityProvider",
    "_decode_properties_bytes",
    "_load_teamcity_properties",
    "_looks_like_git_root",
    "_merge_surrogates",
    "_normalize_root_id_for_env",
    "_parse_java_properties",
    "_read_properties_file",
    "_select_commit_sha",
    "_select_ref",
    "_select_repo_url",
    "_split_key_value",
    "_unescape",
    "_url_looks_like_git",
]
