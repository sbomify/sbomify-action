"""Persistent, cross-run cache for enrichment lookups.

Each source keeps its own in-process dictionary, which only helps within a
single run. Enrichment is dominated by repeated lookups of the same
coordinates -- CI re-scans a dependency set that barely changes between
builds -- so without something on disk every run re-asks every upstream for
answers it already had. That is the bulk of the request volume, and it is what
gets a shared CI egress IP rate-limited.

This module sits behind the registry's call to ``source.fetch`` and persists
the result, so a coordinate is fetched once and reused until it expires.

Design notes:

* **Negative results are cached too, but briefly.** A miss usually means the
  package is genuinely absent, and re-asking every run is what generates load.
  But packages do get added, so a miss expires far sooner than a hit.
* **Failures are never cached here.** The registry only offers a result to the
  cache when the fetch completed; a timeout or an HTTP 429 must not be
  persisted as "no data", or throttling would silently degrade every
  subsequent run's output.
* **Cache errors are never fatal.** Any problem reading or writing degrades to
  "no cache" rather than failing enrichment. A corrupt cache should cost
  network calls, not the run.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import asdict, fields
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from sbomify_action.logging_config import logger

from .metadata import NormalizedMetadata

# A definition for a fixed coordinate rarely changes -- an upstream curation is
# the usual reason -- so hits can be held for a long time.
DEFAULT_HIT_TTL_SECONDS = 30 * 24 * 3600  # 30 days
# Misses expire quickly so a newly published package is picked up on the next
# run rather than being remembered as absent for a month.
DEFAULT_MISS_TTL_SECONDS = 24 * 3600  # 1 day

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    source     TEXT NOT NULL,
    key        TEXT NOT NULL,
    payload    TEXT,
    fetched_at REAL NOT NULL,
    PRIMARY KEY (source, key)
)
"""

_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None
_disabled: Optional[bool] = None


def _is_disabled() -> bool:
    global _disabled
    if _disabled is None:
        _disabled = os.environ.get("SBOMIFY_ENRICHMENT_CACHE", "").strip().lower() in ("0", "off", "false", "no")
    return _disabled


def _ttl(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.debug(f"Ignoring non-integer {name}={raw!r}")
        return default
    return value if value >= 0 else default


def cache_dir() -> Path:
    """Resolve the cache directory, matching the license-db convention.

    ``SBOMIFY_CACHE_DIR`` wins, then ``XDG_CACHE_HOME``, then ``~/.cache``.
    """
    explicit = os.environ.get("SBOMIFY_CACHE_DIR")
    if explicit:
        return Path(explicit) / "enrichment"
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "sbomify" / "enrichment"


def _connect() -> Optional[sqlite3.Connection]:
    """Open (once) the cache database, or return None if it is unusable."""
    global _conn
    if _conn is not None:
        return _conn
    try:
        directory = cache_dir()
        directory.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: the registry may be driven from a worker
        # thread; access is serialised by _lock regardless.
        conn = sqlite3.connect(str(directory / "metadata.sqlite"), timeout=5.0, check_same_thread=False)
        # WAL lets concurrent runs share one cache file without blocking.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(_SCHEMA)
        conn.commit()
        _conn = conn
        logger.debug(f"Enrichment cache at {directory / 'metadata.sqlite'}")
    except Exception as e:  # pragma: no cover - depends on the filesystem
        logger.debug(f"Enrichment cache unavailable, continuing without it: {e}")
        _conn = None
    return _conn


def _serialize(metadata: Optional[NormalizedMetadata]) -> Optional[str]:
    if metadata is None:
        return None
    return json.dumps(asdict(metadata), separators=(",", ":"))


def _deserialize(payload: Optional[str]) -> Optional[NormalizedMetadata]:
    if payload is None:
        return None
    data: Dict[str, Any] = json.loads(payload)
    # Tolerate a cache written by a build whose dataclass had other fields.
    known = {f.name for f in fields(NormalizedMetadata)}
    return NormalizedMetadata(**{k: v for k, v in data.items() if k in known})


def get(source: str, key: str) -> Tuple[bool, Optional[NormalizedMetadata]]:
    """Look up a cached result.

    Returns ``(hit, metadata)``. ``hit`` distinguishes a cached negative result
    (``(True, None)``) from nothing cached at all (``(False, None)``), which the
    caller needs in order to skip the network for a known-absent package.
    """
    if _is_disabled():
        return False, None
    with _lock:
        conn = _connect()
        if conn is None:
            return False, None
        try:
            row = conn.execute(
                "SELECT payload, fetched_at FROM entries WHERE source = ? AND key = ?",
                (source, key),
            ).fetchone()
        except Exception as e:  # pragma: no cover - corrupt db
            logger.debug(f"Enrichment cache read failed for {source}/{key}: {e}")
            return False, None

    if row is None:
        return False, None

    payload, fetched_at = row
    ttl = (
        _ttl("SBOMIFY_ENRICHMENT_CACHE_TTL", DEFAULT_HIT_TTL_SECONDS)
        if payload is not None
        else _ttl("SBOMIFY_ENRICHMENT_CACHE_MISS_TTL", DEFAULT_MISS_TTL_SECONDS)
    )
    if ttl and (time.time() - fetched_at) > ttl:
        return False, None

    try:
        return True, _deserialize(payload)
    except Exception as e:
        logger.debug(f"Discarding unreadable cache entry for {source}/{key}: {e}")
        return False, None


def set(source: str, key: str, metadata: Optional[NormalizedMetadata]) -> None:
    """Store a completed lookup. Only call this when the fetch actually ran."""
    if _is_disabled():
        return
    with _lock:
        conn = _connect()
        if conn is None:
            return
        try:
            conn.execute(
                "INSERT OR REPLACE INTO entries (source, key, payload, fetched_at) VALUES (?, ?, ?, ?)",
                (source, key, _serialize(metadata), time.time()),
            )
            conn.commit()
        except Exception as e:  # pragma: no cover - disk full, readonly fs
            logger.debug(f"Enrichment cache write failed for {source}/{key}: {e}")


def clear() -> None:
    """Drop every cached entry."""
    with _lock:
        conn = _connect()
        if conn is None:
            return
        try:
            conn.execute("DELETE FROM entries")
            conn.commit()
        except Exception as e:  # pragma: no cover
            logger.debug(f"Enrichment cache clear failed: {e}")


def close() -> None:
    """Close the connection and reset module state (used by tests)."""
    global _conn, _disabled
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:  # pragma: no cover
                pass
        _conn = None
        _disabled = None


def stats() -> Dict[str, int]:
    """Entry counts, for logging how much of a run was served from cache."""
    with _lock:
        conn = _connect()
        if conn is None:
            return {}
        try:
            total = conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]
            negative = conn.execute("SELECT COUNT(*) FROM entries WHERE payload IS NULL").fetchone()[0]
        except Exception:  # pragma: no cover
            return {}
    return {"entries": total, "negative": negative, "positive": total - negative}
