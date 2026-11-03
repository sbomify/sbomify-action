"""Control-flow exceptions shared by the enrichment sources."""


class TransientSourceError(Exception):
    """A source failed for a reason that says nothing about the package.

    A timeout, a connection reset or an HTTP 429 means "ask again later", not
    "this package has no metadata". The two are worth distinguishing because
    the registry persists results: recording a throttled response as a miss
    would suppress that package's enrichment on every subsequent run until the
    entry expired, which is precisely the silent data loss the cache is meant
    to avoid.

    Sources already made this distinction informally -- ``pypi.py`` returns
    None on a timeout with the comment "Do not cache so a later component can
    re-try", and signals it by declining to write its own in-memory cache. That
    signal never reached the registry, which saw an ordinary None. Raising
    makes it explicit and machine-readable.

    Raised in place of returning None, so the registry's existing
    continue-to-the-next-source behaviour is unchanged.
    """
