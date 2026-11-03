"""Secret scrubbing for text that may end up in logs or exception messages.

Upstreams occasionally echo request payloads or include credentials in debug
responses, and CI log lines outlive the 15-minute lifetime of an OIDC-minted
token. Anything derived from a remote response body goes through here first.
"""

import re

# Redact Bearer tokens and JWT-shaped substrings.
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-+/=]+")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")


def scrub_secrets(text: str) -> str:
    """Replace anything that looks like a Bearer token or JWT with a placeholder."""
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _JWT_RE.sub("[REDACTED-JWT]", text)
    return text
