"""TEA (Transparency Exchange API) CLI subcommand group.

Re-exports libtea's CLI as ``sbomify-action tea``, providing access to
TEA server discovery, search, inspect, download, and conformance testing
directly from the sbomify-action CLI.

All subcommands accept --base-url/--domain for server selection,
--token/--auth for authentication, and --json for machine-readable output.
"""

from libtea.cli import app as tea_group

__all__ = ["tea_group"]
