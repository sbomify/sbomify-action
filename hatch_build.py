"""Freeze lockfile-derived tool versions into every distribution we build.

``tools.toml`` points at the manifests that own each version -- ``uv.lock`` for
uv -- so Dependabot maintains them and there is no bespoke version file to keep
in step. Those manifests are not part of the Python package, so an installed
copy cannot read them: the path resolves under site-packages, where they do not
exist, and ``load_tools()`` fails at import time.

``scripts/freeze_tool_versions.py`` resolves them to literals, and the image
build has always run it before ``uv build``. That left every other way of
building the package broken -- ``uv build``, ``pip install .``,
``pip install git+https://...`` -- with a crash naming a lockfile the user has
no reason to have heard of. Doing it here instead means a distribution is
frozen because it was built, not because whoever built it remembered a step.

The source tree is never touched: the frozen manifest is written to a temporary
file and force-included in its place, which is why the build targets exclude
``sbomify_action/tools.toml`` from the files they collect.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

MANIFEST_PATH = "sbomify_action/tools.toml"
FREEZER = "scripts/freeze_tool_versions.py"


class FreezeToolVersionsHook(BuildHookInterface):
    """Substitute a frozen ``tools.toml`` for the one in the source tree."""

    PLUGIN_NAME = "freeze-tool-versions"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        """Write the frozen manifest and point the build at it."""
        root = Path(self.root)
        manifest = root / MANIFEST_PATH
        if not manifest.is_file():
            raise RuntimeError(f"{MANIFEST_PATH} is missing; the package cannot be built without it")

        # Held on the instance so it outlives this method: the temporary
        # directory is read while the artifact is being written, and cleaned up
        # in finalize().
        self._staging = tempfile.TemporaryDirectory(prefix="sbomify-manifest-")
        frozen = Path(self._staging.name) / "tools.toml"
        shutil.copy2(manifest, frozen)

        if self._freeze(root, frozen) != 0:
            raise RuntimeError(f"could not resolve tool versions; see {FREEZER}")

        build_data.setdefault("force_include", {})[str(frozen)] = MANIFEST_PATH

    def finalize(self, version: str, build_data: dict[str, Any], artifact_path: str) -> None:
        """Drop the staged manifest once the artifact has been written."""
        staging = getattr(self, "_staging", None)
        if staging is not None:
            staging.cleanup()
            self._staging = None

    def _freeze(self, root: Path, manifest: Path) -> int:
        """Run the freezer against ``manifest``, loaded from its path.

        Imported rather than reimplemented: the resolution rules belong to that
        script, and a second copy here would be free to drift from the one CI
        checks with ``--check``.
        """
        script = root / FREEZER
        if not script.is_file():
            # Building from an sdist whose manifest is already frozen. Anything
            # else has no versions to write and must not be published.
            if "version_from" in manifest.read_text():
                raise RuntimeError(f"{FREEZER} is missing and {MANIFEST_PATH} is not frozen")
            return 0

        spec = importlib.util.spec_from_file_location("_sbomify_freeze_tool_versions", script)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"could not load {FREEZER}")
        module = importlib.util.module_from_spec(spec)
        # The script imports sbomify_action to resolve versions, and the build
        # backend runs in its own environment where the project is not
        # installed.
        sys.path.insert(0, str(root))
        try:
            spec.loader.exec_module(module)
            return int(module.freeze(manifest))
        finally:
            sys.path.remove(str(root))
