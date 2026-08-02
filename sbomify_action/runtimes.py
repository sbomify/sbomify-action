"""Fetch pinned tool runtimes at run time, into an unprivileged prefix.

Some tools are needed by only a minority of runs (cosign and crane are used
solely for Chainguard attestations; JDK/Maven only for Java dependency
resolution). Baking them into the image makes every user download them,
and the historical alternative -- ``apt-get install`` at run time -- forces
the container to run as root and pins nothing.

This module takes the third path: a self-contained runtime is downloaded on
first use, verified against a SHA256 recorded here at build time, and
unpacked into a cache directory. Tools are confined to that prefix and
reached through ``PATH``; nothing is installed system-wide, so no privileges
are required. This is the same model as a Python virtualenv, not a chroot --
``chroot(2)`` needs ``CAP_SYS_CHROOT``, which a non-root process does not
have.

The hash is the whole trust anchor. We deliberately do not verify
signatures: a pinned digest proves "these are the exact bytes we tested
against", which is a stronger claim than "the vendor signed something", and
it needs no verifier in the base image -- verifying cosign's signature would
otherwise require shipping cosign. The trade-off is that runtimes cannot be
updated without a release, which is a feature for a tool whose output is a
provenance document.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import tarfile
import tempfile
import threading
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import requests

from .exceptions import SBOMGenerationError
from .logging_config import logger
from .tool_manifest import STAGE_RUNTIME, tools_for_stage

# Download tuning. Runtimes range from ~12MB (crane) to ~190MB (a full JDK),
# so the read timeout is generous while the connect timeout stays short.
_CONNECT_TIMEOUT = 10
_READ_TIMEOUT = 120
_CHUNK = 1024 * 1024

# Marker written into a runtime prefix once it is fully unpacked. Extraction
# happens in a scratch directory and is moved into place atomically, so a
# prefix that exists but lacks this file is from an older/partial layout and
# is re-fetched rather than trusted.
_READY = ".sbomify-runtime-ready"


@dataclass(frozen=True)
class Asset:
    """A single downloadable artifact and the digest it must have."""

    url: str
    algorithm: str
    digest: str


@dataclass(frozen=True)
class RuntimeSpec:
    """A tool runtime that can be fetched and confined to a prefix.

    Attributes:
        name: Key used by callers, e.g. "cosign".
        version: Pinned version, surfaced in logs and cache paths.
        assets: Per-arch artifact, keyed by "amd64"/"arm64".
        kind: "raw" for a bare executable, otherwise the archive format.
        member: For archives, the single file to keep. None keeps the tree.
        bin_subdir: Directory inside the prefix to place on PATH.
    """

    name: str
    version: str
    assets: dict[str, Asset]
    kind: str = "raw"
    member: str | None = None
    bin_subdir: str = ""
    strip_container: bool = False
    env: dict[str, str] = field(default_factory=dict)


# Runtime specs are built from tools.toml rather than written out here, so
# that versions, URLs and digests live in exactly one place -- see
# tool_manifest.py for why that matters once the build and runtime SBOMs
# describe different sets of software.
def _load_runtimes() -> dict[str, RuntimeSpec]:
    specs: dict[str, RuntimeSpec] = {}
    for name, tool in tools_for_stage(STAGE_RUNTIME).items():
        assert tool.assets is not None  # guaranteed by the manifest validation
        specs[name] = RuntimeSpec(
            name=name,
            version=tool.version,
            kind=tool.kind,
            member=tool.member,
            strip_container=tool.strip_container,
            bin_subdir=tool.bin_subdir,
            env=tool.env,
            assets={arch: Asset(url=a.url, algorithm=a.algorithm, digest=a.digest) for arch, a in tool.assets.items()},
        )
    return specs


RUNTIMES: dict[str, RuntimeSpec] = _load_runtimes()

_locks: dict[str, threading.Lock] = {name: threading.Lock() for name in RUNTIMES}
_resolved: dict[str, Path] = {}


def current_arch() -> str:
    """Map the host machine to the arch keys used in RUNTIMES."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    raise SBOMGenerationError(f"No pinned tool runtimes for architecture {platform.machine()!r}")


def cache_root() -> Path:
    """Return the first writable cache location.

    Ordered so that operators can pin the cache somewhere persistent (and so
    CI can point it at a restored cache), falling back to locations that
    exist even when the container runs as a uid with no home directory --
    which is the normal case once the image stops running as root.
    """
    candidates = []
    if explicit := os.environ.get("SBOMIFY_TOOL_CACHE"):
        candidates.append(Path(explicit))
    if xdg := os.environ.get("XDG_CACHE_HOME"):
        candidates.append(Path(xdg) / "sbomify" / "runtimes")
    if home := os.environ.get("HOME"):
        candidates.append(Path(home) / ".cache" / "sbomify" / "runtimes")
    candidates.append(Path(tempfile.gettempdir()) / "sbomify-runtimes")

    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            probe = candidate / ".write-probe"
            probe.touch()
            probe.unlink()
            return candidate
        except OSError:
            continue

    raise SBOMGenerationError("No writable directory for tool runtimes. Set SBOMIFY_TOOL_CACHE to a writable path.")


def _download_verified(asset: Asset, dest: Path) -> None:
    """Stream an asset to dest, failing unless it hashes to the pinned digest.

    Hashing streams alongside the download so a 190MB JDK never has to be
    held in memory, and the file is only moved into place after the digest
    matches -- a mismatched download can never be observed at ``dest``.
    """
    digest = hashlib.new(asset.algorithm)
    scratch = dest.with_suffix(dest.suffix + ".part")
    try:
        with requests.get(asset.url, stream=True, timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT)) as response:
            response.raise_for_status()
            with scratch.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=_CHUNK):
                    if chunk:
                        digest.update(chunk)
                        handle.write(chunk)
    except requests.RequestException as exc:
        scratch.unlink(missing_ok=True)
        raise SBOMGenerationError(f"Failed to download {asset.url}: {exc}") from exc

    actual = digest.hexdigest()
    if actual != asset.digest:
        scratch.unlink(missing_ok=True)
        raise SBOMGenerationError(
            f"Checksum mismatch for {asset.url}: expected {asset.algorithm}:{asset.digest}, "
            f"got {actual}. Refusing to use the download."
        )
    scratch.replace(dest)


def _extract(archive: Path, spec: RuntimeSpec, into: Path) -> None:
    """Unpack an archive, keeping only spec.member when one is named."""
    if spec.kind == "zip":
        with zipfile.ZipFile(archive) as zf:
            names = [spec.member] if spec.member else zf.namelist()
            for name in names:
                _reject_traversal(name)
            zf.extractall(into, members=names)
        return

    if spec.kind == "tar.gz":
        opener = tarfile.open(archive, "r:gz")
    elif spec.kind == "tar.xz":
        opener = tarfile.open(archive, "r:xz")
    else:
        opener = tarfile.open(archive, "r:*")

    with opener as tf:
        members = [tf.getmember(spec.member)] if spec.member else tf.getmembers()
        for member in members:
            _reject_traversal(member.name)
        # filter="data" strips setuid bits, absolute paths and links pointing
        # outside the destination. Available from 3.12 (and 3.10/3.11 point
        # releases); _reject_traversal covers interpreters without it.
        if hasattr(tarfile, "data_filter"):
            tf.extractall(into, members=members, filter="data")
        else:  # pragma: no cover - only on interpreters predating the backport
            tf.extractall(into, members=members)


def _reject_traversal(name: str) -> None:
    """Refuse archive entries that would escape the extraction directory."""
    if name.startswith("/") or ".." in Path(name).parts:
        raise SBOMGenerationError(f"Refusing to extract unsafe archive entry: {name!r}")


def _materialize(spec: RuntimeSpec, arch: str, prefix: Path) -> None:
    """Populate prefix with the runtime, atomically."""
    asset = spec.assets[arch]
    staging = Path(tempfile.mkdtemp(prefix=f".{spec.name}-", dir=prefix.parent))
    try:
        bin_dir = staging / spec.bin_subdir if spec.bin_subdir else staging
        if not spec.strip_container:
            # Deliberately not pre-created for strip_container: the archive
            # brings its own bin/, and shutil.move onto an existing directory
            # moves *into* it, producing bin/bin.
            bin_dir.mkdir(parents=True, exist_ok=True)

        if spec.kind == "raw":
            target = bin_dir / spec.name
            _download_verified(asset, target)
            target.chmod(0o755)
        elif spec.strip_container:
            # jdk-21.0.12+8/, apache-maven-3.9.9/, go/ -- each wraps everything
            # in one versioned directory. Lifting its contents gives a prefix
            # whose layout does not change when the version does, so bin_subdir
            # means the same thing for every tool.
            archive = staging / f"{spec.name}-archive"
            unpacked = staging / ".unpack"
            unpacked.mkdir()
            _download_verified(asset, archive)
            _extract(archive, spec, unpacked)
            archive.unlink(missing_ok=True)
            roots = [entry for entry in unpacked.iterdir() if entry.is_dir()]
            if len(roots) != 1:
                raise SBOMGenerationError(
                    f"{spec.name}: expected one top-level directory in the archive, found {len(roots)}"
                )
            for item in roots[0].iterdir():
                shutil.move(str(item), staging / item.name)
            shutil.rmtree(unpacked, ignore_errors=True)
            for binary in bin_dir.iterdir() if bin_dir.is_dir() else ():
                if binary.is_file():
                    binary.chmod(0o755)
        else:
            archive = staging / f"{spec.name}-archive"
            _download_verified(asset, archive)
            _extract(archive, spec, bin_dir)
            archive.unlink(missing_ok=True)
            if spec.member:
                (bin_dir / spec.member).chmod(0o755)

        (staging / _READY).write_text(f"{spec.name} {spec.version} {asset.algorithm}:{asset.digest}\n")
        # Atomic when it wins; another process getting there first is fine,
        # since both prefixes were built from the same pinned digest.
        try:
            staging.replace(prefix)
        except OSError:
            if not (prefix / _READY).exists():
                raise
            shutil.rmtree(staging, ignore_errors=True)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def ensure_runtime(name: str) -> Path:
    """Make a pinned runtime available and return the directory holding it.

    The directory is prepended to PATH, so callers that shell out by name
    keep working unchanged. Repeat calls are cheap: the result is memoised in
    process and the on-disk prefix is reused across processes.

    Raises:
        SBOMGenerationError: if the runtime is unknown, unavailable for this
            architecture, cannot be downloaded, or fails its checksum.
    """
    if name not in RUNTIMES:
        raise SBOMGenerationError(f"Unknown tool runtime {name!r}")

    if cached := _resolved.get(name):
        return cached

    spec = RUNTIMES[name]
    with _locks[name]:
        if cached := _resolved.get(name):
            return cached

        # Deliberately no "already on PATH, skip the download" shortcut.
        #
        # Each release hard-codes the versions it was built against, and the
        # SBOM it publishes names those versions. Silently preferring whatever
        # happens to be on PATH would mean running one binary and reporting
        # another -- the SBOM would be lying, which is the one defect this
        # project cannot ship. The pinned artifact is always what runs; the
        # on-disk cache keeps that free after the first fetch.

        arch = current_arch()
        if arch not in spec.assets:
            raise SBOMGenerationError(f"No pinned {spec.name} runtime for {arch}")

        prefix = cache_root() / f"{spec.name}-{spec.version}-{arch}"
        bin_dir = prefix / spec.bin_subdir if spec.bin_subdir else prefix

        if not (prefix / _READY).exists():
            logger.info(f"Fetching {spec.name} {spec.version} ({arch}) into {prefix}")
            _materialize(spec, arch, prefix)
            logger.info(f"{spec.name} {spec.version} ready (sha256 verified)")

        _prepend_path(bin_dir)
        for key, value in spec.env.items():
            os.environ.setdefault(key, value.format(prefix=prefix))

        _resolved[name] = bin_dir
        return bin_dir


def _prepend_path(directory: Path) -> None:
    """Put directory first on PATH, without duplicating it."""
    entry = str(directory)
    current = os.environ.get("PATH", "")
    if entry not in current.split(os.pathsep):
        os.environ["PATH"] = f"{entry}{os.pathsep}{current}" if current else entry


def reset_runtime_cache() -> None:
    """Forget memoised lookups. For tests."""
    _resolved.clear()
