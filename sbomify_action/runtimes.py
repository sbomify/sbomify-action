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

Every artifact is pinned by digest, which proves "these are the exact bytes
we tested against". For upstream vendor downloads that is the whole trust
anchor: signature verification there would only establish that the vendor
signed something, which the digest already covers more tightly.

Our own builds get a second check. A digest is only ever as trustworthy as
the file it is written in, so anyone who can edit tools.toml can change a
URL and its digest together. They cannot mint a Sigstore certificate naming
our workflow, so binaries published by build-tools.yml also carry an
attestation bundle, verified here with cosign before use.

cosign is the exception: verifying it would require cosign, which is not
available on a cold cache, so it stays digest-pinned only. That is the
bootstrap, and it is deliberate.

Runtimes cannot be updated without a release either way, which is a feature
for a tool whose output is a provenance document.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import tomllib
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from .exceptions import SBOMGenerationError
from .logging_config import logger
from .tool_manifest import STAGE_RUNTIME, Bundle, bundle_for, tools_for_stage

# POSIX only, and this package is published as OS Independent -- importing it
# at the top would make `import sbomify_action.runtimes` raise on Windows and
# take the whole package with it, since every generator imports this module.
# Its absence costs cross-process locking, which is a degradation; its import
# costs the entire library, which is not.
try:
    import fcntl
except ImportError:  # pragma: no cover - exercised only off POSIX
    fcntl = None  # type: ignore[assignment]

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
    attestation: str | None = None


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
    assets: dict[str, list[Asset]]
    kind: str = "raw"
    member: str | None = None
    bin_subdir: str = ""
    strip_container: bool = False
    rust_dist: bool = False
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
            rust_dist=tool.rust_dist,
            bin_subdir=tool.bin_subdir,
            env=tool.env,
            assets={
                arch: [
                    Asset(url=a.url, algorithm=a.algorithm, digest=a.digest, attestation=a.attestation)
                    for a in arch_assets
                ]
                for arch, arch_assets in tool.assets.items()
            },
        )
    return specs


RUNTIMES: dict[str, RuntimeSpec] = _load_runtimes()

_locks: dict[str, threading.Lock] = {name: threading.Lock() for name in RUNTIMES}
_resolved: dict[str, Path] = {}


def fetching_is_enabled() -> bool:
    """Whether we may fetch a tool that is not already present.

    On by default, everywhere. Fetching what an ecosystem needs is the whole
    design: the image stopped baking in every tool it might want, and the
    tools come from pinned, digest-verified, attested bundles at the moment
    they are needed.

    It used to be opt-in outside our own image, on the reasoning that
    downloading a tool changes which generator wins and so changes the SBOM.
    That has it backwards. Declining to fetch does not leave the user without
    an opinion -- it silently hands them the fallback, which is the worse
    SBOM. A Rust project resolved by syft instead of cargo-cyclonedx is not a
    neutral outcome, and the user is not told. Requiring a flag to get the
    good answer means most people never get it.

    Set SBOMIFY_FETCH_RUNTIMES=0 to opt out, for an air-gapped build or where
    only preinstalled tools may run.
    """
    opt_out = os.environ.get("SBOMIFY_FETCH_RUNTIMES", "").lower()
    return opt_out not in ("0", "false", "no")


def can_provide(tool: str) -> bool:
    """Whether we could obtain this tool if asked.

    A generator uses this to decide whether to claim an input. It has to know
    about bundles as well as the vendor-pinned set: once the tools moved to
    sbomify/sbom-tools, RUNTIMES held only cosign, so every generator that
    asked `name in RUNTIMES` reported itself unavailable and the whole chain
    quietly fell through to syft.
    """
    return (bundle_for(tool) is not None or tool in RUNTIMES) and fetching_is_enabled()


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


def _human(size: float) -> str:
    """Bytes as a short human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"  # pragma: no cover - unreachable, GB exits above


def _interactive() -> bool:
    """Whether to animate. A CI log is not a terminal even when it looks like one."""
    return sys.stderr.isatty() and not os.environ.get("CI")


class _Progress:
    """Report download progress on a terminal and in CI alike.

    These artifacts are large -- 83MB for syft, 92MB for the Rust toolchain,
    190MB for the JDK -- so a silent pause of tens of seconds reads as a hang.

    An animated bar redraws in place, which is right in a terminal and useless
    in a CI log, where the escape codes pile up into thousands of unreadable
    lines. Non-interactive runs therefore get one line per completed step.
    """

    #: Percentage between progress lines when not on a terminal.
    STEP = 25

    def __init__(self, label: str, total: int) -> None:
        self._label = label
        self._total = total
        self._done = 0
        self._next = self.STEP
        self._bar: Any | None = None
        self._task: Any | None = None
        if _interactive() and total:
            from rich.progress import (
                BarColumn,
                DownloadColumn,
                Progress,
                TextColumn,
                TimeRemainingColumn,
                TransferSpeedColumn,
            )

            self._bar = Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
                transient=True,
            )
            self._bar.start()
            self._task = self._bar.add_task(label, total=total)
        else:
            logger.info(f"  downloading {label} ({_human(total) if total else 'size unknown'})")

    def advance(self, count: int) -> None:
        self._done += count
        if self._bar is not None:
            self._bar.update(self._task, advance=count)
        elif self._total:
            percent = self._done * 100 // self._total
            while percent >= self._next and self._next <= 100:
                logger.info(f"  {self._label}: {self._next}% ({_human(self._done)} of {_human(self._total)})")
                self._next += self.STEP

    def close(self) -> None:
        if self._bar is not None:
            self._bar.stop()


#: Who must have signed our own tool builds. The certificate binds the
#: artifact to a workflow file and a ref, so a binary built by any other
#: workflow -- or from a fork, or a branch that is not master -- fails.
_ATTESTATION_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
_ATTESTATION_IDENTITY = (
    r"^https://github\.com/sbomify/sbom-tools/\.github/workflows/build\.yml@refs/(heads/master|tags/.+)$"
)
#: cosign v3 validates --type against the predicate type.
#: actions/attest-build-provenance emits https://slsa.dev/provenance/v1,
#: which cosign aliases to "slsaprovenance1". The --new-bundle-format flag
#: that used to accompany this is deprecated in v3 -- it is the only format
#: now -- and passing it just prints a deprecation warning on every fetch.
_ATTESTATION_PREDICATE_TYPE = "slsaprovenance1"
_ATTESTATION_TIMEOUT = 60
#: cosign refuses a blob larger than 128MiB by default and fails with
#: "size of layer (…) exceeded the limit". Our bundles are legitimately
#: bigger than that -- the jvm bundle carries a JDK, Maven, Gradle and sbt --
#: so the default rejects genuine artifacts. Raised rather than removed: the
#: limit exists to stop an attacker feeding a verifier something enormous,
#: and 1GiB is comfortably above the largest bundle we publish.
_ATTESTATION_MAX_BLOB = str(1024 * 1024 * 1024)


def _verify_attestation(artifact: Path, bundle_url: str, label: str) -> None:
    """Check that ``artifact`` was built by our own workflow.

    The digest pin already proves the bytes are the ones we recorded. This
    proves something the digest cannot: that those bytes came out of
    build-tools.yml, from this repository, on master or a tag. A digest is
    only ever as trustworthy as the file it is written in, so an attacker who
    can edit tools.toml can change the URL and the digest together. They
    cannot produce a Sigstore certificate naming our workflow.

    Only our own builds carry a bundle; upstream vendor downloads have none
    and are digest-pinned alone.
    """
    logger.info(f"  fetching attestation for {label}")
    try:
        response = requests.get(bundle_url, timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
        response.raise_for_status()
        bundle_bytes = response.content
    except requests.RequestException as exc:
        raise SBOMGenerationError(f"Failed to download the attestation bundle for {label}: {exc}") from exc

    # cosign verifies cosign, which cannot work on a cold cache, so cosign
    # itself is digest-pinned only. Every other tool is verified with it.
    cosign = shutil.which("cosign") or str(ensure_runtime("cosign") / "cosign")

    with tempfile.TemporaryDirectory() as tmp:
        bundle = Path(tmp) / "bundle.sigstore.json"
        bundle.write_bytes(bundle_bytes)
        cmd = [
            cosign,
            "verify-blob-attestation",
            "--bundle",
            str(bundle),
            "--type",
            _ATTESTATION_PREDICATE_TYPE,
            "--certificate-identity-regexp",
            _ATTESTATION_IDENTITY,
            "--certificate-oidc-issuer",
            _ATTESTATION_OIDC_ISSUER,
            str(artifact),
        ]
        try:
            environment = {**os.environ, "COSIGN_MAX_ATTACHMENT_SIZE": _ATTESTATION_MAX_BLOB}
            result = subprocess.run(  # noqa: S603
                cmd, capture_output=True, text=True, timeout=_ATTESTATION_TIMEOUT, env=environment
            )
        except subprocess.TimeoutExpired as exc:
            raise SBOMGenerationError(f"Attestation verification timed out for {label}") from exc
        except OSError as exc:
            raise SBOMGenerationError(f"Could not run cosign to verify {label}: {exc}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise SBOMGenerationError(
            f"Attestation verification failed for {label}: cosign exited {result.returncode}: {detail}. "
            "Refusing to use a binary that does not prove it came from our build."
        )
    logger.info(f"  ✓ attestation verified: built by sbomify/sbom-tools ({label})")


def _download_verified(asset: Asset, dest: Path) -> None:
    """Stream an asset to dest, failing unless it hashes to the pinned digest.

    Hashing streams alongside the download so a 190MB JDK never has to be
    held in memory, and the file is only moved into place after the digest
    matches -- a mismatched download can never be observed at ``dest``.
    """
    # Our own builds carry no local digest: the Sigstore bundle holds a signed
    # one, so hashing against a number transcribed into tools.toml would be a
    # weaker check, not a second one.
    digest = hashlib.new(asset.algorithm) if asset.digest else None
    scratch = dest.with_suffix(dest.suffix + ".part")
    name = asset.url.rsplit("/", 1)[-1]
    # Chunked responses legitimately omit Content-Length; fall back to an
    # indeterminate bar rather than reporting a bogus total.
    total = int(getattr(asset, "size", 0) or 0)
    progress = None
    try:
        with requests.get(asset.url, stream=True, timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT)) as response:
            response.raise_for_status()
            total = int(getattr(response, "headers", {}).get("Content-Length") or total or 0)
            progress = _Progress(name, total)
            with scratch.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=_CHUNK):
                    if chunk:
                        if digest is not None:
                            digest.update(chunk)
                        handle.write(chunk)
                        progress.advance(len(chunk))
    except requests.RequestException as exc:
        scratch.unlink(missing_ok=True)
        raise SBOMGenerationError(f"Failed to download {asset.url}: {exc}") from exc
    finally:
        if progress is not None:
            progress.close()

    if digest is not None:
        logger.info(f"  verifying {asset.algorithm} of {name}")
        actual = digest.hexdigest()
        if actual != asset.digest:
            scratch.unlink(missing_ok=True)
            raise SBOMGenerationError(
                f"Checksum mismatch for {asset.url}: expected {asset.algorithm}:{asset.digest}, "
                f"got {actual}. Refusing to use the download."
            )
        logger.info(f"  ✓ {asset.algorithm} matches the pin ({actual[:16]}…)")
    elif not asset.attestation:
        scratch.unlink(missing_ok=True)
        raise SBOMGenerationError(
            f"{name} has neither a pinned digest nor an attestation; refusing an unverified download."
        )
    if asset.attestation:
        try:
            _verify_attestation(scratch, asset.attestation, name)
        except Exception:
            # Never leave an unverified artifact where a later run could
            # mistake it for a good one.
            scratch.unlink(missing_ok=True)
            raise
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


def _digest_line(spec: RuntimeSpec, arch: str) -> str:
    """The marker contents a correctly-populated prefix must carry."""
    digests = " ".join(f"{a.algorithm}:{a.digest}" for a in spec.assets[arch])
    return f"{spec.name} {spec.version} {digests}"


def _prefix_matches(prefix: Path, expected: str) -> bool:
    """Whether an existing prefix was built from the digests we now expect."""
    marker = prefix / _READY
    try:
        return marker.read_text().strip() == expected
    except OSError:
        return False


def _materialize(spec: RuntimeSpec, arch: str, prefix: Path) -> None:
    """Populate prefix with the runtime, atomically."""
    assets = spec.assets[arch]
    asset = assets[0]
    staging = Path(tempfile.mkdtemp(prefix=f".{spec.name}-", dir=prefix.parent))
    try:
        bin_dir = staging / spec.bin_subdir if spec.bin_subdir else staging
        if not spec.strip_container and not spec.rust_dist:
            # Deliberately not pre-created for strip_container: the archive
            # brings its own bin/, and shutil.move onto an existing directory
            # moves *into* it, producing bin/bin.
            bin_dir.mkdir(parents=True, exist_ok=True)

        if spec.kind == "raw":
            target = bin_dir / spec.name
            _download_verified(asset, target)
            target.chmod(0o755)
        elif spec.rust_dist:
            # cargo and rustc ship as separate tarballs, each nesting
            # <pkg>-<ver>-<triple>/<component>/{bin,lib} plus an install.sh we
            # do not want to run. Merging the component directories ourselves
            # gives a plain prefix where bin/cargo finds ../lib as it expects.
            for index, one in enumerate(assets):
                archive = staging / f"{spec.name}-{index}-archive"
                unpacked = staging / f".unpack-{index}"
                unpacked.mkdir()
                _download_verified(one, archive)
                _extract(archive, spec, unpacked)
                archive.unlink(missing_ok=True)
                for top in unpacked.iterdir():
                    if not top.is_dir():
                        continue
                    for component in top.iterdir():
                        if not component.is_dir():
                            continue
                        for item in component.iterdir():
                            target = staging / item.name
                            if item.is_dir():
                                shutil.copytree(item, target, dirs_exist_ok=True, symlinks=True)
                            else:
                                target.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(item, target, follow_symlinks=False)
                shutil.rmtree(unpacked, ignore_errors=True)
            for binary in bin_dir.iterdir() if bin_dir.is_dir() else ():
                if binary.is_file():
                    binary.chmod(0o755)
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

        (staging / _READY).write_text(_digest_line(spec, arch) + "\n")
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


_bundle_locks: dict[str, threading.Lock] = {}
_bundle_lock_guard = threading.Lock()
_bundles_ready: dict[str, Path] = {}


def _bundle_lock(name: str) -> threading.Lock:
    with _bundle_lock_guard:
        return _bundle_locks.setdefault(name, threading.Lock())


@contextlib.contextmanager
def _bundle_file_lock(name: str) -> Iterator[None]:
    """Serialise bundle materialisation across processes, not just threads.

    ``_bundle_lock`` is a ``threading.Lock``, which coordinates threads inside
    one interpreter and nothing else. Two *processes* sharing a cache -- two
    jobs on one CI runner, or two steps of the same workflow -- would both find
    the prefix missing and both start unpacking into it. The loser of the race
    then hit ``ENOTEMPTY`` renaming its staging directory over the winner's
    finished prefix, and the run failed with an error naming neither cause nor
    remedy, because from inside one process nothing looked wrong.

    ``flock`` is released by the kernel when the process exits, so a crash
    mid-fetch cannot leave the lock held -- which matters more here than it
    would for a lock file we would have to reap ourselves.

    A cache on a filesystem without ``flock`` (some network mounts) degrades to
    the previous behaviour rather than refusing to run: unsynchronised, but no
    worse than it was. So does a platform with no ``fcntl`` at all.
    """
    if fcntl is None:
        yield
        return

    root = cache_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
        handle = (root / f".bundle-{name}.lock").open("w")
    except OSError:
        yield
        return

    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except OSError:
            yield
            return
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


#: Bundle environment variables a caller is allowed to set for itself.
#:
#: The jvm bundle points these at directories inside the shared runtime cache,
#: and assigning them unconditionally is what makes two concurrent JVM builds
#: on one machine unsafe: they share a Gradle journal, an Ivy home and a local
#: Maven repository, and corrupt each other. Because the assignment happened
#: after the caller's environment was read, exporting GRADLE_USER_HOME did
#: nothing -- the only fix from outside was to stop running two builds at once.
#:
#: Deliberately a list of *cache locations*, not every variable in the [env]
#: block. JAVA_HOME must keep pointing into the prefix: a runner with its own
#: JDK installed almost always has JAVA_HOME set already, and honouring it
#: would silently build against a different Java than the one we pinned and
#: attested. Getting a wrong answer quietly is worse than the contention.
_CALLER_OVERRIDABLE_ENV = frozenset(
    {
        "GRADLE_USER_HOME",
        "MAVEN_ARGS",
        "SBT_OPTS",
    }
)


def _apply_bundle_manifest(prefix: Path) -> Path:
    """Read the bundle's own description and make it usable.

    The bundle states where its executables are and what environment it
    needs, so support for a new ecosystem lands in sbom-tools without any
    change here. bin_dirs is a list because one is not enough: a JDK keeps
    java in jdk/bin and Maven keeps mvn in maven/bin, and a bundle that
    advertised only its top-level bin would hide both.
    """
    manifest = prefix / "bundle.toml"
    if not manifest.exists():
        raise SBOMGenerationError(f"{prefix.name} has no bundle.toml; it is not a bundle we can use")
    declared = tomllib.loads(manifest.read_text())
    body = declared.get("bundle") or {}
    bin_dirs = [str(d) for d in (body.get("bin_dirs") or ["bin"])]

    for key, value in (declared.get("env") or {}).items():
        resolved = str(value).replace("{prefix}", str(prefix))
        if str(key) in _CALLER_OVERRIDABLE_ENV and os.environ.get(str(key)):
            logger.debug(f"Keeping the caller's {key} instead of the {prefix.name} default")
            continue
        os.environ[str(key)] = resolved

    first: Path | None = None
    for relative in bin_dirs:
        directory = prefix / relative
        if not directory.is_dir():
            continue
        _prepend_path(directory)
        first = first or directory
    if first is None:
        raise SBOMGenerationError(f"{prefix.name}: none of its bin_dirs exist ({bin_dirs})")
    return first


def ensure_bundle(bundle: Bundle) -> Path:
    """Fetch, verify and unpack an ecosystem bundle; return its main bin dir."""
    if cached := _bundles_ready.get(bundle.name):
        return cached

    with _bundle_lock(bundle.name), _bundle_file_lock(bundle.name):
        if cached := _bundles_ready.get(bundle.name):
            return cached

        arch = current_arch()
        prefix = cache_root() / f"bundle-{bundle.name}-{bundle.release}-{arch}"
        marker = prefix / _READY
        # Re-read under the file lock. Another process may have finished this
        # bundle while we waited for it, in which case there is nothing to do
        # -- and, more to the point, the rmtree below would otherwise delete a
        # prefix that process is about to use.
        if not marker.exists():
            if prefix.exists():
                shutil.rmtree(prefix, ignore_errors=True)
            logger.info(f"Fetching the {bundle.name} bundle ({bundle.release}, {arch})")
            staging = prefix.with_name(prefix.name + ".staging")
            shutil.rmtree(staging, ignore_errors=True)
            staging.mkdir(parents=True)
            try:
                archive = staging / "bundle.tar.gz"
                _download_verified(
                    Asset(
                        url=bundle.archive_url(arch),
                        algorithm="none",
                        digest="",
                        attestation=bundle.attestation_url(arch),
                    ),
                    archive,
                )
                unpacked = staging / "prefix"
                unpacked.mkdir()
                with tarfile.open(archive) as tar:
                    for member in tar.getmembers():
                        _reject_traversal(member.name)
                    tar.extractall(unpacked)  # noqa: S202 - every member checked above
                archive.unlink()
                (unpacked / _READY).write_text(f"{bundle.name} {bundle.release} {arch}\n")
                # Belt and braces behind the file lock, for the cache that
                # could not take one. Losing this race is not an error: both
                # prefixes were unpacked from the same pinned, attested
                # archive, so the winner's is as good as ours.
                try:
                    unpacked.rename(prefix)
                except OSError:
                    if not marker.exists():
                        raise
            finally:
                shutil.rmtree(staging, ignore_errors=True)
            logger.info(f"  ✓ {bundle.name} bundle ready")

        bin_dir = _apply_bundle_manifest(prefix)
        _bundles_ready[bundle.name] = bin_dir
        return bin_dir


def bundle_plugin_version(tool: str, plugin: str) -> str:
    """The version of a build plugin, as declared by the bundle that provides it.

    Maven, Gradle and sbt fetch these themselves at run time, so nothing here
    installs them -- but the caller has to name a version when it applies one,
    and that version has to come from somewhere. It comes from the bundle.

    Keeping a second copy of the pin here meant two repositories describing the
    same plugin, both watched by Dependabot, free to disagree. They did: within
    hours of the split, sbom-tools said 2.9.3 and this repository still said
    2.9.1. Reading the version off the bundle we already fetched leaves one
    source of truth, in the repository that decides what the bundle contains.
    """
    prefix = ensure_runtime(tool).parent
    manifest = prefix / "bundle.toml"
    if not manifest.exists():
        raise SBOMGenerationError(f"{prefix.name} has no bundle.toml; it cannot say which {plugin} to apply")
    plugins = tomllib.loads(manifest.read_text()).get("plugins") or {}
    version = plugins.get(plugin)
    if not version:
        raise SBOMGenerationError(
            f"{prefix.name} declares no version for {plugin}. "
            "It predates the [plugins] block; a newer sbom-tools bundle carries it."
        )
    return str(version)


def ensure_runtime(name: str) -> Path:
    """Make a pinned runtime available and return the directory holding it.

    The directory is prepended to PATH, so callers that shell out by name
    keep working unchanged. Repeat calls are cheap: the result is memoised in
    process and the on-disk prefix is reused across processes.

    Raises:
        SBOMGenerationError: if the runtime is unknown, unavailable for this
            architecture, cannot be downloaded, or fails its checksum.
    """
    # Most tools now arrive inside an ecosystem bundle from sbomify/sbom-tools.
    # cosign is the exception and stays vendor-pinned below: it is what
    # verifies every bundle's attestation, and trust in a verifier cannot be
    # bootstrapped from an artifact only that verifier can check.
    if bundle := bundle_for(name):
        return ensure_bundle(bundle)

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

        expected = _digest_line(spec, arch)
        if not _prefix_matches(prefix, expected):
            # Either absent, or present from a different pin. The cache may be
            # shared and long-lived (SBOMIFY_TOOL_CACHE), so a prefix left by an
            # earlier digest must not be trusted just because it looks complete:
            # correcting a wrong pin without bumping the version would otherwise
            # keep serving the old bytes forever.
            if prefix.exists():
                logger.info(f"{spec.name} {spec.version} ({arch}) cached under a different digest; refetching")
                shutil.rmtree(prefix, ignore_errors=True)
            logger.info(f"Fetching {spec.name} {spec.version} ({arch}) into {prefix}")
            _materialize(spec, arch, prefix)
            logger.info(f"{spec.name} {spec.version} ready ({expected.split()[-1].split(':')[0]} verified)")

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
