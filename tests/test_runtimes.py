"""Tests for on-demand, hash-pinned tool runtimes."""

import hashlib
import io
import logging
import os
import tarfile
from pathlib import Path

import pytest

from sbomify_action import runtimes
from sbomify_action._generation.protocol import GenerationInput
from sbomify_action.exceptions import SBOMGenerationError
from sbomify_action.runtimes import (
    Asset,
    RuntimeSpec,
    cache_root,
    current_arch,
    ensure_runtime,
    reset_runtime_cache,
)


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Point the cache at a temp dir and clear memoisation between tests."""
    monkeypatch.setenv("SBOMIFY_TOOL_CACHE", str(tmp_path / "cache"))
    reset_runtime_cache()
    yield
    reset_runtime_cache()


class _FakeResponse:
    def __init__(self, payload: bytes):
        self._payload = payload
        self.headers = {"Content-Length": str(len(payload))}

    @property
    def content(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._payload), chunk_size):
            yield self._payload[i : i + chunk_size]


def _serve(monkeypatch, payload: bytes):
    """Make every download return payload."""
    monkeypatch.setattr(runtimes.requests, "get", lambda *a, **k: _FakeResponse(payload))


def _register(monkeypatch, spec: RuntimeSpec):
    monkeypatch.setitem(runtimes.RUNTIMES, spec.name, spec)
    monkeypatch.setitem(runtimes._locks, spec.name, runtimes.threading.Lock())


def _raw_spec(payload: bytes, name: str = "faketool") -> RuntimeSpec:
    return RuntimeSpec(
        name=name,
        version="1.0.0",
        kind="raw",
        assets={
            arch: [
                Asset(
                    url=f"https://example.invalid/{name}",
                    algorithm="sha256",
                    digest=hashlib.sha256(payload).hexdigest(),
                )
            ]
            for arch in ("amd64", "arm64")
        },
    )


def test_fetches_verifies_and_puts_on_path(monkeypatch):
    payload = b"#!/bin/sh\necho hi\n"
    spec = _raw_spec(payload)
    _register(monkeypatch, spec)
    _serve(monkeypatch, payload)

    bin_dir = ensure_runtime("faketool")

    binary = bin_dir / "faketool"
    assert binary.read_bytes() == payload
    assert os.access(binary, os.X_OK), "fetched runtime must be executable"
    assert str(bin_dir) in os.environ["PATH"].split(os.pathsep)


def test_rejects_a_tampered_download(monkeypatch):
    """A payload that does not match the pinned digest must never be used."""
    spec = _raw_spec(b"the-bytes-we-pinned")
    _register(monkeypatch, spec)
    _serve(monkeypatch, b"malicious-substitute")

    with pytest.raises(SBOMGenerationError, match="Checksum mismatch"):
        ensure_runtime("faketool")

    # And nothing is left behind for a later run to pick up.
    leftovers = [p for p in cache_root().rglob("faketool") if p.is_file()]
    assert leftovers == [], f"tampered download was left on disk: {leftovers}"


def test_reuses_an_already_extracted_prefix(monkeypatch):
    payload = b"binary-content"
    spec = _raw_spec(payload)
    _register(monkeypatch, spec)

    calls = {"n": 0}

    def counting_get(*a, **k):
        calls["n"] += 1
        return _FakeResponse(payload)

    monkeypatch.setattr(runtimes.requests, "get", counting_get)

    ensure_runtime("faketool")
    reset_runtime_cache()  # forget the in-process memo, keep the on-disk prefix
    ensure_runtime("faketool")

    assert calls["n"] == 1, "second call re-downloaded instead of reusing the prefix"


def test_ignores_a_tool_already_on_path(monkeypatch, tmp_path):
    """The pinned artifact must win over whatever happens to be installed.

    Each release hard-codes the tool versions it was built against and its
    SBOM names them. Using a different binary found on PATH would mean
    running one thing and reporting another.
    """
    payload = b"the-pinned-bytes"
    spec = _raw_spec(payload)
    _register(monkeypatch, spec)
    _serve(monkeypatch, payload)

    impostor = tmp_path / "bin" / "faketool"
    impostor.parent.mkdir(parents=True)
    impostor.write_bytes(b"a different build entirely")
    monkeypatch.setattr(runtimes.shutil, "which", lambda n: str(impostor) if n == "faketool" else None)

    bin_dir = ensure_runtime("faketool")

    assert bin_dir != impostor.parent, "used the binary on PATH instead of the pinned one"
    assert (bin_dir / "faketool").read_bytes() == payload


def test_extracts_a_named_member_from_an_archive(monkeypatch):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, body in (("tool", b"the-tool"), ("README", b"noise")):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    payload = buf.getvalue()

    spec = RuntimeSpec(
        name="tool",
        version="2.0.0",
        kind="tar.gz",
        member="tool",
        assets={
            arch: [
                Asset(
                    url="https://example.invalid/t.tgz", algorithm="sha256", digest=hashlib.sha256(payload).hexdigest()
                )
            ]
            for arch in ("amd64", "arm64")
        },
    )
    _register(monkeypatch, spec)
    _serve(monkeypatch, payload)

    bin_dir = ensure_runtime("tool")
    assert (bin_dir / "tool").read_bytes() == b"the-tool"
    assert not (bin_dir / "README").exists(), "only the named member should be kept"


def test_refuses_path_traversal_in_archives(monkeypatch):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("../../escaped")
        info.size = 3
        tf.addfile(info, io.BytesIO(b"bad"))
    payload = buf.getvalue()

    spec = RuntimeSpec(
        name="evil",
        version="1.0.0",
        kind="tar.gz",
        assets={
            arch: [
                Asset(
                    url="https://example.invalid/e.tgz", algorithm="sha256", digest=hashlib.sha256(payload).hexdigest()
                )
            ]
            for arch in ("amd64", "arm64")
        },
    )
    _register(monkeypatch, spec)
    _serve(monkeypatch, payload)

    with pytest.raises(SBOMGenerationError, match="unsafe archive entry"):
        ensure_runtime("evil")


def test_unknown_runtime_is_rejected():
    with pytest.raises(SBOMGenerationError, match="Unknown tool runtime"):
        ensure_runtime("no-such-tool")


def test_cache_falls_back_when_home_is_unwritable(monkeypatch, tmp_path):
    """The non-root case: HOME exists but cannot be written to."""
    monkeypatch.delenv("SBOMIFY_TOOL_CACHE", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("HOME", "/proc/nonexistent-home")
    monkeypatch.setattr(runtimes.tempfile, "gettempdir", lambda: str(tmp_path))

    root = cache_root()

    assert root == tmp_path / "sbomify-runtimes"
    assert root.is_dir()


def test_cache_honours_explicit_override(monkeypatch, tmp_path):
    target = tmp_path / "pinned-cache"
    monkeypatch.setenv("SBOMIFY_TOOL_CACHE", str(target))
    assert cache_root() == target


def test_every_pinned_runtime_covers_both_architectures():
    """A missing arch would only surface on arm64 users' machines."""
    for name, spec in runtimes.RUNTIMES.items():
        assert set(spec.assets) == {"amd64", "arm64"}, f"{name} is missing an architecture"
        for arch, arch_assets in spec.assets.items():
            assert arch_assets, f"{name}/{arch} has no assets"
            for asset in arch_assets:
                assert asset.url.startswith("https://"), f"{name}/{arch} must be fetched over https"
                if asset.attestation:
                    # Ours: anchored by the signed digest inside the bundle,
                    # so there is no locally transcribed one to check.
                    assert asset.attestation.startswith("https://"), f"{name}/{arch} attestation must be https"
                    continue
                expected = {"sha256": 64, "sha512": 128}[asset.algorithm]
                assert len(asset.digest) == expected, f"{name}/{arch} digest length is wrong"


def test_current_arch_is_supported():
    assert current_arch() in {"amd64", "arm64"}


def test_partial_download_is_not_left_in_the_cache(monkeypatch):
    """A download that dies mid-stream must not leave a usable-looking file."""
    spec = _raw_spec(b"complete-payload")
    _register(monkeypatch, spec)

    class _Dying(_FakeResponse):
        def iter_content(self, chunk_size=1):
            yield b"partial"
            raise runtimes.requests.ConnectionError("connection reset")

    monkeypatch.setattr(runtimes.requests, "get", lambda *a, **k: _Dying(b""))

    with pytest.raises(SBOMGenerationError, match="Failed to download"):
        ensure_runtime("faketool")

    assert not list(Path(cache_root()).rglob("faketool")), "partial download left behind"


def test_fetching_is_on_by_default_and_opt_out(monkeypatch):
    """Fetching what an ecosystem needs is the design, not an extra.

    This was once opt-in outside our own image, because fetching a tool
    changes which generator wins and so changes the SBOM. The reasoning was
    backwards: declining to fetch does not leave the user without an opinion,
    it silently hands them the fallback. A Rust project resolved by syft
    rather than cargo-cyclonedx is a worse SBOM, and nothing says so.

    The gate was really compensating for a routing defect -- cdxgen becoming
    available on a bare runner, displacing syft for container images and
    degrading enrichment. That is fixed directly now: syft-image outranks
    cdxgen-image, so the incident cannot recur through this door.
    """
    monkeypatch.delenv("SBOMIFY_IN_CONTAINER", raising=False)
    monkeypatch.delenv("SBOMIFY_FETCH_RUNTIMES", raising=False)
    assert runtimes.fetching_is_enabled() is True

    for value in ("0", "false", "no", "FALSE"):
        monkeypatch.setenv("SBOMIFY_FETCH_RUNTIMES", value)
        assert runtimes.fetching_is_enabled() is False, f"{value} should opt out"

    monkeypatch.setenv("SBOMIFY_FETCH_RUNTIMES", "1")
    assert runtimes.fetching_is_enabled() is True


def test_the_container_image_routing_that_gate_protected_is_fixed(monkeypatch):
    """Syft must outrank cdxgen for container images, or the old bug returns."""
    from sbomify_action._generation import create_default_registry

    registry = create_default_registry()
    generators = getattr(registry, "_generators", None) or registry.generators
    priority = {g.name: g.priority for g in generators}
    assert priority["syft-image"] < priority["cdxgen-image"]


def test_fetching_can_be_opted_into_anywhere(monkeypatch):
    monkeypatch.delenv("SBOMIFY_IN_CONTAINER", raising=False)
    monkeypatch.setenv("SBOMIFY_FETCH_RUNTIMES", "1")
    assert runtimes.fetching_is_enabled() is True


def test_a_prefix_from_a_different_digest_is_refetched(monkeypatch):
    """A cached prefix must match the digest we now expect, not merely exist.

    The digest is the whole trust anchor, and it was checked on download but
    not on reuse. Since SBOMIFY_TOOL_CACHE is meant to be shared and
    long-lived, correcting a wrong pin without bumping the version would
    otherwise keep serving the old bytes forever.
    """
    payload = b"the-bytes-we-now-expect"
    spec = _raw_spec(payload)
    _register(monkeypatch, spec)
    _serve(monkeypatch, payload)

    prefix = cache_root() / f"{spec.name}-{spec.version}-{runtimes.current_arch()}"
    prefix.mkdir(parents=True)
    (prefix / spec.name).write_bytes(b"bytes from an older pin")
    (prefix / runtimes._READY).write_text(f"{spec.name} {spec.version} sha256:{'0' * 64}\n")

    bin_dir = ensure_runtime("faketool")

    assert (bin_dir / "faketool").read_bytes() == payload, "stale prefix was reused"


def test_a_prefix_matching_the_digest_is_reused(monkeypatch):
    """The check must not defeat caching for an unchanged pin."""
    payload = b"stable-bytes"
    spec = _raw_spec(payload)
    _register(monkeypatch, spec)

    calls = {"n": 0}

    def counting_get(*a, **k):
        calls["n"] += 1
        return _FakeResponse(payload)

    monkeypatch.setattr(runtimes.requests, "get", counting_get)

    ensure_runtime("faketool")
    reset_runtime_cache()
    ensure_runtime("faketool")

    assert calls["n"] == 1, "a matching prefix should not be refetched"


class TestAttestationVerification:
    """Our own builds must prove they came from our workflow.

    The digest pin proves the bytes match what we recorded. It cannot prove
    where they came from: anyone able to edit tools.toml can change a URL and
    its digest in the same commit. The Sigstore certificate is the part they
    cannot forge, so a bundle that does not verify must stop the fetch.
    """

    @staticmethod
    def _attested_spec(payload: bytes) -> RuntimeSpec:
        spec = _raw_spec(payload, name="ourtool")
        return RuntimeSpec(
            name=spec.name,
            version=spec.version,
            kind=spec.kind,
            assets={
                arch: [
                    Asset(url=a.url, algorithm=a.algorithm, digest=a.digest, attestation="https://example.invalid/b")
                ]
                for arch, assets in spec.assets.items()
                for a in assets
            },
        )

    def test_a_failing_attestation_refuses_the_binary(self, monkeypatch):
        payload = b"bytes-that-hash-correctly"
        _register(monkeypatch, self._attested_spec(payload))
        _serve(monkeypatch, payload)
        monkeypatch.setattr(runtimes.shutil, "which", lambda n: "/usr/bin/cosign" if n == "cosign" else None)
        monkeypatch.setattr(
            runtimes.subprocess,
            "run",
            lambda *a, **k: runtimes.subprocess.CompletedProcess(a[0], 1, "", "no matching signatures"),
        )

        with pytest.raises(SBOMGenerationError, match="Attestation verification failed"):
            ensure_runtime("ourtool")

        # The digest matched, so only the attestation stopped this. Nothing
        # may be left where a later run would treat it as verified.
        assert not list(Path(cache_root()).rglob("ourtool")), "rejected binary was left on disk"

    def test_a_passing_attestation_lets_the_fetch_through(self, monkeypatch):
        payload = b"bytes-that-hash-correctly"
        _register(monkeypatch, self._attested_spec(payload))
        _serve(monkeypatch, payload)
        monkeypatch.setattr(runtimes.shutil, "which", lambda n: "/usr/bin/cosign" if n == "cosign" else None)
        seen = {}

        def fake_run(cmd, *a, **k):
            seen["cmd"] = cmd
            return runtimes.subprocess.CompletedProcess(cmd, 0, "Verified OK", "")

        monkeypatch.setattr(runtimes.subprocess, "run", fake_run)

        bin_dir = ensure_runtime("ourtool")

        assert (bin_dir / "ourtool").read_bytes() == payload
        # The identity is the point of the check: without pinning the workflow
        # and issuer, any Sigstore-signed artifact at all would pass.
        assert "--certificate-identity-regexp" in seen["cmd"]
        identity = seen["cmd"][seen["cmd"].index("--certificate-identity-regexp") + 1]
        # The tools moved repositories; verifying against the old identity
        # would reject every bundle we now publish.
        assert "sbom-tools" in identity and "build" in identity
        assert seen["cmd"][seen["cmd"].index("--certificate-oidc-issuer") + 1] == (
            "https://token.actions.githubusercontent.com"
        )
        assert seen["cmd"][seen["cmd"].index("--type") + 1] == "slsaprovenance1"
        # --new-bundle-format is deprecated in cosign v3 -- it is the only
        # format now -- and passing it printed a deprecation warning on every
        # single fetch.
        assert "--new-bundle-format" not in seen["cmd"]

    def test_upstream_downloads_are_digest_pinned_only(self, monkeypatch):
        """No bundle declared means no cosign call, not a silent pass."""
        payload = b"vendor-bytes"
        _register(monkeypatch, _raw_spec(payload))
        _serve(monkeypatch, payload)
        monkeypatch.setattr(
            runtimes.subprocess,
            "run",
            lambda *a, **k: pytest.fail("cosign was invoked for an artifact with no attestation"),
        )

        assert (ensure_runtime("faketool") / "faketool").read_bytes() == payload

    def test_cosign_itself_carries_no_attestation(self):
        """The bootstrap: verifying cosign would require cosign."""
        for asset in runtimes.RUNTIMES["cosign"].assets["amd64"]:
            assert asset.attestation is None, "cosign cannot verify its own download on a cold cache"


class TestBundleEnvironment:
    """The [env] block a bundle declares, and who is allowed to win."""

    @staticmethod
    def _bundle(tmp_path: Path, env: str) -> Path:
        prefix = tmp_path / "bundle-jvm-tools-rolling-amd64"
        (prefix / "bin").mkdir(parents=True)
        (prefix / "bundle.toml").write_text('[bundle]\nname = "jvm"\nbin_dirs = ["bin"]\n\n[env]\n' + env)
        return prefix

    def test_bundle_env_is_applied_with_the_prefix_substituted(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GRADLE_USER_HOME", raising=False)
        prefix = self._bundle(tmp_path, 'GRADLE_USER_HOME = "{prefix}/.gradle"\n')

        runtimes._apply_bundle_manifest(prefix)

        assert os.environ["GRADLE_USER_HOME"] == str(prefix / ".gradle")

    def test_a_caller_can_isolate_its_own_gradle_home(self, tmp_path, monkeypatch):
        """F16: two concurrent JVM builds shared one Gradle journal.

        The bundle pins GRADLE_USER_HOME into the shared runtime cache and used
        to assign it unconditionally, after the caller's environment was read.
        Exporting it did nothing, so the only way to stop two builds corrupting
        each other was to stop running two builds.
        """
        monkeypatch.setenv("GRADLE_USER_HOME", "/tmp/mine")
        prefix = self._bundle(tmp_path, 'GRADLE_USER_HOME = "{prefix}/.gradle"\n')

        runtimes._apply_bundle_manifest(prefix)

        assert os.environ["GRADLE_USER_HOME"] == "/tmp/mine"

    def test_maven_and_sbt_are_overridable_too(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MAVEN_ARGS", "-Dmaven.repo.local=/tmp/m2")
        monkeypatch.setenv("SBT_OPTS", "-Dsbt.global.base=/tmp/sbt")
        prefix = self._bundle(
            tmp_path,
            'MAVEN_ARGS = "-Dmaven.repo.local={prefix}/repository"\nSBT_OPTS = "-Dsbt.global.base={prefix}/.sbt"\n',
        )

        runtimes._apply_bundle_manifest(prefix)

        assert os.environ["MAVEN_ARGS"] == "-Dmaven.repo.local=/tmp/m2"
        assert os.environ["SBT_OPTS"] == "-Dsbt.global.base=/tmp/sbt"

    def test_java_home_is_not_overridable(self, tmp_path, monkeypatch):
        """A runner's own JDK must not displace the one we pinned and attested.

        JAVA_HOME is set on most CI images, so honouring it would quietly build
        against a different Java than the bundle provides -- a wrong answer,
        where the contention it would avoid is merely slow.
        """
        monkeypatch.setenv("JAVA_HOME", "/usr/lib/jvm/some-other-jdk")
        prefix = self._bundle(tmp_path, 'JAVA_HOME = "{prefix}/jdk"\n')

        runtimes._apply_bundle_manifest(prefix)

        assert os.environ["JAVA_HOME"] == str(prefix / "jdk")

    def test_an_empty_override_does_not_count_as_set(self, tmp_path, monkeypatch):
        """GRADLE_USER_HOME= in a workflow is an accident, not an isolation request."""
        monkeypatch.setenv("GRADLE_USER_HOME", "")
        prefix = self._bundle(tmp_path, 'GRADLE_USER_HOME = "{prefix}/.gradle"\n')

        runtimes._apply_bundle_manifest(prefix)

        assert os.environ["GRADLE_USER_HOME"] == str(prefix / ".gradle")

    @pytest.mark.parametrize("name", ["GOCACHE", "GOMODCACHE", "GOPATH"])
    def test_the_go_caches_are_overridable(self, tmp_path, monkeypatch, name):
        """The go bundle puts its caches inside the prefix, same as the JVM one.

        {prefix} is the only substitution a bundle gets, so left unoverridable
        the module cache has nowhere to live but inside a Sigstore-attested
        directory: 6.2 GB of .gomodcache around 370 MB of toolchain, in a tree
        that is reused on a marker file and never re-verified. The release is
        `rolling`, so each toolchain refresh rmtree's the prefix and discards a
        module cache that never depended on the Go version.
        """
        monkeypatch.setenv(name, "/tmp/mine")
        prefix = self._bundle(tmp_path, f'{name} = "{{prefix}}/.default"\n')

        runtimes._apply_bundle_manifest(prefix)

        assert os.environ[name] == "/tmp/mine"

    @pytest.mark.parametrize("name", ["GOCACHE", "GOMODCACHE", "GOPATH"])
    def test_the_go_caches_keep_the_bundle_default_when_unset(self, tmp_path, monkeypatch, name):
        """Making them overridable must not move them for anyone who says nothing."""
        monkeypatch.delenv(name, raising=False)
        prefix = self._bundle(tmp_path, f'{name} = "{{prefix}}/.default"\n')

        runtimes._apply_bundle_manifest(prefix)

        assert os.environ[name] == str(prefix / ".default")


class TestBundleFileLock:
    """F19: materialising a bundle has to be safe between processes."""

    def test_the_lock_is_held_exclusively_and_released(self, tmp_path, monkeypatch):
        fcntl = pytest.importorskip("fcntl", reason="POSIX only")

        monkeypatch.setenv("SBOMIFY_TOOL_CACHE", str(tmp_path / "cache"))
        reset_runtime_cache()

        with runtimes._bundle_file_lock("jvm"):
            path = cache_root() / ".bundle-jvm.lock"
            assert path.exists()
            # A second handle must not be able to take it while we hold it.
            with path.open("w") as rival:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(rival.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

        # ...and must be able to once we let go.
        with (cache_root() / ".bundle-jvm.lock").open("w") as after:
            fcntl.flock(after.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(after.fileno(), fcntl.LOCK_UN)

    def test_an_unlockable_cache_degrades_rather_than_failing(self, tmp_path, monkeypatch):
        """Some network filesystems have no flock. Unsynchronised beats refusing to run."""
        pytest.importorskip("fcntl", reason="POSIX only")

        def _no_flock(*_args, **_kwargs):
            raise OSError("flock not supported")

        monkeypatch.setattr(runtimes.fcntl, "flock", _no_flock)

        with runtimes._bundle_file_lock("jvm"):
            pass

    def test_a_symlinked_lock_file_is_refused_not_followed(self, tmp_path, monkeypatch):
        """cache_root() can be a world-writable tempdir.

        A container with no writable HOME falls back to one, so the lock file
        is not always somewhere only we can create things. Following a symlink
        there -- or opening it with "w" -- would let anyone who can plant
        .bundle-jvm.lock have us truncate whatever it points at.
        """
        pytest.importorskip("fcntl", reason="POSIX only")
        cache = tmp_path / "cache"
        cache.mkdir()
        monkeypatch.setenv("SBOMIFY_TOOL_CACHE", str(cache))
        reset_runtime_cache()

        victim = tmp_path / "precious"
        victim.write_text("do not truncate me")
        (cache / ".bundle-jvm.lock").symlink_to(victim)

        # Degrades to unsynchronised rather than raising, and above all does
        # not touch the target.
        with runtimes._bundle_file_lock("jvm"):
            pass

        assert victim.read_text() == "do not truncate me"

    def test_an_existing_lock_file_is_reused_without_truncation(self, tmp_path, monkeypatch):
        """Nothing reads the file, but nothing should destroy it either."""
        pytest.importorskip("fcntl", reason="POSIX only")
        cache = tmp_path / "cache"
        cache.mkdir()
        monkeypatch.setenv("SBOMIFY_TOOL_CACHE", str(cache))
        reset_runtime_cache()

        lock = cache / ".bundle-jvm.lock"
        lock.write_text("existing")

        with runtimes._bundle_file_lock("jvm"):
            pass

        assert lock.read_text() == "existing"

    def test_a_platform_without_fcntl_degrades_rather_than_crashing(self, monkeypatch):
        """Windows has no fcntl at all.

        The module is imported defensively because this package is published
        as OS Independent and every generator imports runtimes -- an
        unconditional `import fcntl` would take the whole library down on
        import, not just the locking. Losing cross-process locking is a
        degradation; losing the library is not.
        """
        monkeypatch.setattr(runtimes, "fcntl", None)

        entered = False
        with runtimes._bundle_file_lock("jvm"):
            entered = True

        assert entered, "the context manager must still yield without fcntl"


class TestDownloadRetries:
    """A dropped connection to the release CDN must not fail the run.

    Seen in production as `RemoteDisconnected('Remote end closed connection
    without response')`, which aborted generation outright because falling
    back to another generator is deliberately refused.
    """

    @pytest.fixture(autouse=True)
    def _no_sleeping(self, monkeypatch):
        monkeypatch.setattr(runtimes.time, "sleep", lambda _seconds: None)

    def test_a_dropped_connection_is_retried(self, monkeypatch):
        payload = b"#!/bin/sh\necho hi\n"
        spec = _raw_spec(payload)
        _register(monkeypatch, spec)

        attempts = []

        def _flaky(*args, **kwargs):
            attempts.append(1)
            if len(attempts) == 1:
                raise runtimes.requests.ConnectionError("Remote end closed connection without response")
            return _FakeResponse(payload)

        monkeypatch.setattr(runtimes.requests, "get", _flaky)

        bin_dir = ensure_runtime("faketool")

        assert len(attempts) == 2, "the first attempt should have been retried"
        assert (bin_dir / "faketool").read_bytes() == payload

    def test_a_retry_after_a_partial_body_still_matches_the_pin(self, monkeypatch):
        """The hash must not carry bytes over from the failed attempt.

        The mid-body failure is a ChunkedEncodingError, not a
        ConnectionError: requests only raises the latter before a response
        exists. Getting this wrong makes the test pass against a retry path
        that would not fire in production.
        """
        payload = b"0123456789" * 32
        spec = _raw_spec(payload)
        _register(monkeypatch, spec)

        attempts = []

        class _TruncatedResponse(_FakeResponse):
            def iter_content(self, chunk_size=1):
                yield self._payload[:17]
                raise runtimes.requests.exceptions.ChunkedEncodingError(
                    "Connection broken: IncompleteRead(17 bytes read)"
                )

        def _flaky(*args, **kwargs):
            attempts.append(1)
            if len(attempts) == 1:
                return _TruncatedResponse(payload)
            return _FakeResponse(payload)

        monkeypatch.setattr(runtimes.requests, "get", _flaky)

        bin_dir = ensure_runtime("faketool")

        assert len(attempts) == 2
        assert (bin_dir / "faketool").read_bytes() == payload

    @pytest.mark.parametrize(
        "exc",
        [
            pytest.param(runtimes.requests.ConnectionError("Connection aborted."), id="connection-aborted"),
            pytest.param(runtimes.requests.Timeout("read timed out"), id="timeout"),
            pytest.param(runtimes.requests.exceptions.ChunkedEncodingError("Connection broken"), id="chunked"),
            pytest.param(runtimes.requests.exceptions.ContentDecodingError("bad gzip"), id="decoding"),
        ],
    )
    def test_every_transient_shape_is_recognised(self, exc):
        assert runtimes._is_transient(exc) is True

    def test_a_malformed_url_is_not_transient(self):
        """A request that can never be made is not worth three attempts."""
        assert runtimes._is_transient(runtimes.requests.exceptions.MissingSchema("no scheme")) is False

    def test_a_missing_asset_is_not_retried(self, monkeypatch):
        """A 404 means the manifest is wrong; retrying only slows the failure."""
        spec = _raw_spec(b"never-served")
        _register(monkeypatch, spec)

        attempts = []

        class _NotFound(_FakeResponse):
            def __init__(self):
                super().__init__(b"")
                self.status_code = 404

            def raise_for_status(self):
                raise runtimes.requests.HTTPError("404 Not Found", response=self)

        def _gone(*args, **kwargs):
            attempts.append(1)
            return _NotFound()

        monkeypatch.setattr(runtimes.requests, "get", _gone)

        with pytest.raises(SBOMGenerationError, match="Failed to download"):
            ensure_runtime("faketool")

        assert len(attempts) == 1, "a 404 must fail on the first attempt"

    def test_a_persistently_dropped_connection_gives_up(self, monkeypatch):
        spec = _raw_spec(b"never-served")
        _register(monkeypatch, spec)

        attempts = []

        def _always_drops(*args, **kwargs):
            attempts.append(1)
            raise runtimes.requests.ConnectionError("Remote end closed connection without response")

        monkeypatch.setattr(runtimes.requests, "get", _always_drops)

        with pytest.raises(SBOMGenerationError, match="Failed to download"):
            ensure_runtime("faketool")

        assert len(attempts) == runtimes._DOWNLOAD_ATTEMPTS

    def test_a_server_error_is_retried(self, monkeypatch):
        payload = b"#!/bin/sh\necho hi\n"
        spec = _raw_spec(payload)
        _register(monkeypatch, spec)

        attempts = []

        class _Unavailable(_FakeResponse):
            def __init__(self):
                super().__init__(b"")
                self.status_code = 503

            def raise_for_status(self):
                raise runtimes.requests.HTTPError("503 Service Unavailable", response=self)

        def _flaky(*args, **kwargs):
            attempts.append(1)
            if len(attempts) == 1:
                return _Unavailable()
            return _FakeResponse(payload)

        monkeypatch.setattr(runtimes.requests, "get", _flaky)

        bin_dir = ensure_runtime("faketool")

        assert len(attempts) == 2
        assert (bin_dir / "faketool").read_bytes() == payload


class TestNonLinuxHostsDoNotFetchLinuxBinaries:
    """Every published runtime is a ``linux-<arch>`` artifact.

    Fetching one onto a Mac verifies its digest and its attestation -- the
    bytes really are the binary we pinned -- and then fails with
    ``[Errno 8] Exec format error`` once something tries to run it, pointing
    at a cache path rather than at the mismatch. Worse, the fetched binary is
    prepended to PATH, so it shadows a perfectly good native install.
    """

    def test_no_runtime_is_published_where_we_build_nothing(self, monkeypatch):
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        assert runtimes.runtimes_are_published_for_this_host() is False

    def test_the_fetch_opt_out_is_only_about_the_network(self, monkeypatch):
        """fetching_is_enabled answers the user's question, not the host's.

        Folding the host check in here broke callers that only ever meant the
        opt-out: resolving a bare package.json against the npm registry needs
        the network, not a Linux artifact, so a macOS run skipped it and
        handed cdxgen a manifest it reads as zero components.
        """
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setenv("SBOMIFY_FETCH_RUNTIMES", "1")
        assert runtimes.fetching_is_enabled() is True
        monkeypatch.setenv("SBOMIFY_FETCH_RUNTIMES", "0")
        assert runtimes.fetching_is_enabled() is False

    def test_registry_resolution_still_runs_off_linux(self, monkeypatch, tmp_path, caplog):
        """The caller at _generation/utils.py that gates on the opt-out.

        Resolving a bare package.json reaches the npm registry; it wants the
        network, not a Linux artifact. Folding the host check into
        fetching_is_enabled made a macOS run skip it and hand cdxgen a
        manifest it reads as zero components.
        """
        from sbomify_action._generation import utils as generation_utils

        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.delenv("SBOMIFY_FETCH_RUNTIMES", raising=False)
        (tmp_path / "package.json").write_text('{"name": "x"}', encoding="utf-8")
        # A missing bun is a different, later decline -- and the one we want
        # to land on: reaching it proves the opt-out check did not fire.
        monkeypatch.setattr(generation_utils.shutil, "which", lambda name: None)

        with caplog.at_level(logging.DEBUG, logger="sbomify_action"):
            assert generation_utils.resolve_npm_lockfile(tmp_path) is None

        assert "bun is not on PATH" in caplog.text
        assert "Runtime fetching is disabled" not in caplog.text

    def test_nothing_is_claimed_that_cannot_be_obtained(self, monkeypatch):
        """can_provide is how a generator decides to take the job."""
        monkeypatch.setenv("SBOMIFY_FETCH_RUNTIMES", "1")
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(runtimes.shutil, "which", lambda name: None)
        assert runtimes.can_provide("syft") is False
        assert runtimes.can_provide("cdxgen") is False

    def test_an_installed_tool_is_claimable_off_linux(self, monkeypatch):
        """The point of the fallback: a native install is still usable.

        Gating purely on fetchability made the Go and JVM generators decline
        unconditionally off Linux, before their installed toolchains could
        reach the PATH fallback, so a machine with a real Go toolchain fell
        through to syft.
        """
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(
            runtimes.shutil,
            "which",
            lambda name: f"/usr/local/bin/{name}" if name in ("go", "cyclonedx-gomod") else None,
        )
        assert runtimes.can_provide("go") is True
        assert runtimes.can_provide("cyclonedx-gomod") is True
        assert runtimes.can_provide("syft") is False

    def test_a_half_installed_toolchain_is_not_claimable(self, monkeypatch):
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(runtimes.shutil, "which", lambda name: "/usr/local/bin/cargo" if name == "cargo" else None)
        assert runtimes.can_provide("rust") is False

    def test_the_go_generator_claims_go_mod_with_a_native_toolchain(self, monkeypatch, tmp_path):
        from sbomify_action._generation.generators.cyclonedx_gomod import CycloneDXGomodGenerator

        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(
            runtimes.shutil,
            "which",
            lambda name: f"/usr/local/bin/{name}" if name in ("go", "cyclonedx-gomod") else None,
        )
        go_mod = tmp_path / "go.mod"
        go_mod.write_text("module example.com/x\n", encoding="utf-8")
        # supports() also wants source to analyse beside the manifest.
        (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
        generation_input = GenerationInput(lock_file=str(go_mod), output_format="cyclonedx")

        assert CycloneDXGomodGenerator().supports(generation_input) is True

    def test_the_jvm_generator_declines_what_it_cannot_finish(self, monkeypatch, tmp_path):
        """A native JDK is not enough: these generators need the bundle's pins.

        maven_plugin_coordinate and friends read the plugin versions out of
        the bundle's bundle.toml, which sits beside a fetched prefix. A
        natively installed mvn has no such file, so claiming the input on the
        strength of the toolchain only moves the failure from supports() into
        generate().
        """
        from sbomify_action._generation.generators.cyclonedx_jvm import (
            CycloneDXMavenGenerator,
        )

        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(
            runtimes.shutil,
            "which",
            lambda name: f"/usr/local/bin/{name}" if name in ("java", "mvn") else None,
        )
        pom = tmp_path / "pom.xml"
        pom.write_text("<project/>", encoding="utf-8")
        generation_input = GenerationInput(lock_file=str(pom), output_format="cyclonedx")

        assert runtimes.bundle_is_obtainable() is False
        assert CycloneDXMavenGenerator().supports(generation_input) is False

    def test_the_jvm_generator_still_claims_it_on_linux(self, monkeypatch, tmp_path):
        from sbomify_action._generation.generators.cyclonedx_jvm import (
            CycloneDXMavenGenerator,
        )

        monkeypatch.setattr(runtimes.platform, "system", lambda: "Linux")
        monkeypatch.delenv("SBOMIFY_FETCH_RUNTIMES", raising=False)
        pom = tmp_path / "pom.xml"
        pom.write_text("<project/>", encoding="utf-8")
        generation_input = GenerationInput(lock_file=str(pom), output_format="cyclonedx")

        assert runtimes.bundle_is_obtainable() is True
        assert CycloneDXMavenGenerator().supports(generation_input) is True

    def test_the_opt_out_is_not_the_platform_gate(self, monkeypatch):
        """They answer different questions and must not be read as one.

        Folding them together made a macOS run skip npm registry resolution,
        which needs the network rather than a Linux artifact.
        """
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.delenv("SBOMIFY_FETCH_RUNTIMES", raising=False)

        assert runtimes.fetching_is_enabled() is True
        assert runtimes.runtimes_are_published_for_this_host() is False
        assert runtimes.bundle_is_obtainable() is False

    def test_an_unknown_runtime_is_still_unknown_off_linux(self, monkeypatch):
        """The documented contract, which the PATH fallback jumped ahead of.

        Probing PATH first meant `ensure_runtime("no-such-tool")` reported a
        platform problem, or succeeded outright if some unrelated executable
        happened to carry that name.
        """
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(runtimes.shutil, "which", lambda name: "/usr/bin/" + name)

        with pytest.raises(SBOMGenerationError, match="Unknown tool runtime"):
            ensure_runtime("no-such-tool")

    @pytest.mark.parametrize("system", ["Darwin", "Windows"])
    def test_fetching_anyway_says_what_is_wrong(self, monkeypatch, system):
        monkeypatch.setattr(runtimes.platform, "system", lambda: system)
        # Nothing on PATH to stand in: this is the no-fallback case.
        monkeypatch.setattr(runtimes.shutil, "which", lambda name: None)
        with pytest.raises(SBOMGenerationError) as excinfo:
            ensure_runtime("cosign")
        message = str(excinfo.value)
        assert "Linux only" in message
        assert system in message

    def test_bundles_refuse_the_same_way(self, monkeypatch):
        bundle = runtimes.bundle_for("syft")
        assert bundle is not None, "syft is expected to arrive in a bundle"
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        with pytest.raises(SBOMGenerationError, match="Linux only"):
            runtimes.ensure_bundle(bundle)

    def test_linux_is_unaffected(self, monkeypatch):
        monkeypatch.delenv("SBOMIFY_FETCH_RUNTIMES", raising=False)
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Linux")
        assert runtimes.runtimes_are_published_for_this_host() is True
        assert runtimes.fetching_is_enabled() is True
        assert runtimes.can_provide("syft") is True

    def test_the_opt_out_still_stops_a_claim_on_linux(self, monkeypatch):
        """An air-gapped Linux build with nothing installed claims nothing."""
        monkeypatch.setenv("SBOMIFY_FETCH_RUNTIMES", "0")
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Linux")
        monkeypatch.setattr(runtimes.shutil, "which", lambda name: None)
        assert runtimes.can_provide("syft") is False

    def test_an_installed_tool_is_used_rather_than_refused(self, monkeypatch, tmp_path):
        """The whole point of declining the fetch: the native install still runs.

        A generator sets its ``_*_AVAILABLE`` flag from PATH, so refusing here
        meant it claimed the input and then died before invoking the binary it
        had already found.
        """
        installed = tmp_path / "bin" / "syft"
        installed.parent.mkdir(parents=True)
        installed.touch()
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(runtimes.shutil, "which", lambda name: str(installed) if name == "syft" else None)

        assert ensure_runtime("syft") == installed.parent

    def test_a_runtime_id_that_is_not_a_command_resolves_its_real_one(self, monkeypatch, tmp_path):
        """ "maven" is satisfied by an ``mvn``; the jvm bundle's id is not a command."""
        mvn = tmp_path / "bin" / "mvn"
        mvn.parent.mkdir(parents=True)
        mvn.touch()
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(runtimes.shutil, "which", lambda name: str(mvn) if name == "mvn" else None)

        assert runtimes.commands_for("maven") == ("mvn",)
        assert ensure_runtime("maven") == mvn.parent

    def test_a_toolchain_id_requires_every_command_it_stands_for(self, monkeypatch, tmp_path):
        """ "rust" is cargo *and* rustc: cargo-cyclonedx shells out to both."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir(parents=True)
        for command in ("cargo", "rustc"):
            (bin_dir / command).touch()
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(
            runtimes.shutil,
            "which",
            lambda name: str(bin_dir / name) if name in ("cargo", "rustc") else None,
        )

        assert runtimes.commands_for("rust") == ("cargo", "rustc")
        assert ensure_runtime("rust") == bin_dir

    def test_half_a_toolchain_is_not_enough(self, monkeypatch, tmp_path):
        """A ``cargo`` without a ``rustc`` fails here, not inside cargo-cyclonedx.

        cargo-cyclonedx asks rustc for the host target triple and exits
        non-zero without it, reporting a missing target rather than a
        half-installed toolchain.
        """
        cargo = tmp_path / "bin" / "cargo"
        cargo.parent.mkdir(parents=True)
        cargo.touch()
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(runtimes.shutil, "which", lambda name: str(cargo) if name == "cargo" else None)

        with pytest.raises(SBOMGenerationError, match="rustc"):
            ensure_runtime("rust")

    def test_the_java_caller_succeeds_with_a_native_toolchain(self, monkeypatch, tmp_path):
        """`ensure_java_maven_installed` asks for "java" then "maven"."""
        from sbomify_action._generation.utils import ensure_java_maven_installed

        bin_dir = tmp_path / "bin"
        bin_dir.mkdir(parents=True)
        for command in ("java", "mvn"):
            (bin_dir / command).touch()
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(
            runtimes.shutil,
            "which",
            lambda name: str(bin_dir / name) if name in ("java", "mvn") else None,
        )

        ensure_java_maven_installed()

    def test_commands_for_passes_through_a_plain_runtime_id(self):
        for name in ("syft", "cdxgen", "cosign", "crane", "java", "go", "dotnet"):
            assert runtimes.commands_for(name) == (name,)

    def test_a_generator_run_reaches_the_installed_binary(self, monkeypatch, tmp_path):
        """End to end: the syft generator invokes the syft it found on PATH.

        ``generate()`` calls ``ensure_runtime("syft")`` as its first act. The
        assertion that matters is that the command afterwards actually runs,
        rather than the generator refusing an input it had already claimed.
        """
        from sbomify_action._generation.generators import syft as syft_generator

        installed = tmp_path / "bin" / "syft"
        installed.parent.mkdir(parents=True)
        installed.touch(mode=0o755)
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(runtimes.shutil, "which", lambda name: str(installed) if name == "syft" else None)
        # The generator reads PATH at import time, so pin the flag the way an
        # install on a non-Linux host would have set it.
        monkeypatch.setattr(syft_generator, "_SYFT_AVAILABLE", True)
        monkeypatch.setattr(syft_generator, "_SYFT_PATH", str(installed))
        # conftest's _no_runtime_fetching stubs ensure_runtime inside every
        # generator module, which is exactly the call under test here. Put the
        # real one back; it reaches no network on this path by construction.
        monkeypatch.setattr(syft_generator, "ensure_runtime", runtimes.ensure_runtime)

        lock_file = tmp_path / "package-lock.json"
        lock_file.write_text('{"lockfileVersion": 3, "packages": {}}', encoding="utf-8")
        output_file = tmp_path / "out.cdx.json"

        invoked: list[list[str]] = []

        def _fake_run(cmd, tool_name, **kwargs):
            invoked.append(list(cmd))
            output_file.write_text(
                '{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}',
                encoding="utf-8",
            )
            return None

        monkeypatch.setattr(syft_generator, "run_command", _fake_run)

        generator = syft_generator.SyftFsGenerator()
        generation_input = GenerationInput(
            lock_file=str(lock_file),
            output_file=str(output_file),
            output_format="cyclonedx",
        )
        assert generator.supports(generation_input) is True

        result = generator.generate(generation_input)

        assert invoked, "generate() raised before invoking the installed syft"
        assert invoked[0][0] == "syft"
        assert result.success is True, result.error_message

    def test_the_user_is_told_why_nothing_was_available(self, monkeypatch):
        from sbomify_action import tool_checks

        monkeypatch.setattr(tool_checks.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(runtimes.platform, "system", lambda: "Darwin")
        monkeypatch.setattr(tool_checks, "check_tool_for_input", lambda *a, **k: ([], ["syft"]))
        message = tool_checks.format_no_tools_error("lock_file", "package-lock.json")
        assert "Linux only" in message
        assert "Darwin" in message
