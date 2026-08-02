"""Tests for on-demand, hash-pinned tool runtimes."""

import hashlib
import io
import os
import tarfile
from pathlib import Path

import pytest

from sbomify_action import runtimes
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
            arch: Asset(
                url=f"https://example.invalid/{name}", algorithm="sha256", digest=hashlib.sha256(payload).hexdigest()
            )
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
            arch: Asset(
                url="https://example.invalid/t.tgz", algorithm="sha256", digest=hashlib.sha256(payload).hexdigest()
            )
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
            arch: Asset(
                url="https://example.invalid/e.tgz", algorithm="sha256", digest=hashlib.sha256(payload).hexdigest()
            )
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
        for arch, asset in spec.assets.items():
            expected = {"sha256": 64, "sha512": 128}[asset.algorithm]
            assert len(asset.digest) == expected, f"{name}/{arch} digest length is wrong"
            assert asset.url.startswith("https://"), f"{name}/{arch} must be fetched over https"


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


def test_fetching_is_disabled_outside_our_image(monkeypatch):
    """A pip install must keep whatever toolchain the user has.

    Fetching a tool the user did not install would change which generator
    the chain selects, and so change the SBOM they get, without them asking.
    That is how the alpine license-db check broke: cdxgen became "available"
    on a bare runner, displaced syft, and enrichment silently degraded.
    """
    monkeypatch.delenv("SBOMIFY_IN_CONTAINER", raising=False)
    monkeypatch.delenv("SBOMIFY_FETCH_RUNTIMES", raising=False)
    monkeypatch.setattr(runtimes, "Path", lambda _: type("P", (), {"exists": lambda s: False})())
    assert runtimes.fetching_is_enabled() is False

    monkeypatch.setenv("SBOMIFY_IN_CONTAINER", "1")
    assert runtimes.fetching_is_enabled() is True


def test_fetching_can_be_opted_into_anywhere(monkeypatch):
    monkeypatch.delenv("SBOMIFY_IN_CONTAINER", raising=False)
    monkeypatch.setenv("SBOMIFY_FETCH_RUNTIMES", "1")
    assert runtimes.fetching_is_enabled() is True
