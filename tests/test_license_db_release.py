"""Where the license databases are downloaded from.

sbom-tools builds and publishes them now, under the same release tag as the
bundles, so a build fetches the databases from the sbom-tools release it pins.
Until that release carries them, the sbomify-action releases that always have
are the fallback.
"""

import gzip
import io
import json
import os
from unittest.mock import patch

import sbomify_action._enrichment.sources.license_db as mod
from sbomify_action.tool_manifest import tools_release

DB = {"metadata": {"distro": "alpine", "version": "3.20"}, "packages": {}}


def _gz(obj) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(json.dumps(obj).encode())
    return buf.getvalue()


class _Resp:
    def __init__(self, status_code=200, content=b"", payload=None):
        self.status_code = status_code
        self.content = content
        self._payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError(f"unexpected HTTP {self.status_code}")

    def json(self):
        return self._payload


class _Session:
    def __init__(self, routes):
        self.routes = routes
        self.urls = []

    def get(self, url, params=None, timeout=None, headers=None):
        self.urls.append(url)
        return self.routes.get(url, _Resp(404))


def _sbom_tools_url(release, filename="alpine-3.20.json.gz"):
    return f"https://github.com/sbomify/sbom-tools/releases/download/{release}/{filename}"


def setup_function():
    mod.clear_cache()


def teardown_function():
    mod.clear_cache()


def test_downloads_from_the_pinned_sbom_tools_release(tmp_path):
    with patch.dict(os.environ, {}, clear=True):
        url = _sbom_tools_url(tools_release())
        session = _Session({url: _Resp(content=_gz(DB))})
        db = mod.LicenseDBSource(cache_dir=tmp_path)._download_from_release("alpine", "3.20", session)

    assert db == DB
    # Found, so the rate-limited releases API is never asked.
    assert session.urls == [url]


def test_a_master_image_fetches_from_rolling(tmp_path):
    with patch.dict(os.environ, {"SBOMIFY_GITHUB_ACTION_VCS_REF": "master"}, clear=True):
        url = _sbom_tools_url("rolling")
        session = _Session({url: _Resp(content=_gz(DB))})
        db = mod.LicenseDBSource(cache_dir=tmp_path)._download_from_release("alpine", "3.20", session)

    assert db == DB
    assert session.urls == [url]


def test_falls_back_to_sbomify_action_releases(tmp_path):
    legacy = "https://github.com/sbomify/sbomify-action/releases/download/v26.10.3/alpine-3.20.json.gz"
    releases = [{"tag_name": "v26.10.3", "assets": [{"name": "alpine-3.20.json.gz", "browser_download_url": legacy}]}]
    with patch.dict(os.environ, {}, clear=True):
        session = _Session(
            {
                mod.GITHUB_RELEASES_API: _Resp(payload=releases),
                legacy: _Resp(content=_gz(DB)),
            }
        )
        db = mod.LicenseDBSource(cache_dir=tmp_path)._download_from_release("alpine", "3.20", session)

    assert db == DB
    assert session.urls == [_sbom_tools_url(tools_release()), mod.GITHUB_RELEASES_API, legacy]
