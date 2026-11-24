"""RELEASE_INCLUDES: a product release includes releases of other products.

PRODUCT_RELEASE says where this run's SBOM goes. RELEASE_INCLUDES says what each
of those releases ships with besides, such as the toolchain it downloads at run
time. The link is made from the including release, so the included product's
release is never written to.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests

from sbomify_action._processors.processors.releases import SbomifyReleasesProcessor
from sbomify_action._processors.protocol import ProcessorInput
from sbomify_action.cli.main import build_config
from sbomify_action.exceptions import APIError
from sbomify_action.sbomify_api import SbomifyApiClient


def _config(tmp_path, **kwargs: Any):
    lock = tmp_path / "uv.lock"
    lock.write_text("")
    defaults: dict[str, Any] = {
        "token": "tok",
        "component_id": "comp-1",
        "lock_file": str(lock),
        "output_file": str(tmp_path / "out.json"),
        "upload": False,
    }
    defaults.update(kwargs)
    return build_config(**defaults)


class TestConfig:
    def test_parsed_into_a_list(self, tmp_path):
        config = _config(
            tmp_path,
            product_releases='["app:v2.0.0"]',
            release_includes='["tools:tools-1.0.0", "runtime:3.1"]',
        )
        assert config.release_includes == ["tools:tools-1.0.0", "runtime:3.1"]

    def test_needs_a_product_release_to_include_into(self, tmp_path, caplog):
        with pytest.raises(SystemExit):
            _config(tmp_path, release_includes='["tools:tools-1.0.0"]')
        assert "needs PRODUCT_RELEASE" in caplog.text

    @pytest.mark.parametrize("value", ["not json", '"tools:1"', '["tools"]', '["tools:"]', '[":1"]', "[1]"])
    def test_malformed_values_are_refused(self, tmp_path, value, caplog):
        with pytest.raises(SystemExit):
            _config(tmp_path, product_releases='["app:v2.0.0"]', release_includes=value)
        assert "RELEASE_INCLUDES" in caplog.text


class TestProcessor:
    def _input(self, **kwargs: Any) -> ProcessorInput:
        return ProcessorInput(
            sbom_id="sbom-1",
            product_releases=["app:v2.0.0"],
            api_base_url="https://api.test",
            token="tok",
            **kwargs,
        )

    def _client(self) -> Mock:
        client = Mock()
        client.check_release_exists.return_value = True
        client.get_release_id.return_value = "rel-app"
        client.get_release_details.return_value = {"id": "rel-app", "version": "v2.0.0"}
        return client

    @patch("sbomify_action._processors.releases_api._client")
    def test_each_release_links_each_include(self, factory):
        client = self._client()
        factory.return_value = client

        result = SbomifyReleasesProcessor().process(self._input(release_includes=["tools:tools-1.0.0", "runtime:3.1"]))

        assert result.success
        assert [c.args for c in client.link_release.call_args_list] == [
            ("rel-app", "tools", "tools-1.0.0"),
            ("rel-app", "runtime", "3.1"),
        ]

    @patch("sbomify_action._processors.releases_api._client")
    def test_no_includes_links_nothing(self, factory):
        client = self._client()
        factory.return_value = client

        assert SbomifyReleasesProcessor().process(self._input()).success
        client.link_release.assert_not_called()

    @patch("sbomify_action._processors.releases_api._client")
    def test_a_failed_link_fails_the_run(self, factory):
        """A release that silently misses what it ships with is the failure this exists to prevent."""
        client = self._client()
        client.link_release.side_effect = APIError("Failed to include tools:tools-9 in release. [404]")
        factory.return_value = client

        result = SbomifyReleasesProcessor().process(self._input(release_includes=["tools:tools-9"]))

        assert not result.success
        assert "tools:tools-9" in result.error_message


class _Response:
    def __init__(self, status_code: int, body: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self._body = body
        self.headers = {"content-type": "application/json"}
        self.text = ""

    def json(self) -> Any:
        return self._body


def _client(response: _Response) -> tuple[SbomifyApiClient, MagicMock]:
    session = MagicMock(spec=requests.Session)
    session.request = MagicMock(return_value=response)
    return SbomifyApiClient("https://api.test", "tok", session=session), session


class TestClient:
    def test_links_by_product_and_version(self):
        client, session = _client(_Response(201, {"id": "rel-tools"}))

        client.link_release("rel-app", "tools", "tools-1.0.0")

        call = session.request.call_args
        assert call.args[0] == "POST" or call.kwargs.get("method") == "POST"
        url = call.kwargs.get("url") or call.args[1]
        assert url == "https://api.test/api/v1/releases/rel-app/links"
        assert call.kwargs["json"] == {"product_id": "tools", "version": "tools-1.0.0"}

    def test_an_existing_link_is_not_an_error(self):
        client, _ = _client(_Response(409, {"error_code": "CONFLICT", "detail": "This release is already linked"}))
        client.link_release("rel-app", "tools", "tools-1.0.0")

    def test_a_missing_release_raises(self):
        client, _ = _client(_Response(404, {"error_code": "RELEASE_NOT_FOUND", "detail": "Release to link not found"}))
        with pytest.raises(APIError, match="Release to link not found"):
            client.link_release("rel-app", "tools", "tools-9")
