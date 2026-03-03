import pytest
import requests
from ml.zap_integration.zap_client import ZAPClient, ZAPConfigError, ZAPConnectionError, ZAPTimeoutError


class DummyResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class DummySession:
    def __init__(self, responses):
        self.responses = responses
        self.request_count = 0

    def request(self, method, url, params=None, json=None, timeout=None):
        if self.request_count >= len(self.responses):
            raise requests.RequestException("no more responses")
        resp = self.responses[self.request_count]
        self.request_count += 1
        return resp


def test_invalid_config():
    with pytest.raises(ZAPConfigError):
        ZAPClient(host="", port=8080)
    with pytest.raises(ZAPConfigError):
        ZAPClient(host="localhost", port=99999)
    with pytest.raises(ZAPConfigError):
        ZAPClient(host="localhost", port=8080, api_key="!notgood")


def test_request_retries(monkeypatch):
    client = ZAPClient(host="localhost", port=8080, api_key="")
    # override session with dummy that returns 500 twice then 200
    client.session = DummySession([
        DummyResponse(status_code=500, text="error"),
        DummyResponse(status_code=500, text="error"),
        DummyResponse(status_code=200, json_data={"ok": True}),
    ])
    # should succeed after retries
    result = client.request("GET", "core/view/version")
    assert result == {"ok": True}
    assert client.session.request_count == 3


def test_timeout(monkeypatch):
    client = ZAPClient(host="localhost", port=8080, api_key="")
    def raise_timeout(*args, **kwargs):
        raise requests.Timeout()

    client.session = DummySession([])
    client.session.request = raise_timeout
    with pytest.raises(ZAPTimeoutError):
        client.request("GET", "core/view/version", retry_count=2)


def test_get_status(monkeypatch):
    client = ZAPClient(host="localhost", port=8080, api_key="")
    # stub get_version
    monkeypatch.setattr(client, "get_version", lambda: {"version": "2.1"})
    status = client.get_status()
    assert status["status"] == "connected"
    assert status["version"] == "2.1"


# more tests could follow
