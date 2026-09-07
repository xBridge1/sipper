import json

from ciper.updater import check_for_update


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def test_check_for_update_returns_newer_release_installer(monkeypatch):
    payload = {
        "tag_name": "v1.1.0",
        "html_url": "https://github.com/xBridge1/sipper/releases/tag/v1.1.0",
        "assets": [
            {
                "name": "SIPPER-Setup-1.1.0.exe",
                "browser_download_url": "https://github.com/xBridge1/sipper/releases/download/v1.1.0/SIPPER-Setup-1.1.0.exe",
            }
        ],
    }
    monkeypatch.setattr("ciper.updater.urlopen", lambda request, timeout: FakeResponse(payload))

    update = check_for_update("1.0.0")

    assert update.version == "1.1.0"
    assert update.download_url.endswith("SIPPER-Setup-1.1.0.exe")


def test_check_for_update_ignores_current_release(monkeypatch):
    payload = {
        "tag_name": "v1.0.0",
        "html_url": "https://github.com/xBridge1/sipper/releases/tag/v1.0.0",
        "assets": [],
    }
    monkeypatch.setattr("ciper.updater.urlopen", lambda request, timeout: FakeResponse(payload))

    assert check_for_update("1.0.0") is None
