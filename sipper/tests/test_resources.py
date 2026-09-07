import sys

from ciper.resources import resource_path


def test_resource_path_uses_pyinstaller_bundle_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    assert resource_path("logo", "splash.png") == tmp_path / "logo" / "splash.png"
