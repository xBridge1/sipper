import json
from pathlib import Path

from ciper.settings import AnalysisSettings, load_settings, save_settings


def test_settings_are_saved_and_loaded(tmp_path):
    file_path = tmp_path / "settings.json"
    settings = AnalysisSettings(
        rtp_high_jitter_threshold=0.08,
        rtp_loss_high_threshold=4,
        max_traffic_points=360,
        max_pcap_size_mb=256,
        export_directory="C:/reports",
        target_platform="freeswitch",
        target_platform_ips="10.0.0.20, 10.0.0.21",
    )

    save_settings(settings, file_path)

    assert load_settings(file_path) == settings


def test_missing_settings_file_uses_defaults(tmp_path):
    settings = load_settings(tmp_path / "missing.json")

    assert settings == AnalysisSettings()


def test_invalid_settings_values_fall_back_to_safe_defaults(tmp_path):
    file_path = tmp_path / "settings.json"
    file_path.write_text(
        json.dumps(
            {
                "rtp_high_jitter_threshold": "invalid",
                "rtp_loss_high_threshold": True,
                "max_traffic_points": 0,
                "max_pcap_size_mb": -1,
                "export_directory": 42,
                "target_platform": "unsupported",
                "target_platform_ips": ["10.0.0.20"],
            }
        ),
        encoding="utf-8",
    )

    settings = load_settings(file_path)

    assert settings == AnalysisSettings(export_directory=str(Path.home()))


def test_settings_with_invalid_encoding_use_defaults(tmp_path):
    file_path = tmp_path / "settings.json"
    file_path.write_bytes(b"\xff\xfe\x00")

    assert load_settings(file_path) == AnalysisSettings()
