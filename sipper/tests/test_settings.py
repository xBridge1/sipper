from ciper.settings import AnalysisSettings, load_settings, save_settings


def test_settings_are_saved_and_loaded(tmp_path):
    file_path = tmp_path / "settings.json"
    settings = AnalysisSettings(
        rtp_high_jitter_threshold=0.08,
        rtp_loss_high_threshold=4,
        max_traffic_points=360,
        max_pcap_size_mb=256,
        export_directory="C:/reports",
    )

    save_settings(settings, file_path)

    assert load_settings(file_path) == settings


def test_missing_settings_file_uses_defaults(tmp_path):
    settings = load_settings(tmp_path / "missing.json")

    assert settings == AnalysisSettings()
