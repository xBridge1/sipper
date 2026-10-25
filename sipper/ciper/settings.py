import json
from dataclasses import asdict, dataclass
from math import isfinite
from pathlib import Path


@dataclass
class AnalysisSettings:
    rtp_high_jitter_threshold: float = 0.04
    rtp_loss_high_threshold: int = 2
    max_traffic_points: int = 720
    max_pcap_size_mb: int = 1024
    export_directory: str = str(Path.home())
    target_platform: str = "generic"
    target_platform_ips: str = ""


def default_settings_path():
    return Path.home() / ".sipper" / "settings.json"


def load_settings(file_path=None):
    path = Path(file_path) if file_path else default_settings_path()
    if not path.is_file():
        return AnalysisSettings()

    try:
        values = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return AnalysisSettings()

    if not isinstance(values, dict):
        return AnalysisSettings()
    return _validate_settings(values)


def save_settings(settings, file_path=None):
    path = Path(file_path) if file_path else default_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")


def _validate_settings(values):
    defaults = AnalysisSettings()
    jitter = _valid_float(
        values.get("rtp_high_jitter_threshold"),
        defaults.rtp_high_jitter_threshold,
        0.001,
        0.5,
    )
    loss = _valid_int(
        values.get("rtp_loss_high_threshold"),
        defaults.rtp_loss_high_threshold,
        1,
        100,
    )
    traffic_points = _valid_int(
        values.get("max_traffic_points"),
        defaults.max_traffic_points,
        60,
        5000,
    )
    max_pcap_size = _valid_int(
        values.get("max_pcap_size_mb"),
        defaults.max_pcap_size_mb,
        1,
        10240,
    )
    export_directory = values.get("export_directory")
    if not isinstance(export_directory, str) or not export_directory.strip():
        export_directory = defaults.export_directory
    target_platform = values.get("target_platform")
    if target_platform not in {"generic", "freeswitch"}:
        target_platform = defaults.target_platform
    target_platform_ips = values.get("target_platform_ips")
    if not isinstance(target_platform_ips, str):
        target_platform_ips = defaults.target_platform_ips

    return AnalysisSettings(
        rtp_high_jitter_threshold=jitter,
        rtp_loss_high_threshold=loss,
        max_traffic_points=traffic_points,
        max_pcap_size_mb=max_pcap_size,
        export_directory=export_directory,
        target_platform=target_platform,
        target_platform_ips=target_platform_ips,
    )


def _valid_float(value, default, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    value = float(value)
    return value if isfinite(value) and minimum <= value <= maximum else default


def _valid_int(value, default, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value if minimum <= value <= maximum else default
