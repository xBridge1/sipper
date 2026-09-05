import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class AnalysisSettings:
    rtp_high_jitter_threshold: float = 0.04
    rtp_loss_high_threshold: int = 2
    max_traffic_points: int = 720
    max_pcap_size_mb: int = 1024
    export_directory: str = str(Path.home())


def default_settings_path():
    return Path.home() / ".sipper" / "settings.json"


def load_settings(file_path=None):
    path = Path(file_path) if file_path else default_settings_path()
    if not path.is_file():
        return AnalysisSettings()

    try:
        values = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return AnalysisSettings()

    defaults = asdict(AnalysisSettings())
    if not isinstance(values, dict):
        return AnalysisSettings()
    defaults.update({key: value for key, value in values.items() if key in defaults})

    try:
        return AnalysisSettings(**defaults)
    except (TypeError, ValueError):
        return AnalysisSettings()


def save_settings(settings, file_path=None):
    path = Path(file_path) if file_path else default_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")
