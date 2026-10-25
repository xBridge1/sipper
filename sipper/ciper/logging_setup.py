import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from tempfile import gettempdir


def configure_logging():
    logger = logging.getLogger("ciper")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    handler = None
    for log_path in (
        Path.home() / ".sipper" / "sipper.log",
        Path(gettempdir()) / "SIPPER" / "sipper.log",
    ):
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                log_path,
                maxBytes=1_000_000,
                backupCount=3,
                encoding="utf-8",
            )
            break
        except OSError:
            continue
    if handler is None:
        handler = logging.NullHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)
    return logger
