import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging():
    logger = logging.getLogger("ciper")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    log_path = Path.home() / ".sipper" / "sipper.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)
    return logger
