import logging

from ciper.logging_setup import configure_logging


def test_logging_falls_back_when_user_profile_is_not_writable(tmp_path, monkeypatch):
    blocked_home = tmp_path / "blocked"
    blocked_home.write_text("not a directory", encoding="utf-8")
    monkeypatch.setattr("ciper.logging_setup.Path.home", lambda: blocked_home)
    monkeypatch.setattr("ciper.logging_setup.gettempdir", lambda: str(tmp_path / "fallback"))
    logger = logging.getLogger("ciper")
    original_handlers = list(logger.handlers)
    logger.handlers.clear()

    try:
        configured = configure_logging()

        configured.info("fallback log test")
        assert configured.handlers
    finally:
        for handler in logger.handlers:
            handler.close()
        logger.handlers[:] = original_handlers
