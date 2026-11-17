"""Offscreen smoke tests for the main window workflow."""

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

QtWidgets = pytest.importorskip("PySide6.QtWidgets")
from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "teste_sip_rtp_problemas.pcap"


@pytest.fixture
def window(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    import ciper.gui.app as gui

    monkeypatch.setattr(gui.SipperWindow, "_check_for_update", lambda self: None)
    created = gui.SipperWindow()
    yield created
    created.close()
    app.processEvents()


def _wait_for_analysis(window, timeout_ms=30000):
    waited = 0
    while window.analysis_thread is not None and waited < timeout_ms:
        loop = QEventLoop()
        QTimer.singleShot(50, loop.quit)
        loop.exec()
        waited += 50
    assert window.analysis_thread is None, "analysis did not finish"


def test_welcome_screen_is_shown_before_any_analysis(window):
    window.show()

    assert window.welcome_card.isVisibleTo(window)
    assert not window.summary_metrics.isVisibleTo(window)
    assert not window.cancel_button.isVisibleTo(window)


def test_open_capture_runs_analysis_and_remembers_file(window, tmp_path):
    window.show()

    window.open_capture(str(SAMPLE))
    _wait_for_analysis(window)

    assert window.last_viewmodel is not None
    assert not window.welcome_card.isVisibleTo(window)
    assert window.windowTitle() == f"SIPPER - {SAMPLE.name}"
    assert window.status_bar_label.text().startswith("Analise concluida em")
    assert window.analysis_settings.recent_files[0] == str(SAMPLE)
    assert (tmp_path / ".sipper" / "settings.json").is_file()
    titles = [window.findings_table.item(row, 2).text() for row in range(window.findings_table.rowCount())]
    assert "Perda de pacotes RTP" in titles
    assert all("_" not in title for title in titles)


def test_missing_file_reports_error_without_starting(window):
    window.open_capture("C:/nao/existe/captura.pcap")

    assert window.analysis_thread is None
    assert "nao encontrado" in window.status_bar_label.text()
