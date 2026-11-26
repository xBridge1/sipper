"""The Configuracoes page: analysis thresholds and the FreeSWITCH profile.

Mixin of ``SipperWindow``; split out of ``ciper/gui/app.py``.
"""

from dataclasses import replace
from pathlib import Path
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)
from ciper.gui.widgets import PanelCard
from ciper.settings import save_settings


class SettingsPageMixin:
    def _build_settings_page(self):
        page = self._new_page("Configuracoes")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        card = PanelCard("Preferencias de Analise")
        content = QWidget()
        form = QGridLayout(content)
        form.setContentsMargins(0, 0, 0, 0)
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(14)

        self.settings_jitter = QDoubleSpinBox()
        self.settings_jitter.setRange(1.0, 500.0)
        self.settings_jitter.setDecimals(1)
        self.settings_jitter.setSuffix(" ms")

        self.settings_loss = QSpinBox()
        self.settings_loss.setRange(1, 100)
        self.settings_loss.setSuffix(" pacotes")

        self.settings_loss_percent = QDoubleSpinBox()
        self.settings_loss_percent.setRange(0.01, 50.0)
        self.settings_loss_percent.setDecimals(2)
        self.settings_loss_percent.setSingleStep(0.5)
        self.settings_loss_percent.setSuffix(" %")

        self.settings_traffic_points = QSpinBox()
        self.settings_traffic_points.setRange(60, 5000)
        self.settings_traffic_points.setSuffix(" pontos")

        self.settings_max_pcap_size = QSpinBox()
        self.settings_max_pcap_size.setRange(1, 10240)
        self.settings_max_pcap_size.setSuffix(" MB")

        self.settings_platform = QComboBox()
        self.settings_platform.addItem("SIP/RTP generico", "generic")
        self.settings_platform.addItem("FreeSWITCH", "freeswitch")
        self.settings_platform.currentIndexChanged.connect(
            self._update_platform_settings_state
        )

        self.settings_platform_ips = QLineEdit()
        self.settings_platform_ips.setPlaceholderText(
            "Ex.: 10.0.0.20, 10.0.0.21 ou 10.0.0.0/24"
        )

        self.settings_capture_point = QLineEdit()
        self.settings_capture_point.setPlaceholderText("Vazio = detectar automaticamente. Ex.: 10.0.0.20")
        self.settings_fs_codecs = QLineEdit()
        self.settings_fs_codecs.setPlaceholderText("Codecs aceitos pelo FreeSWITCH, ex.: PCMU,PCMA,G722,OPUS (vazio = nao verificar)")
        self.settings_fs_100rel = QCheckBox("enable-100rel (PRACK) habilitado")
        self.settings_fs_timer = QCheckBox("enable-timer (session timers) habilitado")
        self.settings_fs_srtp = QCheckBox("SRTP (rtp_secure_media) habilitado")
        self.settings_ignored_headers = QLineEdit()
        self.settings_ignored_headers.setPlaceholderText("Headers X- conhecidos que nao devem gerar alerta, ex.: X-Carrier-Route")
        self.settings_trusted_peers = QLineEdit()
        self.settings_trusted_peers.setPlaceholderText("IPs/redes de operadoras confiaveis, ex.: 200.1.1.0/24")
        fs_options = QWidget()
        fs_options_layout = QHBoxLayout(fs_options)
        fs_options_layout.setContentsMargins(0, 0, 0, 0)
        fs_options_layout.setSpacing(16)
        for checkbox in (self.settings_fs_100rel, self.settings_fs_timer, self.settings_fs_srtp):
            fs_options_layout.addWidget(checkbox)
        fs_options_layout.addStretch(1)

        self.settings_export_directory = QLineEdit()
        self.settings_export_directory.setReadOnly(True)
        self.settings_export_directory_button = QPushButton("Escolher pasta")
        self.settings_export_directory_button.setObjectName("secondaryButton")
        self.settings_export_directory_button.clicked.connect(self._choose_export_directory)
        export_row = QWidget()
        export_layout = QHBoxLayout(export_row)
        export_layout.setContentsMargins(0, 0, 0, 0)
        export_layout.setSpacing(8)
        export_layout.addWidget(self.settings_export_directory, 1)
        export_layout.addWidget(self.settings_export_directory_button)

        rows = [
            ("Jitter RTP alto", self.settings_jitter),
            ("Perda RTP para severidade alta", self.settings_loss_percent),
            ("Minimo de pacotes perdidos para alta", self.settings_loss),
            ("Maximo de pontos no grafico", self.settings_traffic_points),
            ("Tamanho maximo do PCAP", self.settings_max_pcap_size),
            ("Plataforma VoIP", self.settings_platform),
            ("IPs da plataforma monitorada", self.settings_platform_ips),
            ("Codecs aceitos pelo FreeSWITCH", self.settings_fs_codecs),
            ("Perfil Sofia", fs_options),
            ("Headers X- ignorados", self.settings_ignored_headers),
            ("Peers confiaveis", self.settings_trusted_peers),
            ("Ponto de captura (IP)", self.settings_capture_point),
            ("Pasta padrao para relatorios", export_row),
        ]
        for row, (label, widget) in enumerate(rows):
            form.addWidget(QLabel(label), row, 0)
            form.addWidget(widget, row, 1)

        self.settings_save_button = QPushButton("Salvar configuracoes")
        self.settings_save_button.setObjectName("primaryButton")
        self.settings_save_button.clicked.connect(self._save_settings)
        form.addWidget(self.settings_save_button, len(rows), 1, alignment=Qt.AlignRight)
        form.setColumnStretch(1, 1)
        card.add_widget(content)
        layout.addWidget(card)
        self._register_page_cards("Configuracoes", card)

    def _render_settings_page(self):
        self.settings_jitter.setValue(self.analysis_settings.rtp_high_jitter_threshold * 1000)
        self.settings_loss.setValue(self.analysis_settings.rtp_loss_high_threshold)
        self.settings_loss_percent.setValue(self.analysis_settings.rtp_loss_high_percent)
        self.settings_traffic_points.setValue(self.analysis_settings.max_traffic_points)
        self.settings_max_pcap_size.setValue(self.analysis_settings.max_pcap_size_mb)
        self._select_filter_value(
            self.settings_platform,
            self.analysis_settings.target_platform,
        )
        self.settings_platform_ips.setText(self.analysis_settings.target_platform_ips)
        self.settings_capture_point.setText(self.analysis_settings.capture_point_ip)
        self.settings_fs_codecs.setText(self.analysis_settings.freeswitch_codecs)
        self.settings_fs_100rel.setChecked(self.analysis_settings.freeswitch_100rel)
        self.settings_fs_timer.setChecked(self.analysis_settings.freeswitch_session_timer)
        self.settings_fs_srtp.setChecked(self.analysis_settings.freeswitch_srtp)
        self.settings_ignored_headers.setText(self.analysis_settings.ignored_custom_headers)
        self.settings_trusted_peers.setText(self.analysis_settings.trusted_peer_ips)
        self._update_platform_settings_state()
        self.settings_export_directory.setText(self.analysis_settings.export_directory)

    def _update_platform_settings_state(self):
        enabled = self.settings_platform.currentData() == "freeswitch"
        for widget in (
            self.settings_platform_ips,
            self.settings_fs_codecs,
            self.settings_fs_100rel,
            self.settings_fs_timer,
            self.settings_fs_srtp,
            self.settings_ignored_headers,
            self.settings_trusted_peers,
        ):
            widget.setEnabled(enabled)

    def _choose_export_directory(self):
        directory = QFileDialog.getExistingDirectory(
            self,
            "Escolha a pasta padrao para relatorios",
            self.settings_export_directory.text(),
        )
        if directory:
            self.settings_export_directory.setText(directory)

    def _save_settings(self):
        self.analysis_settings = replace(
            self.analysis_settings,
            rtp_high_jitter_threshold=self.settings_jitter.value() / 1000,
            rtp_loss_high_threshold=self.settings_loss.value(),
            rtp_loss_high_percent=self.settings_loss_percent.value(),
            max_traffic_points=self.settings_traffic_points.value(),
            max_pcap_size_mb=self.settings_max_pcap_size.value(),
            export_directory=self.settings_export_directory.text().strip() or str(Path.home()),
            target_platform=self.settings_platform.currentData() or "generic",
            target_platform_ips=self.settings_platform_ips.text().strip(),
            capture_point_ip=self.settings_capture_point.text().strip(),
            freeswitch_codecs=self.settings_fs_codecs.text().strip(),
            freeswitch_100rel=self.settings_fs_100rel.isChecked(),
            freeswitch_session_timer=self.settings_fs_timer.isChecked(),
            freeswitch_srtp=self.settings_fs_srtp.isChecked(),
            ignored_custom_headers=self.settings_ignored_headers.text().strip(),
            trusted_peer_ips=self.settings_trusted_peers.text().strip(),
        )
        try:
            save_settings(self.analysis_settings)
        except OSError as error:
            self._set_status(f"Falha ao salvar configuracoes: {error}")
            return
        self._set_status("Configuracoes salvas")
