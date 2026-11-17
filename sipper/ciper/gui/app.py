import sys
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QEasingCurve, QSize, QPropertyAnimation, QThread, QTimer, QUrl, Qt
from PySide6.QtGui import QAction, QColor, QDesktopServices, QIcon, QKeySequence, QPixmap, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGraphicsOpacityEffect,
    QHeaderView,
    QHBoxLayout,
    QLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QPushButton,
    QProgressBar,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QStyle,
)

from ciper.gui.evidence import build_finding_evidence_context
from ciper.labels import SEVERITY_ORDER, finding_title, is_actionable, severity_label, state_label
from ciper.gui.styles import build_stylesheet
from ciper.gui.theme import THEMES
from ciper.gui.viewmodels import build_dashboard_viewmodel
from ciper.gui.widgets import (
    BarChart,
    CallFlowWidget,
    DonutChart,
    KPIStat,
    MetricGrid,
    PanelCard,
    SIPLadderWidget,
    StreamTimelineChart,
    TrafficChart,
    _font,
    make_nav_icon,
)
from ciper.gui.workers import AnalysisWorker, UpdateCheckWorker
from ciper.reporting import build_report_payload, export_csv, export_json, export_pdf
from ciper.resources import resource_path
from ciper.settings import add_recent_file, load_settings, save_settings
from ciper.voip_quality import (
    LOSS_HIGH_QUALITY_PERCENT,
    LOSS_TARGET_PERCENT,
    jitter_observation,
    mos_observation,
    packet_loss_observation,
    quality_reference_note,
)
from ciper.updater import CURRENT_VERSION


CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
LOGO_ICON_PATH = resource_path("logo", "e4d70232-e1e2-4761-bd1b-dc88ac325f6e.png")
LOGO_PREVIEW_PATH = resource_path("logo", "9761bd23-eb2a-4777-8de4-2910814a3f4c.png")
DARK_SPLASH_LOGO_PATH = resource_path("logo", "splash.png")
LIGHT_SPLASH_LOGO_PATH = resource_path("logo", "splash_black.png")



class SipperWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIPPER")
        self.setWindowIcon(QIcon(str(LOGO_ICON_PATH)))
        self.resize(1600, 1000)
        self.setMinimumSize(1180, 720)
        self.analysis_settings = load_settings()
        self.current_theme = self.analysis_settings.theme
        self.analysis_started_at = None
        self.analyzed_file = None
        self.last_viewmodel = None
        self.last_engine_result = None
        self.last_packets = []
        self.last_packet_analysis = None
        self.last_traffic_series = []
        self.last_traffic_labels = []
        self.capture_duration = 0.0
        self.call_index = {}
        self.finding_index = {}
        self.selected_call_id = None
        self.selected_finding_key = None
        self.analysis_thread = None
        self.analysis_worker = None
        self.update_thread = None
        self.update_worker = None
        self.available_update = None
        self.page_buttons = {}
        self.rtp_nav_buttons = {}
        self.sip_nav_buttons = {}
        self.network_nav_buttons = {}
        self.security_nav_buttons = {}
        self.page_widgets = {}
        self.page_cards = {}
        self.nav_icon_buttons = []
        self.nav_sections = {}
        self.selected_stream_key = None
        self.active_animations = []
        self.setAcceptDrops(True)
        self._build_ui()
        self._install_shortcuts()
        self._apply_theme()
        self._render_all()
        QTimer.singleShot(1500, self._check_for_update)

    def _build_ui(self):
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(8, 8, 8, 8)
        root_layout.setSpacing(8)
        self.setCentralWidget(root)

        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setMinimumWidth(250)
        self.sidebar.setMaximumWidth(290)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(18, 16, 14, 14)
        sidebar_layout.setSpacing(10)

        self.brand_splash = QLabel()
        self.brand_splash.setAlignment(Qt.AlignCenter)
        self.brand_splash.setMinimumHeight(72)
        sidebar_layout.addWidget(self.brand_splash)

        theme_row = QHBoxLayout()
        theme_label = QLabel("Tema")
        theme_label.setFont(_font("subtitle"))
        self.theme_toggle = QFrame()
        self.theme_toggle.setObjectName("themeToggle")
        self.theme_toggle_layout = QHBoxLayout(self.theme_toggle)
        self.theme_toggle_layout.setContentsMargins(4, 4, 4, 4)
        self.theme_toggle_layout.setSpacing(8)
        self.theme_group = QButtonGroup(self)
        self.dark_radio = QRadioButton("Dark")
        self.light_radio = QRadioButton("Light")
        self.dark_radio.setChecked(True)
        self.theme_group.addButton(self.dark_radio)
        self.theme_group.addButton(self.light_radio)
        self.dark_radio.toggled.connect(self._on_theme_radio_changed)
        self.theme_toggle_layout.addWidget(self.dark_radio)
        self.theme_toggle_layout.addWidget(self.light_radio)
        theme_row.addWidget(theme_label)
        theme_row.addStretch(1)
        theme_row.addWidget(self.theme_toggle)
        sidebar_layout.addLayout(theme_row)

        nav_sections = (
            (
                "Inicio",
                [
                    ("Visao geral", "Resumo", None, None),
                    ("Diagnostico", "Diagnostico", None, None),
                ],
            ),
            (
                "Chamadas",
                [
                    ("Todas as chamadas", "SIP", "sip", "all"),
                    ("Falhas de sinalizacao", "SIP", "sip", "errors"),
                    ("Headers e MTU", "SIP", "sip", "headers"),
                    ("Compatibilidade", "SIP", "sip", "freeswitch"),
                ],
            ),
            (
                "Midia RTP",
                [
                    ("Todos os streams", "RTP", "rtp", "all"),
                    ("Jitter", "RTP", "rtp", "jitter"),
                    ("Packet Loss", "RTP", "rtp", "loss"),
                    ("Out-of-Order", "RTP", "rtp", "out_of_order"),
                    ("Codecs", "RTP", "rtp", "codecs"),
                ],
            ),
            (
                "Rede e Seguranca",
                [
                    ("TCP", "Rede", "network", "tcp"),
                    ("UDP", "Rede", "network", "udp"),
                    ("ICMP", "Rede", "network", "icmp"),
                    ("TLS", "Seguranca", "security", "tls"),
                    ("Fragmentacao", "Seguranca", "security", "fragmentation"),
                ],
            ),
            ("Sistema", [("Estatisticas", "Estatisticas", None, None), ("Configuracoes", "Configuracoes", None, None), ("Sobre", "Sobre", None, None)]),
        )
        self.nav_scroll = QScrollArea()
        self.nav_scroll.setObjectName("navigationScroll")
        self.nav_scroll.setWidgetResizable(True)
        self.nav_scroll.setFrameShape(QFrame.NoFrame)
        self.nav_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.nav_scroll.setFocusPolicy(Qt.NoFocus)
        self.nav_scroll.verticalScrollBar().setSingleStep(32)
        self.nav_scroll.verticalScrollBar().setPageStep(160)
        nav_content = QWidget()
        nav_content.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        nav_layout = QVBoxLayout(nav_content)
        nav_layout.setContentsMargins(0, 0, 4, 0)
        nav_layout.setSpacing(2)
        nav_layout.setSizeConstraint(QLayout.SetMinimumSize)
        self.nav_scroll.setWidget(nav_content)

        for title, pages in nav_sections:
            section_button = QPushButton(f"\u25BE  {title.upper()}")
            section_button.setObjectName("navSection")
            section_button.setCursor(Qt.PointingHandCursor)
            section_button.setToolTip("Clique para recolher ou expandir")
            section_button.clicked.connect(lambda _checked=False, name=title: self._toggle_nav_section(name))
            nav_layout.addWidget(section_button)
            self.nav_sections[title] = {"header": section_button, "buttons": [], "expanded": True}
            for label_text, page, filter_group, filter_name in pages:
                button = QPushButton(label_text)
                button.setObjectName("navButton")
                self.nav_icon_buttons.append((button, page))
                self.nav_sections[title]["buttons"].append(button)
                if filter_group is None:
                    button.clicked.connect(lambda _checked=False, name=page: self._set_page(name))
                    self.page_buttons[page] = button
                elif filter_group == "rtp":
                    button.clicked.connect(
                        lambda _checked=False, name=filter_name: self._set_rtp_filter(name)
                    )
                    self.rtp_nav_buttons[filter_name] = button
                elif filter_group == "sip":
                    button.clicked.connect(
                        lambda _checked=False, name=filter_name: self._set_sip_filter(name)
                    )
                    self.sip_nav_buttons[filter_name] = button
                elif filter_group == "security":
                    button.clicked.connect(
                        lambda _checked=False, name=filter_name: self._set_security_filter(name)
                    )
                    self.security_nav_buttons[filter_name] = button
                else:
                    button.clicked.connect(
                        lambda _checked=False, name=filter_name: self._set_network_filter(name)
                    )
                    self.network_nav_buttons[filter_name] = button
                button.setMinimumHeight(30)
                button.setIconSize(QSize(16, 16))
                button.setCursor(Qt.PointingHandCursor)
                nav_layout.addWidget(button)
        nav_layout.addStretch(1)
        sidebar_layout.addWidget(self.nav_scroll, 1)
        # The status lives in the window footer; the sidebar copy is kept only
        # as an attribute for compatibility and stays hidden.
        self.sidebar_status = QLabel("Pronto")
        self.sidebar_status.setFont(_font("small"))
        self.sidebar_status.setVisible(False)
        sidebar_layout.addWidget(self.sidebar_status)

        self.content = QWidget()
        content_layout = QVBoxLayout(self.content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(8)

        self.toolbar = QFrame()
        toolbar_layout = QHBoxLayout(self.toolbar)
        toolbar_layout.setContentsMargins(18, 14, 18, 14)
        toolbar_layout.setSpacing(12)
        toolbar_layout.addWidget(QLabel("Arquivo PCAP:"))
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Arraste um .pcap/.pcapng para a janela ou clique em Abrir PCAP")
        self.file_input.returnPressed.connect(self._analyze_file)
        self.file_input.setMinimumWidth(220)
        toolbar_layout.addWidget(self.file_input, 1)
        self.open_button = QPushButton("Abrir PCAP")
        self.open_button.setObjectName("secondaryButton")
        self.open_button.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
        self.open_button.clicked.connect(self._choose_file)
        self.open_button.setToolTip("Abrir e analisar uma captura (Ctrl+O)")
        self.recent_button = QPushButton("Recentes")
        self.recent_button.setObjectName("secondaryButton")
        self.recent_menu = QMenu(self.recent_button)
        self.recent_button.setMenu(self.recent_menu)
        self.recent_button.setToolTip("Capturas analisadas recentemente")
        self.analyze_button = QPushButton("Analisar")
        self.analyze_button.setObjectName("primaryButton")
        self.analyze_button.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        self.analyze_button.clicked.connect(self._analyze_file)
        self.analyze_button.setToolTip("Analisar novamente o arquivo atual (F5)")
        self.export_button = QPushButton("Exportar")
        self.export_button.setObjectName("secondaryButton")
        self.export_button.setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export_report)
        self.export_button.setToolTip("Exportar relatorio JSON, CSV ou PDF (Ctrl+E)")
        self.cancel_button = QPushButton("Cancelar")
        self.cancel_button.setObjectName("secondaryButton")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel_analysis)
        self.cancel_button.setToolTip("Cancelar a analise em andamento (Esc)")
        self.cancel_button.setVisible(False)
        self.analysis_progress = QProgressBar()
        self.analysis_progress.setRange(0, 100)
        self.analysis_progress.setValue(0)
        self.analysis_progress.setTextVisible(True)
        self.analysis_progress.setFormat("%p%")
        self.analysis_progress.setFixedWidth(160)
        self.analysis_progress.setVisible(False)
        self.page_badge = QLabel("Resumo")
        self.page_badge.setObjectName("pageBadge")
        self.page_badge.setVisible(False)
        toolbar_layout.addWidget(self.open_button)
        toolbar_layout.addWidget(self.recent_button)
        toolbar_layout.addWidget(self.analyze_button)
        toolbar_layout.addWidget(self.cancel_button)
        toolbar_layout.addWidget(self.export_button)
        toolbar_layout.addWidget(self.analysis_progress)
        toolbar_layout.addStretch(1)
        toolbar_layout.addWidget(self.page_badge)

        self.pages = QStackedWidget()
        self._build_pages()
        self._rebuild_recent_menu()

        self.status_bar_label = QLabel("Pronto")
        self.status_bar_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.status_bar_label.setFont(_font("small"))

        content_layout.addWidget(self.toolbar)
        content_layout.addWidget(self.pages, 1)
        content_layout.addWidget(self.status_bar_label)

        root_layout.addWidget(self.sidebar)
        root_layout.addWidget(self.content, 1)

    def _build_pages(self):
        self._build_summary_page()
        self._build_diagnostic_page()
        self._build_sip_page()
        self._build_rtp_page()
        self._build_network_page()
        self._build_security_page()
        self._build_findings_page()
        self._build_statistics_page()
        self._build_settings_page()
        self._build_about_page()

    def _new_page(self, name):
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        page = QWidget()
        page.setMinimumWidth(0)
        scroll_area.setWidget(page)
        effect = QGraphicsOpacityEffect(page)
        effect.setOpacity(1.0)
        page.setGraphicsEffect(effect)
        self.pages.addWidget(scroll_area)
        self.page_widgets[name] = scroll_area
        self.page_cards[name] = []
        return page

    def _register_page_cards(self, name, *cards):
        self.page_cards[name].extend(cards)

    def _new_grid_page(self, name, columns, rows):
        page = self._new_page(name)
        layout = QGridLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        for index, stretch in enumerate(columns):
            layout.setColumnStretch(index, stretch)
        for index, stretch in enumerate(rows):
            layout.setRowStretch(index, stretch)
        return page, layout

    def _build_summary_page(self):
        _page, layout = self._new_grid_page("Resumo", [4, 4, 3], [0, 1, 1])
        self.summary_metrics = PanelCard("Resumo da captura")
        self.summary_protocols = PanelCard("Protocolos")
        self.summary_findings = PanelCard("Findings")
        self.summary_calls = PanelCard("Chamadas SIP Detectadas")
        self.summary_rtp_streams = PanelCard("RTP Flows (Resumo)")
        self.summary_call_detail = PanelCard("Detalhes da Chamada")
        self.summary_recent_findings = PanelCard("Incidentes prioritarios")
        self.summary_traffic = PanelCard("Grafico de Trafego")

        self.summary_kpi_row = QWidget()
        self.summary_kpi_layout = QGridLayout(self.summary_kpi_row)
        self.summary_kpi_layout.setContentsMargins(0, 0, 0, 0)
        self.summary_kpi_layout.setSpacing(10)
        self.kpi_packets = KPIStat("Pacotes")
        self.kpi_calls = KPIStat("Chamadas")
        self.kpi_streams = KPIStat("Streams RTP")
        self.kpi_findings = KPIStat("Problemas")
        self.kpi_high = KPIStat("Severidade alta")
        self.kpi_mos = KPIStat("MOS medio")
        self.kpi_duration = KPIStat("Duracao")
        self.kpi_protocols = KPIStat("Protocolos")
        for index, widget in enumerate(
            (
                self.kpi_packets,
                self.kpi_calls,
                self.kpi_streams,
                self.kpi_findings,
                self.kpi_high,
                self.kpi_mos,
                self.kpi_duration,
                self.kpi_protocols,
            )
        ):
            self.summary_kpi_layout.addWidget(widget, index // 4, index % 4)
        self.summary_protocol_chart = DonutChart()
        self.summary_findings_chart = BarChart()
        self.summary_calls_table = self._make_calls_table()
        self.summary_rtp_table = self._make_rtp_table()
        self.summary_flow = CallFlowWidget()
        self.summary_sip_flow_button = QPushButton("Abrir SIP Flow")
        self.summary_sip_flow_button.setObjectName("secondaryButton")
        self.summary_sip_flow_button.clicked.connect(self._open_sip_flow_dialog)
        self.summary_detail_text = self._make_text()
        self.summary_findings_table = self._make_incident_table()
        self.summary_findings_table.doubleClicked.connect(lambda _index: self._set_page("Diagnostico"))
        self.summary_findings_table.setToolTip("Clique duplo para abrir o diagnostico completo")
        self.summary_traffic_chart = TrafficChart()

        self.summary_metrics.add_widget(self.summary_kpi_row)
        self.summary_metrics.body_layout.addStretch(1)
        self.summary_protocols.add_widget(self.summary_protocol_chart)
        self.summary_findings.add_widget(self.summary_findings_chart)
        self.summary_calls.add_widget(self.summary_calls_table)
        self.summary_rtp_streams.add_widget(self.summary_rtp_table)
        self.summary_call_detail.add_widget(self.summary_flow)
        self.summary_call_detail.add_widget(self.summary_sip_flow_button)
        self.summary_call_detail.add_widget(self.summary_detail_text)
        self.summary_recent_findings.add_widget(self.summary_findings_table)
        self.summary_traffic.add_widget(self.summary_traffic_chart, 1)

        layout.addWidget(self.summary_metrics, 0, 0)
        layout.addWidget(self.summary_protocols, 0, 1)
        layout.addWidget(self.summary_findings, 0, 2)
        layout.addWidget(self.summary_recent_findings, 1, 0, 1, 3)
        layout.addWidget(self.summary_traffic, 2, 0, 1, 3)
        self.welcome_card = self._build_welcome_card()
        layout.addWidget(self.welcome_card, 0, 0, 3, 3)
        self._register_page_cards(
            "Resumo",
            self.summary_metrics,
            self.summary_protocols,
            self.summary_findings,
            self.summary_recent_findings,
            self.summary_traffic,
        )

    def _build_diagnostic_page(self):
        _page, layout = self._new_grid_page("Diagnostico", [4, 5], [0, 1])
        self.diagnostic_priority = PanelCard("Prioridade de acao")
        self.diagnostic_scope = PanelCard("Escopo do impacto")
        self.diagnostic_incidents = PanelCard("Fila de incidentes")
        self.diagnostic_detail = PanelCard("Evidencia e proxima acao")
        self.diagnostic_priority_text = MetricGrid(columns=2)
        self.diagnostic_scope_text = MetricGrid(columns=2)
        self.diagnostic_incidents_table = self._make_incident_table()
        self.diagnostic_detail_text = self._make_text()
        self.diagnostic_priority.add_widget(self.diagnostic_priority_text)
        self.diagnostic_scope.add_widget(self.diagnostic_scope_text)
        self.diagnostic_incidents.add_widget(self.diagnostic_incidents_table)
        self.diagnostic_detail.add_widget(self.diagnostic_detail_text)
        layout.addWidget(self.diagnostic_priority, 0, 0)
        layout.addWidget(self.diagnostic_scope, 0, 1)
        layout.addWidget(self.diagnostic_incidents, 1, 0)
        layout.addWidget(self.diagnostic_detail, 1, 1)
        self._register_page_cards(
            "Diagnostico",
            self.diagnostic_priority,
            self.diagnostic_scope,
            self.diagnostic_incidents,
            self.diagnostic_detail,
        )

    def _build_sip_page(self):
        _page, layout = self._new_grid_page("SIP", [5, 4], [0, 1])
        self.sip_state = PanelCard("Estado da sinalizacao")
        self.sip_findings = PanelCard("Falhas de sinalizacao")
        self.sip_calls = PanelCard("Chamadas filtradas")
        self.sip_detail = PanelCard("Jornada da chamada")
        self.sip_state_text = MetricGrid(columns=3)
        self.sip_findings_text = self._make_text()
        self.sip_findings_text.setMaximumHeight(170)
        self.sip_calls_table = self._make_calls_table()
        self.sip_filter = QComboBox()
        self.sip_filter.addItem("Todos os fluxos", "all")
        self.sip_filter.addItem("Com erro de sinalizacao", "errors")
        self.sip_filter.addItem("Headers e MTU", "headers")
        self.sip_filter.addItem("Analise de chamadas", "analysis")
        self.sip_filter.addItem("Compatibilidade FreeSWITCH", "freeswitch")
        self.sip_filter.currentIndexChanged.connect(self._on_sip_filter_changed)
        self.sip_search = QLineEdit()
        self.sip_search.setPlaceholderText("Buscar Call-ID ou IP")
        self.sip_search.textChanged.connect(self._render_sip_page)
        self.sip_time_range = QLineEdit()
        self.sip_time_range.setPlaceholderText("Tempo relativo, ex.: 0-30 s")
        self.sip_time_range.textChanged.connect(self._render_sip_page)
        self.sip_flow = CallFlowWidget()
        self.sip_open_flow_button = QPushButton("Abrir SIP Flow")
        self.sip_open_flow_button.setObjectName("secondaryButton")
        self.sip_open_flow_button.clicked.connect(self._open_sip_flow_dialog)
        self.sip_detail_text = self._make_text()
        self.sip_state.add_widget(self.sip_state_text)
        self.sip_findings.add_widget(self.sip_findings_text)
        # The filter is driven by the sidebar entries; the combo stays as state.
        self.sip_filter.setVisible(False)
        self.sip_calls.add_widget(self.sip_filter)
        self.sip_calls.add_widget(self.sip_search)
        self.sip_calls.add_widget(self.sip_time_range)
        self.sip_calls.add_widget(self.sip_calls_table)
        self.sip_detail.add_widget(self.sip_flow)
        self.sip_detail.add_widget(self.sip_open_flow_button)
        self.sip_detail.add_widget(self.sip_detail_text)
        layout.addWidget(self.sip_state, 0, 0)
        layout.addWidget(self.sip_findings, 0, 1)
        layout.addWidget(self.sip_calls, 1, 0)
        layout.addWidget(self.sip_detail, 1, 1)
        self._register_page_cards("SIP", self.sip_state, self.sip_findings, self.sip_calls, self.sip_detail)

    def _build_rtp_page(self):
        _page, layout = self._new_grid_page("RTP", [5, 4], [1, 1])
        self.rtp_streams = PanelCard("Streams e codecs")
        self.rtp_health = PanelCard("Qualidade do stream selecionado")
        self.rtp_calls = PanelCard("Chamadas com midia")
        self.rtp_detail = PanelCard("Contexto da chamada")
        self.rtp_streams_table = self._make_rtp_table()
        self.rtp_filter = QComboBox()
        self.rtp_filter.addItem("Todos os streams", "all")
        self.rtp_filter.addItem("Com jitter", "jitter")
        self.rtp_filter.addItem("Com perda", "loss")
        self.rtp_filter.addItem("Fora de ordem", "out_of_order")
        self.rtp_filter.addItem("Com codec identificado", "codecs")
        self.rtp_filter.currentIndexChanged.connect(self._on_rtp_filter_changed)
        self.rtp_search = QLineEdit()
        self.rtp_search.setPlaceholderText("Buscar IP, SSRC ou codec")
        self.rtp_search.textChanged.connect(self._render_rtp_page)
        self.rtp_health_text = MetricGrid(columns=3)
        self.rtp_timeline = StreamTimelineChart()
        self.rtp_findings_text = self._make_text()
        self.rtp_findings_text.setMaximumHeight(100)
        self.rtp_streams_table.itemSelectionChanged.connect(self._on_stream_selected)
        self.rtp_calls_table = self._make_calls_table()
        self.rtp_flow = CallFlowWidget()
        self.rtp_detail_text = self._make_text()
        self.rtp_filter.setVisible(False)
        self.rtp_streams.add_widget(self.rtp_filter)
        self.rtp_streams.add_widget(self.rtp_search)
        self.rtp_streams.add_widget(self.rtp_streams_table)
        self.rtp_health.add_widget(self.rtp_health_text)
        self.rtp_health.add_widget(self.rtp_timeline, 1)
        self.rtp_health.add_widget(self.rtp_findings_text)
        self.rtp_calls.add_widget(self.rtp_calls_table)
        self.rtp_detail.add_widget(self.rtp_flow)
        self.rtp_detail.add_widget(self.rtp_detail_text)
        layout.addWidget(self.rtp_streams, 0, 0)
        layout.addWidget(self.rtp_health, 0, 1)
        layout.addWidget(self.rtp_calls, 1, 0)
        layout.addWidget(self.rtp_detail, 1, 1)
        self._register_page_cards("RTP", self.rtp_streams, self.rtp_health, self.rtp_calls, self.rtp_detail)

    def _build_network_page(self):
        _page, layout = self._new_grid_page("Rede", [4, 5], [0, 1])
        self.network_protocols = PanelCard("Contexto de rede")
        self.network_health = PanelCard("Falhas da camada")
        self.network_events = PanelCard("Eventos TCP, UDP e ICMP")
        self.network_detail = PanelCard("Evidencia do evento")
        self.network_protocols_text = MetricGrid(columns=3)
        self.network_health_text = self._make_text()
        self.network_health_text.setMaximumHeight(170)
        self.network_events_table = self._make_findings_table()
        self.network_filter = QComboBox()
        self.network_filter.addItem("Todos os eventos", "all")
        self.network_filter.addItem("TCP", "tcp")
        self.network_filter.addItem("UDP", "udp")
        self.network_filter.addItem("ICMP", "icmp")
        self.network_filter.currentIndexChanged.connect(self._on_network_filter_changed)
        self.network_search = QLineEdit()
        self.network_search.setPlaceholderText("Buscar IP ou tipo de evento")
        self.network_search.textChanged.connect(self._render_network_page)
        self.network_detail_text = self._make_text()
        self.network_protocols.add_widget(self.network_protocols_text)
        self.network_health.add_widget(self.network_health_text)
        self.network_events.add_widget(self.network_search)
        self.network_events.add_widget(self.network_events_table)
        self.network_detail.add_widget(self.network_detail_text)
        layout.addWidget(self.network_protocols, 0, 0)
        layout.addWidget(self.network_health, 0, 1)
        layout.addWidget(self.network_events, 1, 0)
        layout.addWidget(self.network_detail, 1, 1)
        self._register_page_cards("Rede", self.network_protocols, self.network_health, self.network_events, self.network_detail)

    def _build_security_page(self):
        _page, layout = self._new_grid_page("Seguranca", [4, 4, 5], [0, 1])
        self.security_tls = PanelCard("Estado TLS")
        self.security_fragmentation = PanelCard("Fragmentacao e MTU")
        self.security_events = PanelCard("Eventos de seguranca")
        self.security_detail = PanelCard("Evidencia do evento")
        self.security_tls_text = MetricGrid(columns=2)
        self.security_fragmentation_text = MetricGrid(columns=4)
        self.security_events_table = self._make_findings_table()
        self.security_filter = QComboBox()
        self.security_filter.addItem("Todos os eventos", "all")
        self.security_filter.addItem("TLS", "tls")
        self.security_filter.addItem("Fragmentacao", "fragmentation")
        self.security_filter.currentIndexChanged.connect(self._on_security_filter_changed)
        self.security_search = QLineEdit()
        self.security_search.setPlaceholderText("Buscar IP ou tipo de evento")
        self.security_search.textChanged.connect(self._render_security_page)
        self.security_detail_text = self._make_text()
        self.security_tls.add_widget(self.security_tls_text)
        self.security_fragmentation.add_widget(self.security_fragmentation_text)
        self.security_events.add_widget(self.security_search)
        self.security_events.add_widget(self.security_events_table)
        self.security_detail.add_widget(self.security_detail_text)
        layout.addWidget(self.security_tls, 0, 0)
        layout.addWidget(self.security_fragmentation, 0, 1, 1, 2)
        layout.addWidget(self.security_events, 1, 0, 1, 2)
        layout.addWidget(self.security_detail, 1, 2)
        self._register_page_cards(
            "Seguranca",
            self.security_tls,
            self.security_fragmentation,
            self.security_events,
            self.security_detail,
        )

    def _build_findings_page(self):
        _page, layout = self._new_grid_page("Findings", [6, 4], [0, 1])
        self.findings_summary = PanelCard("Resumo de findings")
        self.findings_recommendation = PanelCard("Recomendacao")
        self.findings_table_card = PanelCard("Todos os findings")
        self.findings_detail = PanelCard("Detalhe do finding")
        self.findings_summary_text = MetricGrid(columns=5)
        self.findings_recommendation_text = self._make_text()
        self.findings_recommendation_text.setMaximumHeight(150)
        self.findings_table = self._make_findings_table()
        self.findings_filter = QComboBox()
        self.findings_filter.addItem("Todas as severidades", "all")
        self.findings_filter.addItem("Alta", "high")
        self.findings_filter.addItem("Media", "medium")
        self.findings_filter.addItem("Baixa", "low")
        self.findings_filter.addItem("Informativos", "info")
        self.findings_filter.currentIndexChanged.connect(self._render_findings_page)
        self.findings_search = QLineEdit()
        self.findings_search.setPlaceholderText("Buscar IP ou tipo de finding")
        self.findings_search.textChanged.connect(self._render_findings_page)
        self.findings_detail_text = self._make_text()
        self.findings_summary.add_widget(self.findings_summary_text)
        self.findings_recommendation.add_widget(self.findings_recommendation_text)
        self.findings_table_card.add_widget(self.findings_filter)
        self.findings_table_card.add_widget(self.findings_search)
        self.findings_table_card.add_widget(self.findings_table)
        self.findings_detail.add_widget(self.findings_detail_text)
        layout.addWidget(self.findings_summary, 0, 0)
        layout.addWidget(self.findings_recommendation, 0, 1)
        layout.addWidget(self.findings_table_card, 1, 0)
        layout.addWidget(self.findings_detail, 1, 1)
        self._register_page_cards("Findings", self.findings_summary, self.findings_recommendation, self.findings_table_card, self.findings_detail)

    def _build_statistics_page(self):
        _page, layout = self._new_grid_page("Estatisticas", [1, 1], [1, 1])
        self.stats_traffic = PanelCard("Grafico de Trafego")
        self.stats_protocols = PanelCard("Distribuicao de Protocolos")
        self.stats_calls = PanelCard("Chamadas e Severidade")
        self.stats_traffic_chart = TrafficChart()
        self.stats_protocols_text = MetricGrid(columns=3)
        self.stats_protocol_chart = DonutChart()
        self.stats_calls_text = MetricGrid(columns=3)
        self.stats_calls_chart = BarChart()
        self.stats_traffic.add_widget(self.stats_traffic_chart)
        self.stats_protocols.add_widget(self.stats_protocols_text)
        self.stats_protocols.add_widget(self.stats_protocol_chart)
        self.stats_calls.add_widget(self.stats_calls_text)
        self.stats_calls.add_widget(self.stats_calls_chart)
        layout.addWidget(self.stats_traffic, 0, 0, 1, 2)
        layout.addWidget(self.stats_protocols, 1, 0)
        layout.addWidget(self.stats_calls, 1, 1)
        self._register_page_cards("Estatisticas", self.stats_traffic, self.stats_protocols, self.stats_calls)

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

    def _build_about_page(self):
        page = self._new_page("Sobre")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        card = PanelCard("Sobre o SIPPER")
        self.about_logo = QLabel()
        self.about_logo.setAlignment(Qt.AlignCenter)
        preview_pixmap = QPixmap(str(LOGO_PREVIEW_PATH))
        if not preview_pixmap.isNull():
            self.about_logo.setPixmap(
                preview_pixmap.scaled(560, 280, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            )
        self.about_text = self._make_text()
        self.about_update_status = QLabel()
        self.about_update_status.setObjectName("mutedLabel")
        self.about_update_button = QPushButton("Verificar atualizacoes")
        self.about_update_button.setObjectName("secondaryButton")
        self.about_update_button.clicked.connect(self._handle_update_action)
        card.add_widget(self.about_logo)
        card.add_widget(self.about_text)
        card.add_widget(self.about_update_status)
        card.add_widget(self.about_update_button)
        layout.addWidget(card)
        self._register_page_cards("Sobre", card)

    def _make_text(self):
        widget = QTextEdit()
        widget.setReadOnly(True)
        widget.setFrameStyle(QFrame.NoFrame)
        widget.setFont(_font("body"))
        widget.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        widget.setAcceptRichText(True)
        return widget

    def _make_calls_table(self):
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(
            ["ID", "Origem", "Destino", "Inicio", "Duracao", "Status"]
        )
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.setCornerButtonEnabled(False)
        self._configure_responsive_table(table, 72, stretch_columns=(0,))
        table.verticalHeader().setDefaultSectionSize(28)
        table.itemSelectionChanged.connect(self._on_call_selected)
        return table

    def _make_findings_table(self):
        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["Severidade", "Camada", "Problema", "Origem", "Destino"])
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.setCornerButtonEnabled(False)
        self._configure_responsive_table(table, 90, stretch_columns=(2,))
        table.verticalHeader().setDefaultSectionSize(28)
        table.itemSelectionChanged.connect(self._on_finding_selected)
        return table

    def _make_incident_table(self):
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["Prioridade", "Incidente", "De \u2192 Para", "Responsavel"])
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.setCornerButtonEnabled(False)
        self._configure_responsive_table(table, 90, stretch_columns=(1,))
        table.verticalHeader().setDefaultSectionSize(32)
        table.itemSelectionChanged.connect(self._on_finding_selected)
        return table

    def _make_rtp_table(self):
        table = QTableWidget(0, 8)
        table.setHorizontalHeaderLabels(
            ["Fluxo", "SSRC", "Codec", "Pacotes", "Perda", "Jitter max", "MOS", "Duracao"]
        )
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.setCornerButtonEnabled(False)
        self._configure_responsive_table(table, 64, stretch_columns=(0,))
        table.verticalHeader().setDefaultSectionSize(28)
        return table

    def _configure_responsive_table(self, table, minimum_section_width, stretch_columns=None):
        header = table.horizontalHeader()
        header.setMinimumSectionSize(minimum_section_width)
        header.setDefaultSectionSize(minimum_section_width)
        if stretch_columns:
            # Short columns (severity, ports, counters) fit their content and the
            # descriptive columns share the remaining width, so titles are not cut.
            header.setSectionResizeMode(QHeaderView.ResizeToContents)
            for column in stretch_columns:
                header.setSectionResizeMode(column, QHeaderView.Stretch)
        else:
            header.setSectionResizeMode(QHeaderView.Stretch)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        table.setTextElideMode(Qt.ElideRight)
        table.setContextMenuPolicy(Qt.ActionsContextMenu)
        copy_action = QAction("Copiar linha", table)
        copy_action.setShortcut(QKeySequence.Copy)
        copy_action.setShortcutContext(Qt.WidgetShortcut)
        copy_action.triggered.connect(lambda _checked=False, source=table: self._copy_table_selection(source))
        table.addAction(copy_action)

    def _copy_table_selection(self, table):
        rows = sorted({index.row() for index in table.selectionModel().selectedRows()})
        if not rows:
            return
        headers = [
            table.horizontalHeaderItem(column).text() if table.horizontalHeaderItem(column) else ""
            for column in range(table.columnCount())
        ]
        lines = ["\t".join(headers)]
        for row in rows:
            lines.append(
                "\t".join(
                    table.item(row, column).text() if table.item(row, column) else ""
                    for column in range(table.columnCount())
                )
            )
        QApplication.clipboard().setText("\n".join(lines))
        self._set_status(f"{len(rows)} linha(s) copiada(s)")

    def _choose_file(self):
        if self.analysis_thread is not None:
            return
        recent = self.analysis_settings.recent_files
        start_directory = str(Path(recent[0]).parent) if recent else ""
        file_path, _selected = QFileDialog.getOpenFileName(
            self,
            "Selecione uma captura",
            start_directory,
            "Capturas (*.pcap *.pcapng *.cap);;Todos os arquivos (*)",
        )
        if file_path:
            self.open_capture(file_path)

    def open_capture(self, file_path):
        """Load a capture and start analysing it right away."""
        if self.analysis_thread is not None:
            self._set_status("Aguarde a analise atual terminar ou cancele com Esc")
            return
        self.file_input.setText(str(file_path))
        self._analyze_file()

    def dragEnterEvent(self, event):
        if self._dropped_capture(event.mimeData()) is not None and self.analysis_thread is None:
            event.acceptProposedAction()
            return
        event.ignore()

    def dropEvent(self, event):
        file_path = self._dropped_capture(event.mimeData())
        if file_path is None:
            event.ignore()
            return
        event.acceptProposedAction()
        self.open_capture(file_path)

    def _dropped_capture(self, mime_data):
        if not mime_data.hasUrls():
            return None
        for url in mime_data.urls():
            if url.isLocalFile() and Path(url.toLocalFile()).suffix.lower() in CAPTURE_SUFFIXES:
                return url.toLocalFile()
        return None

    def _install_shortcuts(self):
        bindings = (
            (QKeySequence.Open, self._choose_file),
            (QKeySequence("F5"), self._analyze_file),
            (QKeySequence("Ctrl+E"), self._export_report),
            (QKeySequence("Esc"), self._cancel_analysis),
            (QKeySequence.Find, self._focus_search),
        )
        self.shortcuts = []
        for sequence, handler in bindings:
            shortcut = QShortcut(sequence, self)
            shortcut.activated.connect(handler)
            self.shortcuts.append(shortcut)

    def _focus_search(self):
        searches = {
            "SIP": self.sip_search,
            "RTP": self.rtp_search,
            "Rede": self.network_search,
            "Seguranca": self.security_search,
            "Findings": self.findings_search,
        }
        current = self.page_badge.text()
        if current not in searches:
            self._set_page("Findings")
            current = "Findings"
        searches[current].setFocus()
        searches[current].selectAll()

    def _build_welcome_card(self):
        card = QFrame()
        card.setObjectName("dropZone")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(40, 48, 40, 40)
        layout.setSpacing(14)
        layout.addStretch(1)
        title = QLabel("Arraste uma captura para ca")
        title.setObjectName("welcomeTitle")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(_font("title"))
        subtitle = QLabel(
            "Solte um arquivo .pcap ou .pcapng em qualquer lugar da janela "
            "e a analise comeca automaticamente."
        )
        subtitle.setObjectName("mutedLabel")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setWordWrap(True)
        open_button = QPushButton("Abrir captura  (Ctrl+O)")
        open_button.setObjectName("primaryButton")
        open_button.setMinimumHeight(44)
        open_button.setCursor(Qt.PointingHandCursor)
        open_button.clicked.connect(self._choose_file)
        open_row = QHBoxLayout()
        open_row.addStretch(1)
        open_row.addWidget(open_button)
        open_row.addStretch(1)
        self.welcome_recent_title = QLabel("Abertos recentemente")
        self.welcome_recent_title.setAlignment(Qt.AlignCenter)
        self.welcome_recent_title.setFont(_font("subtitle"))
        self.welcome_recent_container = QWidget()
        self.welcome_recent_layout = QVBoxLayout(self.welcome_recent_container)
        self.welcome_recent_layout.setContentsMargins(0, 0, 0, 0)
        self.welcome_recent_layout.setSpacing(6)
        privacy = QLabel(
            "A analise e feita localmente neste computador; nenhuma captura e enviada para a internet."
        )
        privacy.setObjectName("mutedLabel")
        privacy.setAlignment(Qt.AlignCenter)
        privacy.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(8)
        layout.addLayout(open_row)
        layout.addSpacing(18)
        layout.addWidget(self.welcome_recent_title)
        layout.addWidget(self.welcome_recent_container, 0, Qt.AlignHCenter)
        layout.addStretch(1)
        layout.addWidget(privacy)
        return card

    def _rebuild_welcome_recent_list(self):
        while self.welcome_recent_layout.count():
            item = self.welcome_recent_layout.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        recent = [path for path in self.analysis_settings.recent_files if Path(path).is_file()][:5]
        self.welcome_recent_title.setVisible(bool(recent))
        for path in recent:
            button = QPushButton(f"{Path(path).name}    {Path(path).parent}")
            button.setObjectName("recentFileButton")
            button.setToolTip(path)
            button.setCursor(Qt.PointingHandCursor)
            button.setMinimumWidth(520)
            button.clicked.connect(lambda _checked=False, item=path: self.open_capture(item))
            self.welcome_recent_layout.addWidget(button)

    def _rebuild_recent_menu(self):
        self.recent_menu.clear()
        recent = self.analysis_settings.recent_files
        for path in recent:
            action = self.recent_menu.addAction(Path(path).name)
            action.setToolTip(path)
            action.setEnabled(Path(path).is_file())
            action.triggered.connect(lambda _checked=False, item=path: self.open_capture(item))
        if recent:
            self.recent_menu.addSeparator()
            self.recent_menu.addAction("Limpar lista").triggered.connect(self._clear_recent_files)
        self.recent_button.setEnabled(bool(recent))

    def _clear_recent_files(self):
        self.analysis_settings = replace(self.analysis_settings, recent_files=[])
        self._save_preferences()
        self._rebuild_recent_menu()
        self._rebuild_welcome_recent_list()

    def _remember_recent_file(self, file_path):
        self.analysis_settings = replace(
            self.analysis_settings,
            recent_files=add_recent_file(self.analysis_settings, file_path),
        )
        self._save_preferences()
        self._rebuild_recent_menu()

    def _save_preferences(self):
        try:
            save_settings(self.analysis_settings)
        except OSError:
            pass

    def _analyze_file(self):
        file_path = self.file_input.text().strip()
        if not file_path:
            self._set_status("Selecione um arquivo PCAP")
            return

        if self.analysis_thread is not None:
            return

        if not Path(file_path).is_file():
            self._set_status(f"Arquivo nao encontrado: {file_path}")
            return

        self.analysis_started_at = time.perf_counter()
        self._set_analysis_running(True)
        self._set_status(f"Analisando {Path(file_path).name}")
        self.analysis_thread = QThread(self)
        self.analysis_worker = AnalysisWorker(file_path, self.analysis_settings)
        self.analysis_worker.moveToThread(self.analysis_thread)
        self.analysis_thread.started.connect(self.analysis_worker.run)
        self.analysis_worker.progress_changed.connect(self._set_status)
        self.analysis_worker.progress_value.connect(self._on_analysis_progress)
        self.analysis_worker.completed.connect(self._on_analysis_completed)
        self.analysis_worker.failed.connect(self._on_analysis_failed)
        self.analysis_worker.completed.connect(self.analysis_thread.quit)
        self.analysis_worker.failed.connect(self.analysis_thread.quit)
        self.analysis_thread.finished.connect(self.analysis_worker.deleteLater)
        self.analysis_thread.finished.connect(self._cleanup_analysis_worker)
        self.analysis_thread.start()

    def _on_analysis_progress(self, stage, fraction):
        percent = max(0, min(100, int(fraction * 100)))
        self.analysis_progress.setValue(percent)
        self._set_status(f"{stage}... {percent}%")

    def _on_analysis_completed(
        self,
        packet_analysis,
        engine_result,
        traffic_counts,
        traffic_labels,
        capture_duration,
    ):
        self.last_engine_result = engine_result
        self.last_packet_analysis = packet_analysis
        self.last_packets = []
        self.capture_duration = capture_duration
        self.last_traffic_series = self._build_traffic_series(traffic_counts)
        self.last_traffic_labels = traffic_labels
        self.last_viewmodel = build_dashboard_viewmodel(packet_analysis, engine_result)
        self.call_index = {call["dialog_key"]: call for call in self.last_viewmodel["calls"]}
        self.finding_index = {
            self._finding_key(finding, index): finding
            for index, finding in enumerate(self.last_viewmodel["findings"])
        }
        self.selected_stream_key = None
        self.selected_call_id = self.last_viewmodel["calls"][0]["dialog_key"] if self.last_viewmodel["calls"] else None
        self.selected_finding_key = (
            self._finding_key(self.last_viewmodel["findings"][0], 0) if self.last_viewmodel["findings"] else None
        )
        self._render_all()
        if any(
            finding["severity"] in {"high", "medium"}
            for finding in self.last_viewmodel["findings"]
        ):
            self._set_page("Diagnostico")
        else:
            self._set_page("Resumo")
        self.export_button.setEnabled(True)
        self._set_analysis_running(False)
        file_path = self.file_input.text().strip()
        self.analyzed_file = file_path
        self.setWindowTitle(f"SIPPER - {Path(file_path).name}")
        self._remember_recent_file(file_path)
        elapsed = time.perf_counter() - (self.analysis_started_at or time.perf_counter())
        overview = self.last_viewmodel["overview"]
        actionable = sum(1 for finding in self.last_viewmodel["findings"] if is_actionable(finding) and finding["severity"] in {"high", "medium"})
        self._set_status(
            f"Analise concluida em {elapsed:.1f} s  |  "
            f"{overview['packet_count']:,} pacotes  |  "
            f"{overview['call_count']} chamadas  |  "
            f"{actionable} problemas prioritarios".replace(",", ".")
        )

    def _on_analysis_failed(self, error):
        self._set_analysis_running(False)
        if error == "Analise cancelada pelo usuario":
            self._set_status(error)
            return
        self._set_status(f"Nao foi possivel analisar o arquivo: {error}")

    def _cancel_analysis(self):
        if self.analysis_worker is None:
            return
        self.analysis_worker.cancel()
        self.cancel_button.setEnabled(False)
        self._set_status("Cancelando analise")

    def _cleanup_analysis_worker(self):
        if self.analysis_thread is not None:
            self.analysis_thread.deleteLater()
        self.analysis_worker = None
        self.analysis_thread = None

    def _set_analysis_running(self, is_running):
        self.open_button.setEnabled(not is_running)
        self.analyze_button.setEnabled(not is_running)
        self.cancel_button.setEnabled(is_running)
        self.cancel_button.setVisible(is_running)
        self.recent_button.setEnabled(not is_running and bool(self.analysis_settings.recent_files))
        self.export_button.setEnabled(not is_running and self.last_viewmodel is not None)
        self.file_input.setReadOnly(is_running)
        self.analysis_progress.setVisible(is_running)
        self.analysis_progress.setValue(0)

    def _export_report(self):
        if self.last_viewmodel is None:
            self._set_status("Analise um PCAP antes de exportar")
            return

        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Exportar relatorio",
            str(Path(self.analysis_settings.export_directory) / "SIPPER_relatorio"),
            "Relatorio JSON (*.json);;Relatorio CSV (*.csv);;Relatorio PDF (*.pdf)",
        )

        if not file_path:
            return

        extension = Path(file_path).suffix.lower()
        if not extension:
            extension = ".json" if "JSON" in selected_filter else ".csv" if "CSV" in selected_filter else ".pdf"
            file_path = f"{file_path}{extension}"

        payload = build_report_payload(
            self.last_viewmodel,
            self.file_input.text().strip(),
            self.capture_duration,
        )

        try:
            if extension == ".json":
                export_json(payload, file_path)
            elif extension == ".csv":
                export_csv(payload, file_path)
            elif extension == ".pdf":
                export_pdf(payload, file_path)
            else:
                self._set_status("Escolha JSON, CSV ou PDF para exportar")
                return
        except OSError as error:
            self._set_status(f"Falha ao exportar: {error}")
            return

        self._set_status(f"Relatorio exportado: {file_path}")

    def _set_page(self, name):
        page = self.page_widgets[name]
        self.pages.setCurrentWidget(page)
        self.page_badge.setText(name)
        self._refresh_nav_state(name)
        self._set_status(f"Visao atual: {name}")

    def _set_rtp_filter(self, filter_name):
        for index in range(self.rtp_filter.count()):
            if self.rtp_filter.itemData(index) == filter_name:
                self.rtp_filter.setCurrentIndex(index)
                break
        self._set_page("RTP")

    def _set_sip_filter(self, filter_name):
        self._select_filter_value(self.sip_filter, filter_name)
        self._set_page("SIP")

    def _set_network_filter(self, filter_name):
        self._select_filter_value(self.network_filter, filter_name)
        self._set_page("Rede")

    def _set_security_filter(self, filter_name):
        self._select_filter_value(self.security_filter, filter_name)
        self._set_page("Seguranca")

    def _select_filter_value(self, combo_box, value):
        for index in range(combo_box.count()):
            if combo_box.itemData(index) == value:
                combo_box.setCurrentIndex(index)
                return

    def _on_rtp_filter_changed(self):
        self._render_rtp_page()
        if self.pages.currentWidget() is self.page_widgets.get("RTP"):
            self._refresh_nav_state("RTP")

    def _on_sip_filter_changed(self):
        self._render_sip_page()
        if self.pages.currentWidget() is self.page_widgets.get("SIP"):
            self._refresh_nav_state("SIP")

    def _on_network_filter_changed(self):
        self._render_network_page()
        if self.pages.currentWidget() is self.page_widgets.get("Rede"):
            self._refresh_nav_state("Rede")

    def _on_security_filter_changed(self):
        self._render_security_page()
        if self.pages.currentWidget() is self.page_widgets.get("Seguranca"):
            self._refresh_nav_state("Seguranca")

    def _refresh_nav_state(self, current):
        for name, button in self.page_buttons.items():
            button.setProperty("active", name == current)
            button.style().unpolish(button)
            button.style().polish(button)

        self._refresh_filter_nav_buttons("RTP", self.rtp_nav_buttons, self.rtp_filter, current)
        self._refresh_filter_nav_buttons("SIP", self.sip_nav_buttons, self.sip_filter, current)
        self._refresh_filter_nav_buttons("Rede", self.network_nav_buttons, self.network_filter, current)
        self._refresh_filter_nav_buttons("Seguranca", self.security_nav_buttons, self.security_filter, current)

    def _refresh_filter_nav_buttons(self, page, buttons, combo_box, current_page):
        current_filter = combo_box.currentData()
        for filter_name, button in buttons.items():
            button.setProperty("active", current_page == page and filter_name == current_filter)
            button.style().unpolish(button)
            button.style().polish(button)

    def _on_theme_radio_changed(self):
        self.current_theme = "dark" if self.dark_radio.isChecked() else "light"
        self.analysis_settings = replace(self.analysis_settings, theme=self.current_theme)
        self._save_preferences()
        self._apply_theme()
        self._render_all()

    def _apply_theme(self):
        palette = THEMES[self.current_theme]
        self.dark_radio.blockSignals(True)
        self.light_radio.blockSignals(True)
        self.dark_radio.setChecked(self.current_theme == "dark")
        self.light_radio.setChecked(self.current_theme == "light")
        self.dark_radio.blockSignals(False)
        self.light_radio.blockSignals(False)
        stylesheet = build_stylesheet(palette)
        self.setStyleSheet(stylesheet)
        self._update_brand_splash()
        self.page_badge.setStyleSheet(
            f"background: {palette['selection']}; color: {palette['text']}; border: 1px solid {palette['accent']}; border-radius: 12px; padding: 8px 12px;"
        )
        self.status_bar_label.setStyleSheet(f"color: {palette['muted']}; padding: 2px 8px;")
        self.sidebar_status.setStyleSheet(f"color: {palette['muted']};")
        self._refresh_nav_icons()

    def _update_brand_splash(self):
        splash_path = LIGHT_SPLASH_LOGO_PATH if self.current_theme == "light" else DARK_SPLASH_LOGO_PATH
        splash_pixmap = QPixmap(str(splash_path))
        if splash_pixmap.isNull():
            return
        self.brand_splash.setPixmap(
            splash_pixmap.scaled(206, 72, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        )

    def _render_all(self):
        self._refresh_nav_state(self.page_badge.text())
        self._render_summary_page()
        self._render_diagnostic_page()
        self._render_sip_page()
        self._render_rtp_page()
        self._render_network_page()
        self._render_security_page()
        self._render_findings_page()
        self._render_statistics_page()
        self._render_settings_page()
        self._render_about_page()

    def _render_diagnostic_page(self):
        palette = THEMES[self.current_theme]
        if self.last_viewmodel is None:
            self.diagnostic_priority_text.set_message("Abra um PCAP para priorizar incidentes.")
            self.diagnostic_scope_text.set_message("Nenhum diagnostico carregado.")
            self.diagnostic_detail_text.setPlainText("Selecione um incidente para ver as evidencias.")
            self._fill_incident_table(self.diagnostic_incidents_table, [])
            return

        incidents = self._sorted_incidents(self.last_viewmodel["findings"])
        actionable = [
            finding
            for finding in incidents
            if finding["severity"] in {"high", "medium"} and is_actionable(finding)
        ]
        top = actionable[0] if actionable else (incidents[0] if incidents else None)
        if top is None or not actionable:
            self.diagnostic_priority_text.set_metrics(
                [("Resultado", "Nenhum problema detectado na captura", "success", 2)],
                palette,
            )
        else:
            severity = self._display_severity(top)
            self.diagnostic_priority_text.set_metrics(
                [
                    ("Incidente", self._finding_title(top), self._severity_tone(severity), 2),
                    ("Prioridade", severity_label(severity), self._severity_tone(severity)),
                    ("Possivel responsavel", top["responsibility"]),
                    ("De", top["source"]),
                    ("Para", top["destination"]),
                ],
                palette,
            )
        high_count = sum(1 for finding in actionable if self._display_severity(finding) == "high")
        self.diagnostic_scope_text.set_metrics(
            [
                ("Acionaveis", len(actionable), "danger" if high_count else ("warning" if actionable else "success")),
                ("Severidade alta", high_count, "danger" if high_count else None),
                ("Camadas afetadas", self._finding_category_summary(actionable or incidents), None, 2),
                ("Atribuicao principal", self._responsibility_summary(actionable or incidents), None, 2),
            ],
            palette,
        )
        self._fill_incident_table(self.diagnostic_incidents_table, actionable or incidents)
        self._render_diagnostic_detail(self._selected_finding(actionable or incidents))

    def _render_summary_page(self):
        has_data = self.last_viewmodel is not None
        self.welcome_card.setVisible(not has_data)
        for card in self.page_cards["Resumo"]:
            card.setVisible(has_data)
        self._rebuild_welcome_recent_list()
        if self.last_viewmodel is None:
            self.summary_detail_text.setPlainText("Selecione ou carregue uma chamada para ver detalhes.")
            for widget in self._summary_kpis():
                widget.set_value(0)
            self._fill_calls_table(self.summary_calls_table, [])
            self._fill_rtp_table(self.summary_rtp_table, [])
            self._fill_incident_table(self.summary_findings_table, [])
            self.summary_protocol_chart.set_series([])
            self.summary_findings_chart.set_items([])
            self.summary_traffic_chart.set_data([], [])
            self.summary_flow.set_call(None)
            self.summary_sip_flow_button.setEnabled(False)
            return

        viewmodel = self.last_viewmodel
        protocols = viewmodel["protocols"]
        actionable = [
            finding
            for finding in viewmodel["findings"]
            if is_actionable(finding) and finding["severity"] in {"high", "medium"}
        ]
        mos_values = [
            call["media_quality_metrics"].get("mos_estimate")
            for call in viewmodel["calls"]
            if call.get("media_quality_metrics", {}).get("mos_estimate") is not None
        ] or [stream["mos"] for stream in viewmodel["rtp_streams"] if stream.get("mos") is not None]
        self.kpi_packets.set_value(f"{viewmodel['overview']['packet_count']:,}".replace(",", "."))
        self.kpi_protocols.set_value(viewmodel["overview"]["protocol_count"])
        self.kpi_calls.set_value(viewmodel["overview"]["call_count"])
        self.kpi_streams.set_value(len(viewmodel["rtp_streams"]))
        self.kpi_findings.set_value(len(actionable))
        self.kpi_high.set_value(sum(1 for finding in actionable if finding["severity"] == "high"))
        self.kpi_mos.set_value(f"{sum(mos_values) / len(mos_values):.2f}" if mos_values else "-")
        self.kpi_duration.set_value(self._format_duration(self.capture_duration))
        self._fill_calls_table(self.summary_calls_table, viewmodel["calls"])
        self._fill_rtp_table(
            self.summary_rtp_table,
            viewmodel["rtp_streams"],
        )
        priority_findings = [
            finding
            for finding in self._sorted_incidents(viewmodel["findings"])
            if finding["severity"] in {"high", "medium"} and is_actionable(finding)
        ]
        self._fill_incident_table(self.summary_findings_table, priority_findings[:6])
        self.summary_recent_findings.set_title(
            "Incidentes prioritarios"
            if priority_findings
            else "Incidentes prioritarios: nenhum problema encontrado nesta captura"
        )
        self.summary_traffic_chart.set_data(
            self.last_traffic_series,
            self.last_traffic_labels,
            self._call_markers(),
        )
        call = self._selected_call()
        self.summary_flow.set_call(call)
        self.summary_sip_flow_button.setEnabled(call is not None)
        self._render_call_text(self.summary_detail_text, call)
        palette = THEMES[self.current_theme]
        self.summary_protocol_chart.set_series(
            [
                {
                    "label": f"{item['name']}  {item['share']:.1%}",
                    "value": item["count"],
                    "color": color,
                    "border": palette["panel"],
                }
                for item, color in zip(
                    protocols[:5],
                    [palette["accent"], palette["info"], palette["warning"], palette["danger"], palette["success"]],
                )
            ],
            str(viewmodel["overview"]["packet_count"]),
            "pacotes",
        )
        self.summary_findings_chart.set_items(
            [
                {
                    "label": severity_label(severity),
                    "value": self._count_display_severity(severity),
                    "color": self._severity_color(severity, palette),
                    "track": palette["surface"],
                }
                for severity in ("high", "medium", "low", "info")
            ]
        )

    def _render_sip_page(self):
        if self.last_viewmodel is None:
            self.sip_state_text.set_message("Abra um PCAP para analisar sinalizacao SIP.")
            self.sip_findings_text.setPlainText("Nenhum erro SIP carregado.")
            self.sip_detail_text.setPlainText("Sem chamada selecionada.")
            self.sip_flow.set_call(None)
            self.sip_open_flow_button.setEnabled(False)
            self._fill_calls_table(self.sip_calls_table, [])
            return

        all_calls = [call for call in self.last_viewmodel["calls"] if call["signaling_state"] != "unknown"]
        filter_name = self.sip_filter.currentData()
        calls = self._filter_sip_calls(all_calls, filter_name)
        calls = self._filter_calls_by_search(calls, all_calls, self.sip_search.text(), self.sip_time_range.text())
        sip_findings = self._filter_sip_findings(
            [
                finding
                for finding in self.last_viewmodel["findings"]
                if finding["type"].startswith(("sip_", "freeswitch_"))
            ],
            filter_name,
        )
        established = sum(1 for call in calls if call["signaling_state"] in {"established", "terminated"})
        degraded = sum(1 for call in calls if call["severity"] in {"high", "medium"})
        analysis_profile = self.last_viewmodel.get("analysis_profile", {})
        platform = analysis_profile.get("target_platform", "generic")
        platform_ips = analysis_profile.get("target_platform_ips", "")
        profile_name = "FreeSWITCH" if platform == "freeswitch" else "SIP/RTP generico"
        profile_scope = (
            platform_ips or "todos os destinos SIP"
            if platform == "freeswitch"
            else "nao aplicavel"
        )
        self.sip_calls.set_title(self._sip_filter_title(filter_name))
        self.sip_state_text.set_metrics(
            [
                ("Fluxos SIP", len(calls)),
                ("Completadas", established, "success" if established else None),
                ("Com risco", degraded, "warning" if degraded else None),
                ("Perfil", profile_name),
                ("IPs monitorados", profile_scope, None, 2),
            ],
            THEMES[self.current_theme],
        )
        sip_problems = [finding for finding in sip_findings if is_actionable(finding)]
        self.sip_findings_text.setPlainText(
            "\n".join(self._finding_lines(sip_problems, 12)) or "Nenhuma falha de sinalizacao detectada."
        )
        self._fill_calls_table(self.sip_calls_table, calls)
        call = self._selected_call()
        self.sip_flow.set_call(call)
        self.sip_open_flow_button.setEnabled(call is not None)
        self._render_call_text(self.sip_detail_text, call)

    def _filter_sip_calls(self, calls, filter_name):
        if filter_name == "errors":
            return [
                call
                for call in calls
                if call["signaling_state"] in {"failed", "cancelled", "missing_ack", "no_response", "incomplete"}
            ]
        if filter_name == "freeswitch":
            return [
                call
                for call in calls
                if any(
                    finding_type.startswith("freeswitch_")
                    for finding_type in call.get("finding_types", [])
                )
            ]
        return calls

    def _filter_sip_findings(self, findings, filter_name):
        if filter_name == "errors":
            return [finding for finding in findings if is_actionable(finding)]
        if filter_name == "headers":
            return [
                finding
                for finding in findings
                if any(
                    token in finding["type"]
                    for token in ("header", "content_length", "fragmentation")
                )
            ]
        if filter_name == "freeswitch":
            return [
                finding
                for finding in findings
                if finding["type"].startswith("freeswitch_")
            ]
        return findings

    def _filter_calls_by_search(self, calls, all_calls, query, time_range):
        query = query.strip().lower()
        if query:
            calls = [
                call
                for call in calls
                if query in call["call_id"].lower()
                or query in call["source_ip"].lower()
                or query in call["destination_ip"].lower()
            ]

        time_window = self._parse_time_range(time_range)
        if time_window is None:
            return calls

        starts = [call["start_time"] for call in all_calls if call["start_time"] is not None]
        if not starts:
            return calls

        capture_start = min(starts)
        start_offset, end_offset = time_window
        return [
            call
            for call in calls
            if call["start_time"] is not None
            and start_offset <= call["start_time"] - capture_start <= end_offset
        ]

    def _parse_time_range(self, value):
        normalized = value.lower().replace("s", "").strip()
        if not normalized:
            return None
        start, separator, end = normalized.partition("-")
        if not separator:
            return None
        try:
            start_value = float(start.strip())
            end_value = float(end.strip())
        except ValueError:
            return None
        if start_value < 0 or end_value < start_value:
            return None
        return start_value, end_value

    def _sip_filter_title(self, filter_name):
        titles = {
            "all": "Chamadas e sinalizacao",
            "errors": "Falhas de sinalizacao",
            "headers": "Headers SIP e MTU",
            "analysis": "Analise da chamada",
            "freeswitch": "Compatibilidade FreeSWITCH",
        }
        return titles.get(filter_name, "SIP Flows")

    def _render_rtp_page(self):
        if self.last_viewmodel is None:
            self.rtp_health_text.set_message("Nenhum stream RTP carregado.")
            self.rtp_timeline.set_stream([])
            self.rtp_findings_text.setPlainText("")
            self.rtp_detail_text.setPlainText("Sem chamada selecionada.")
            self.rtp_flow.set_call(None)
            self._fill_rtp_table(self.rtp_streams_table, [])
            self._fill_calls_table(self.rtp_calls_table, [])
            return

        calls = [call for call in self.last_viewmodel["calls"] if call["rtp_stream_count"] > 0 or call["media_state"] != "no_media"]
        filter_name = self.rtp_filter.currentData()
        streams = self._filter_rtp_streams(self.last_viewmodel["rtp_streams"], filter_name)
        streams = self._filter_rtp_stream_search(streams, self.rtp_search.text())
        rtp_findings = self._filter_rtp_findings(
            [
                finding
                for finding in self.last_viewmodel["findings"]
                if finding["type"].startswith(("rtp_", "rtcp_"))
            ],
            filter_name,
        )
        self.rtp_streams.set_title(f"{self._rtp_filter_title(filter_name)} ({len(streams)})")
        self._fill_rtp_table(self.rtp_streams_table, streams)
        self._render_stream_quality(self._selected_stream(streams))
        self.rtp_findings_text.setPlainText(
            "\n".join(self._finding_lines(rtp_findings, 10)) or "Nenhum problema de midia detectado."
        )
        self._fill_calls_table(self.rtp_calls_table, calls)
        call = self._selected_call()
        self.rtp_flow.set_call(call)
        self._render_call_text(self.rtp_detail_text, call)

    def _filter_rtp_streams(self, streams, filter_name):
        if filter_name == "jitter":
            return [stream for stream in streams if stream["max_jitter"] > 0]
        if filter_name == "loss":
            return [stream for stream in streams if stream["lost_packets"] > 0]
        if filter_name == "out_of_order":
            return [stream for stream in streams if stream["out_of_order_packets"] > 0]
        if filter_name == "codecs":
            return [stream for stream in streams if stream["codec_guesses"]]
        return streams

    def _filter_rtp_findings(self, findings, filter_name):
        finding_types = {
            "jitter": {"rtp_high_jitter", "rtcp_reported_jitter"},
            "loss": {"rtp_packet_loss", "rtcp_reported_loss"},
            "out_of_order": {"rtp_out_of_order"},
        }.get(filter_name)

        if finding_types is None:
            return findings

        return [finding for finding in findings if finding["type"] in finding_types]

    def _filter_rtp_stream_search(self, streams, query):
        query = query.strip().lower()
        if not query:
            return streams
        return [
            stream
            for stream in streams
            if query in stream["source"].lower()
            or query in stream["destination"].lower()
            or query in str(stream["ssrc"]).lower()
            or any(query in codec.lower() for codec in stream["codec_guesses"])
        ]

    def _rtp_filter_title(self, filter_name):
        titles = {
            "all": "Streams RTP",
            "jitter": "Midia com jitter",
            "loss": "Midia com perda",
            "out_of_order": "Midia fora de ordem",
            "codecs": "Codecs identificados",
        }
        return titles.get(filter_name, "RTP Flows")

    def _codec_summary(self, streams):
        codec_counts = {}
        for stream in streams:
            codecs = stream.get("codec_guesses") or [
                f"PT {payload_type}" for payload_type in stream.get("payload_types", [])
            ]
            for codec in codecs or ["Nao identificado"]:
                codec_counts[codec] = codec_counts.get(codec, 0) + 1
        return ", ".join(
            f"{codec} ({count})"
            for codec, count in sorted(codec_counts.items(), key=lambda item: (-item[1], item[0]))
        ) or "Nenhum"

    def _render_network_page(self):
        if self.last_viewmodel is None:
            self.network_protocols_text.set_message("Abra um PCAP para analisar rede.")
            self.network_health_text.setPlainText("Nenhum evento de rede carregado.")
            self.network_detail_text.setPlainText("Sem finding selecionado.")
            self._fill_findings_table(self.network_events_table, [])
            return

        protocols = self.last_viewmodel["protocols"]
        all_findings = [
            finding
            for finding in self.last_viewmodel["findings"]
            if finding["type"].startswith(("tcp_", "udp_", "icmp_"))
        ]
        filter_name = self.network_filter.currentData()
        findings = self._filter_network_findings(all_findings, filter_name)
        findings = self._filter_findings_by_search(findings, self.network_search.text())
        self.network_events.set_title(self._network_filter_title(filter_name))
        self.network_protocols_text.set_metrics(
            [(item["name"], f"{item['count']:,}  ({item['share']:.1%})".replace(",", ".")) for item in protocols[:9]],
            THEMES[self.current_theme],
        )
        self.network_health_text.setPlainText("\n".join(self._finding_lines(findings, 14)) or "Nenhum finding de rede detectado.")
        self._fill_findings_table(self.network_events_table, findings)
        self._render_finding_text(self.network_detail_text, self._selected_finding(findings))

    def _filter_network_findings(self, findings, filter_name):
        if filter_name in {"tcp", "udp", "icmp"}:
            return [finding for finding in findings if finding["type"].startswith(f"{filter_name}_")]
        return findings

    def _network_filter_title(self, filter_name):
        titles = {
            "all": "Eventos de rede",
            "tcp": "Eventos TCP",
            "udp": "Eventos UDP",
            "icmp": "Eventos ICMP",
        }
        return titles.get(filter_name, "Eventos TCP UDP ICMP")

    def _render_security_page(self):
        if self.last_viewmodel is None:
            self.security_tls_text.set_message("Abra um PCAP para analisar TLS.")
            self.security_fragmentation_text.set_message("Abra um PCAP para analisar fragmentacao e MTU.")
            self.security_detail_text.setPlainText("Sem finding selecionado.")
            self._fill_findings_table(self.security_events_table, [])
            return

        findings = self.last_viewmodel["findings"]
        tls_flows = list(self.last_engine_result.get("tls_flows", {}).values())
        tls_findings = [finding for finding in findings if finding["type"].startswith("tls_")]
        fragmentation_findings = [
            finding
            for finding in findings
            if finding["type"].startswith("ip_fragment")
            or finding["type"] == "icmp_fragmentation_needed"
            or "fragmentation" in finding["type"]
        ]
        filter_name = self.security_filter.currentData()
        filtered_findings = self._filter_security_findings(
            tls_findings,
            fragmentation_findings,
            filter_name,
        )
        filtered_findings = self._filter_findings_by_search(
            filtered_findings,
            self.security_search.text(),
        )
        self.security_events.set_title(self._security_filter_title(filter_name))
        palette = THEMES[self.current_theme]

        def count(items, finding_type):
            return sum(1 for finding in items if finding["type"] == finding_type)

        fatal = count(tls_findings, "tls_fatal_alert")
        self.security_tls_text.set_metrics(
            [
                ("Handshakes analisados", len(tls_flows)),
                ("Eventos TLS", len(tls_findings), "warning" if tls_findings else None),
                ("Alertas fatais", fatal, "danger" if fatal else None),
                ("Sem resposta", count(tls_findings, "tls_client_hello_no_response")),
                ("Versao legada", count(tls_findings, "tls_legacy_version")),
                ("Cifras fracas", count(tls_findings, "tls_weak_cipher_suite")),
                ("SNI observados", len({name for flow in tls_flows for name in flow.server_names})),
            ],
            palette,
        )
        incomplete = count(fragmentation_findings, "ip_fragment_incomplete")
        self.security_fragmentation_text.set_metrics(
            [
                ("Eventos", len(fragmentation_findings), "warning" if fragmentation_findings else None),
                ("Conjuntos incompletos", incomplete, "warning" if incomplete else None),
                ("Sobreposicoes", count(fragmentation_findings, "ip_fragment_overlap")),
                ("Risco em headers SIP", count(fragmentation_findings, "sip_header_fragmentation_risk")),
            ],
            palette,
        )
        self._fill_findings_table(self.security_events_table, filtered_findings)
        self._render_finding_text(
            self.security_detail_text,
            self._selected_finding(filtered_findings),
        )

    def _filter_security_findings(self, tls_findings, fragmentation_findings, filter_name):
        if filter_name == "tls":
            return tls_findings
        if filter_name == "fragmentation":
            return fragmentation_findings
        return tls_findings + fragmentation_findings

    def _security_filter_title(self, filter_name):
        titles = {
            "all": "Eventos TLS e Fragmentacao",
            "tls": "Eventos TLS",
            "fragmentation": "Fragmentacao e MTU",
        }
        return titles.get(filter_name, "Eventos TLS e Fragmentacao")

    def _render_findings_page(self):
        if self.last_viewmodel is None:
            self.findings_summary_text.set_message("Abra um PCAP para ver os findings.")
            self.findings_recommendation_text.setPlainText("Nenhuma recomendacao carregada.")
            self.findings_detail_text.setPlainText("Sem finding selecionado.")
            self._fill_findings_table(self.findings_table, [])
            return

        filter_name = self.findings_filter.currentData()
        findings = sorted(
            self.last_viewmodel["findings"],
            key=lambda finding: SEVERITY_ORDER.get(self._display_severity(finding), 9),
        )
        findings = self._filter_findings_by_severity(findings, filter_name)
        findings = self._filter_findings_by_search(findings, self.findings_search.text())
        self.findings_table_card.set_title(self._findings_filter_title(filter_name))
        top = findings[0] if findings else None
        high = self._count_display_severity("high")
        medium = self._count_display_severity("medium")
        self.findings_summary_text.set_metrics(
            [
                ("Exibindo", f"{len(findings)} de {len(self.last_viewmodel['findings'])}"),
                ("Alta", high, "danger" if high else None),
                ("Media", medium, "warning" if medium else None),
                ("Baixa", self._count_display_severity("low")),
                ("Informativos", self._count_display_severity("info")),
                ("Camadas afetadas", self._finding_category_summary(findings), None, 5),
            ],
            THEMES[self.current_theme],
        )
        self.findings_recommendation_text.setPlainText(
            top["recommendation"] if top else "Nenhuma recomendacao disponivel."
        )
        self._fill_findings_table(self.findings_table, findings)
        self._render_finding_text(self.findings_detail_text, self._selected_finding(findings))

    def _filter_findings_by_severity(self, findings, filter_name):
        if filter_name in {"high", "medium", "low", "info"}:
            return [finding for finding in findings if self._display_severity(finding) == filter_name]
        return findings

    def _filter_findings_by_search(self, findings, query):
        query = query.strip().lower()
        if not query:
            return findings
        return [
            finding
            for finding in findings
            if query in finding["type"].lower()
            or query in self._finding_title(finding).lower()
            or query in finding["source"].lower()
            or query in finding["destination"].lower()
        ]

    def _findings_filter_title(self, filter_name):
        if filter_name == "all":
            return "Todos os Findings"
        return f"Findings - {filter_name.upper()}"

    def _render_statistics_page(self):
        palette = THEMES[self.current_theme]
        if self.last_viewmodel is None:
            self.stats_protocols_text.set_message("Abra um PCAP para gerar estatisticas.")
            self.stats_calls_text.set_message("Nenhuma chamada carregada.")
            self.stats_traffic_chart.set_data([], [])
            self.stats_protocol_chart.set_series([])
            self.stats_calls_chart.set_items([], "vertical")
            return

        protocols = self.last_viewmodel["protocols"]
        calls = self.last_viewmodel["calls"]
        self.stats_traffic_chart.set_data(self.last_traffic_series, self.last_traffic_labels, self._call_markers())
        self.stats_protocols_text.set_metrics(
            [(item["name"], f"{item['count']:,}  ({item['share']:.1%})".replace(",", ".")) for item in protocols[:9]],
            palette,
        )
        media_problems = sum(1 for call in calls if call["media_state"] not in {"ok", "media_present"})
        signaling_problems = sum(
            1 for call in calls if call["signaling_state"] not in {"established", "terminated"}
        )
        high_calls = sum(1 for call in calls if call["severity"] == "high")
        self.stats_calls_text.set_metrics(
            [
                ("Chamadas", len(calls)),
                ("Duracao da captura", self._format_duration(self.capture_duration)),
                ("Severidade alta", high_calls, "danger" if high_calls else None),
                ("Midia com problema", media_problems, "warning" if media_problems else None),
                ("Sinalizacao com problema", signaling_problems, "warning" if signaling_problems else None),
            ],
            palette,
        )
        self.stats_protocol_chart.set_series(
            [
                {
                    "label": f"{item['name']}  {item['share']:.1%}",
                    "value": item["count"],
                    "color": color,
                    "border": palette["panel"],
                }
                for item, color in zip(
                    protocols[:5],
                    [palette["accent"], palette["info"], palette["warning"], palette["danger"], palette["success"]],
                )
            ],
            str(self.last_viewmodel["overview"]["packet_count"]),
            "pacotes",
        )
        self.stats_calls_chart.set_items(
            [
                {"label": "SIP OK", "value": sum(1 for call in calls if call["signaling_state"] in {"established", "terminated"}), "color": palette["success"], "track": palette["surface"]},
                {"label": "RTP OK", "value": sum(1 for call in calls if call["media_state"] in {"media_present", "ok"}), "color": palette["accent"], "track": palette["surface"]},
                {"label": "Alta", "value": sum(1 for call in calls if call["severity"] == "high"), "color": palette["danger"], "track": palette["surface"]},
                {"label": "Media", "value": sum(1 for call in calls if call["severity"] == "medium"), "color": palette["warning"], "track": palette["surface"]},
            ],
            "vertical",
        )

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
        self._update_platform_settings_state()
        self.settings_export_directory.setText(self.analysis_settings.export_directory)

    def _update_platform_settings_state(self):
        self.settings_platform_ips.setEnabled(
            self.settings_platform.currentData() == "freeswitch"
        )

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
        )
        try:
            save_settings(self.analysis_settings)
        except OSError as error:
            self._set_status(f"Falha ao salvar configuracoes: {error}")
            return
        self._set_status("Configuracoes salvas")

    def _render_about_page(self):
        self.about_text.setPlainText(
            "\n".join(
                [
                    "SIPPER",
                    f"Versao instalada: {CURRENT_VERSION}",
                    "",
                    "Analisador offline de PCAP com foco em diagnostico de rede, VoIP, SIP e RTP.",
                    "",
                    "Objetivo da interface:",
                    "- resumir a captura",
                    "- destacar evidencias",
                    "- facilitar leitura operacional por chamadas",
                ]
            )
        )

    def _handle_update_action(self):
        if self.available_update is not None:
            if QDesktopServices.openUrl(QUrl(self.available_update.download_url)):
                self._set_status("Download da atualizacao aberto no navegador")
            else:
                self._set_status("Nao foi possivel abrir o link da atualizacao")
            return
        self._check_for_update()

    def _check_for_update(self):
        if self.update_thread is not None:
            return

        self.about_update_button.setEnabled(False)
        self.about_update_status.setText("Verificando atualizacoes...")
        self.update_thread = QThread(self)
        self.update_worker = UpdateCheckWorker()
        self.update_worker.moveToThread(self.update_thread)
        self.update_thread.started.connect(self.update_worker.run)
        self.update_worker.completed.connect(self._on_update_check_completed)
        self.update_worker.completed.connect(self.update_thread.quit)
        self.update_thread.finished.connect(self.update_worker.deleteLater)
        self.update_thread.finished.connect(self._cleanup_update_worker)
        self.update_thread.start()

    def _on_update_check_completed(self, update):
        self.available_update = update
        self.about_update_button.setEnabled(True)
        if update is None:
            self.about_update_status.setText("Voce ja esta na versao mais recente ou a verificacao esta indisponivel.")
            self.about_update_button.setText("Verificar atualizacoes")
            return

        checksum_note = " Checksum SHA-256 publicado." if update.checksum_url else ""
        self.about_update_status.setText(f"Atualizacao {update.version} disponivel.{checksum_note}")
        self.about_update_button.setText(f"Baixar SIPPER {update.version}")
        self._set_status(f"Atualizacao {update.version} disponivel")

    def _cleanup_update_worker(self):
        if self.update_thread is not None:
            self.update_thread.deleteLater()
        self.update_worker = None
        self.update_thread = None

    def closeEvent(self, event):
        if self.analysis_thread is not None:
            self._cancel_analysis()
            self._set_status("Cancelando analise antes de fechar")
            event.ignore()
            return
        if self.update_thread is not None:
            self.update_thread.quit()
            self.update_thread.wait(4000)
        super().closeEvent(event)

    def _fill_calls_table(self, table, calls):
        palette = THEMES[self.current_theme]
        table.blockSignals(True)
        table.setRowCount(len(calls))
        for row, call in enumerate(calls):
            values = [
                call["call_id"],
                call["source_ip"],
                call["destination_ip"],
                self._format_packet_time(call["start_time"]),
                self._format_duration(call["duration"]),
                self._call_status_text(call),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setData(Qt.UserRole, call["dialog_key"])
                item.setToolTip(str(value))
                if column == 5:
                    item.setBackground(QColor(self._call_status_color(call, palette)))
                    item.setForeground(QColor(palette["text"]))
                table.setItem(row, column, item)
        self._restore_call_selection(table)
        table.blockSignals(False)

    def _fill_findings_table(self, table, findings):
        palette = THEMES[self.current_theme]
        table.blockSignals(True)
        table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            key = self._finding_key(finding, row)
            values = [
                severity_label(self._display_severity(finding)),
                finding.get("category", "Correlacao"),
                self._finding_title(finding),
                finding["source"],
                finding["destination"],
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setData(Qt.UserRole, key)
                item.setToolTip(str(value))
                if column == 0:
                    item.setBackground(QColor(self._severity_color(self._display_severity(finding), palette)))
                    item.setForeground(QColor(palette["text"]))
                table.setItem(row, column, item)
        self._restore_finding_selection(table)
        table.blockSignals(False)

    def _fill_incident_table(self, table, findings):
        palette = THEMES[self.current_theme]
        table.blockSignals(True)
        table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            key = self._finding_key(finding, row)
            values = [
                severity_label(self._display_severity(finding)),
                self._finding_title(finding),
                f"{finding['source']} → {finding['destination']}",
                finding.get("responsibility", "Em investigacao"),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole, key)
                item.setToolTip(value)
                if column == 0:
                    item.setBackground(QColor(self._severity_color(self._display_severity(finding), palette)))
                    item.setForeground(QColor(palette["text"]))
                table.setItem(row, column, item)
        self._restore_finding_selection(table)
        table.blockSignals(False)

    def _fill_rtp_table(self, table, streams):
        palette = THEMES[self.current_theme]
        threshold = self.analysis_settings.rtp_high_jitter_threshold
        table.blockSignals(True)
        table.setRowCount(len(streams))
        for row, stream in enumerate(streams):
            mos = stream.get("mos")
            values = [
                f"{stream['source']} → {stream['destination']}",
                f"0x{stream['ssrc']:08X}",
                self._format_stream_codecs(stream),
                str(stream["packet_count"]),
                f"{stream['loss_percent']:.2f}% ({stream['lost_packets']})",
                f"{stream['max_jitter'] * 1000:.1f} ms",
                f"{mos:.2f}" if mos is not None else "-",
                self._format_duration(stream.get("duration", 0.0)),
            ]
            tones = {
                4: self._loss_tone(stream["loss_percent"]),
                5: "danger" if stream["max_jitter"] > threshold * 2 else ("warning" if stream["max_jitter"] > threshold else None),
                6: self._mos_tone(mos),
            }
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                item.setData(Qt.UserRole, stream.get("key"))
                if column >= 3:
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                tone = tones.get(column)
                if tone:
                    item.setForeground(QColor(palette[tone]))
                table.setItem(row, column, item)
        self._restore_stream_selection(table)
        table.blockSignals(False)

    def _restore_stream_selection(self, table):
        if self.selected_stream_key is None:
            return
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item and item.data(Qt.UserRole) == self.selected_stream_key:
                table.selectRow(row)
                return

    def _selected_stream(self, streams):
        if self.selected_stream_key is not None:
            for stream in streams:
                if stream.get("key") == self.selected_stream_key:
                    return stream
        if streams:
            # Default to the worst stream: that is what the user came for.
            worst = min(streams, key=lambda item: item["mos"] if item.get("mos") is not None else 5)
            self.selected_stream_key = worst.get("key")
            self._restore_stream_selection(self.rtp_streams_table)
            return worst
        return None

    def _on_stream_selected(self):
        rows = self.rtp_streams_table.selectionModel().selectedRows()
        if not rows or self.last_viewmodel is None:
            return
        item = self.rtp_streams_table.item(rows[0].row(), 0)
        if item is None:
            return
        self.selected_stream_key = item.data(Qt.UserRole)
        stream = next(
            (entry for entry in self.last_viewmodel["rtp_streams"] if entry.get("key") == self.selected_stream_key),
            None,
        )
        self._render_stream_quality(stream)

    def _render_stream_quality(self, stream):
        palette = THEMES[self.current_theme]
        if stream is None:
            self.rtp_health_text.set_message("Nenhum stream RTP detectado nesta captura.")
            self.rtp_timeline.set_stream([])
            return
        mos = stream.get("mos")
        threshold = self.analysis_settings.rtp_high_jitter_threshold
        self.rtp_health_text.set_metrics(
            [
                ("MOS estimado", f"{mos:.2f}" if mos is not None else "-", self._mos_tone(mos)),
                ("Perda", f"{stream['loss_percent']:.2f}% ({stream['lost_packets']})", self._loss_tone(stream["loss_percent"])),
                (
                    "Jitter max (RFC 3550)",
                    f"{stream['max_jitter'] * 1000:.1f} ms",
                    "danger" if stream["max_jitter"] > threshold * 2 else ("warning" if stream["max_jitter"] > threshold else None),
                ),
                ("Pico entre pacotes", f"{stream.get('peak_transit_variation', 0.0) * 1000:.0f} ms"),
                ("Fora de ordem", stream["out_of_order_packets"], "warning" if stream["out_of_order_packets"] else None),
                (
                    "Pausas",
                    f"{stream.get('silence_periods', 0)} silencio / {stream['interruptions']} falha",
                    "danger" if stream["interruptions"] else None,
                ),
            ],
            palette,
        )
        timeline = stream.get("timeline") or {}
        self.rtp_timeline.set_stream(
            timeline.get("points", []),
            timeline.get("losses", []),
            f"{stream['source']} \u2192 {stream['destination']}  |  SSRC 0x{stream['ssrc']:08X}  |  {self._format_stream_codecs(stream)}",
            threshold,
        )

    def _loss_tone(self, loss_percent):
        if loss_percent >= LOSS_HIGH_QUALITY_PERCENT:
            return "danger"
        if loss_percent > LOSS_TARGET_PERCENT:
            return "warning"
        return None

    def _mos_tone(self, mos):
        if mos is None:
            return None
        if mos < 3.5:
            return "danger"
        if mos < 4.0:
            return "warning"
        return "success"

    def _sorted_incidents(self, findings):
        """Severity first, then the most certain evidence (a direct RTP
        measurement beats a far-end RTCP report), then a stable order."""
        return sorted(
            findings,
            key=lambda finding: (
                SEVERITY_ORDER.get(self._display_severity(finding), 9),
                -finding.get("confidence", 0.0),
                finding["type"],
            ),
        )

    def _severity_tone(self, severity):
        return {"high": "danger", "medium": "warning", "low": "low"}.get(severity)

    def _summary_kpis(self):
        return (
            self.kpi_packets,
            self.kpi_calls,
            self.kpi_streams,
            self.kpi_findings,
            self.kpi_high,
            self.kpi_mos,
            self.kpi_duration,
            self.kpi_protocols,
        )

    def _call_markers(self):
        """Call start/end positions on the traffic chart axis."""
        if self.last_viewmodel is None:
            return []
        timebase = self.last_viewmodel.get("capture_timebase")
        if not timebase:
            return []
        first_second, bucket_width, bucket_count = timebase
        if bucket_count < 2:
            return []
        palette = THEMES[self.current_theme]
        span = (bucket_count - 1) * bucket_width
        markers = []
        for call in self.last_viewmodel["calls"][:200]:
            color = self._severity_color(call["severity"], palette) if call["severity"] in {"high", "medium"} else palette["success"]
            for moment in (call.get("start_time"), call.get("end_time")):
                if moment is None:
                    continue
                markers.append({"position": (float(moment) - first_second) / span, "color": color})
        return markers

    def _format_stream_codecs(self, stream):
        codecs = list(stream.get("codec_guesses", []))
        payload_types = stream.get("payload_types", [])
        if codecs:
            return ", ".join(codecs)
        if payload_types:
            return ", ".join(f"PT {payload_type}" for payload_type in payload_types)
        return "Nao identificado"

    def _restore_call_selection(self, table):
        if self.selected_call_id is None:
            return
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item and item.data(Qt.UserRole) == self.selected_call_id:
                table.selectRow(row)
                return

    def _restore_finding_selection(self, table):
        if self.selected_finding_key is None:
            return
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item and item.data(Qt.UserRole) == self.selected_finding_key:
                table.selectRow(row)
                return

    def _on_call_selected(self):
        table = self.sender()
        if not isinstance(table, QTableWidget):
            return
        rows = table.selectionModel().selectedRows()
        if not rows:
            return
        item = table.item(rows[0].row(), 0)
        if item is None:
            return
        call_id = item.data(Qt.UserRole)
        if call_id not in self.call_index:
            return
        self.selected_call_id = call_id
        call = self.call_index[call_id]
        self.summary_flow.set_call(call)
        self.sip_flow.set_call(call)
        self.rtp_flow.set_call(call)
        self.summary_sip_flow_button.setEnabled(True)
        self.sip_open_flow_button.setEnabled(True)
        self._render_call_text(self.summary_detail_text, call)
        self._render_call_text(self.sip_detail_text, call)
        self._render_call_text(self.rtp_detail_text, call)

    def _on_finding_selected(self):
        table = self.sender()
        if not isinstance(table, QTableWidget):
            return
        rows = table.selectionModel().selectedRows()
        if not rows:
            return
        item = table.item(rows[0].row(), 0)
        if item is None:
            return
        key = item.data(Qt.UserRole)
        self.selected_finding_key = key
        finding = self.finding_index.get(key)
        if finding is None and self.last_viewmodel is not None:
            finding = self._selected_finding(self.last_viewmodel["findings"])
        self._render_finding_text(self.network_detail_text, finding)
        self._render_finding_text(self.findings_detail_text, finding)
        self._render_finding_text(self.security_detail_text, finding)
        self._render_diagnostic_detail(finding)
        if finding is not None:
            self.findings_recommendation_text.setPlainText(finding["recommendation"] or "Sem recomendacao.")

    def _open_sip_flow_dialog(self):
        call = self._selected_call()
        if call is None or self.last_engine_result is None:
            self._set_status("Nenhuma chamada SIP selecionada")
            return

        sip_flows = self.last_engine_result.get("sip_flows", {})
        flow = sip_flows.get(call["dialog_key"])

        if flow is None:
            self._set_status("Fluxo SIP nao encontrado para a chamada selecionada")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"SIP Flow - {call['call_id']}")
        dialog.resize(980, 720)
        layout = QVBoxLayout(dialog)

        ladder = SIPLadderWidget()
        ladder.set_flow(flow)
        message_selector = QComboBox()
        header_viewer = QTextEdit()
        header_viewer.setReadOnly(True)
        header_viewer.setFont(_font("body"))
        header_viewer.setMinimumHeight(250)

        for index, message in enumerate(flow.messages):
            kind = message.method if message.is_request else f"{message.status_code} {message.reason_phrase or ''}".strip()
            message_selector.addItem(
                f"{message.packet_time:.3f} | {kind} | {message.source_ip} -> {message.destination_ip}",
                index,
            )

        def show_header(selector_index):
            message_index = message_selector.itemData(selector_index)
            if message_index is None:
                header_viewer.setPlainText("Nenhuma mensagem SIP selecionada.")
                return
            message = flow.messages[message_index]
            header_viewer.setPlainText(message.header_text or message.start_line)

        message_selector.currentIndexChanged.connect(show_header)
        ladder.message_selected.connect(message_selector.setCurrentIndex)
        show_header(message_selector.currentIndex())
        layout.addWidget(ladder, 1)
        layout.addWidget(QLabel("Clique em uma seta ou selecione a mensagem para ver o cabecalho SIP"))
        layout.addWidget(message_selector)
        layout.addWidget(header_viewer, 1)

        self._animate_widget(dialog, 0.0, 1.0, 180)
        dialog.exec()

    def _calculate_capture_duration(self, packets):
        timestamps = [float(packet.time) for packet in packets if hasattr(packet, "time")]
        if len(timestamps) < 2:
            return 0.0
        return max(timestamps) - min(timestamps)

    def _build_traffic_series(self, counters):
        names = ["SIP", "RTP", "TCP", "UDP", "ICMP"]
        palette = THEMES[self.current_theme]
        color_map = {
            "SIP": palette["accent"],
            "RTP": "#36D6C8" if self.current_theme == "dark" else "#1AA59B",
            "TCP": palette["info"],
            "UDP": "#8A63FF" if self.current_theme == "dark" else "#7057D8",
            "ICMP": palette["warning"],
        }
        return [
            {"label": name, "color": color_map[name], "values": counters[name]}
            for name in names
            if any(counters.get(name, []))
        ]

    def _format_duration(self, seconds_value):
        total_seconds = int(round(seconds_value))
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        if hours:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"

    def _format_packet_time(self, timestamp):
        if timestamp is None:
            return "-"
        try:
            moment = datetime.fromtimestamp(float(timestamp))
        except (OverflowError, OSError, ValueError):
            return f"{timestamp:.3f}"
        return moment.strftime("%H:%M:%S.") + f"{moment.microsecond // 1000:03d}"

    def _format_optional_duration(self, seconds_value):
        if seconds_value is None:
            return "-"
        return f"{seconds_value * 1000:.0f} ms"

    def _selected_call(self):
        if self.selected_call_id and self.selected_call_id in self.call_index:
            return self.call_index[self.selected_call_id]
        if self.last_viewmodel and self.last_viewmodel["calls"]:
            self.selected_call_id = self.last_viewmodel["calls"][0]["dialog_key"]
            return self.last_viewmodel["calls"][0]
        return None

    def _selected_finding(self, findings):
        if self.selected_finding_key:
            for index, finding in enumerate(findings):
                if self._finding_key(finding, index) == self.selected_finding_key:
                    return finding
        if findings:
            self.selected_finding_key = self._finding_key(findings[0], 0)
            return findings[0]
        return None

    def _render_call_text(self, widget, call):
        if call is None:
            widget.setPlainText("Nenhuma chamada detectada.")
            return
        palette = THEMES[self.current_theme]
        evidence = call.get("key_evidence_display") or call["key_evidence"] or ["Sem evidencias resumidas."]
        rtp_metrics = call["rtp_metrics"]
        loss_observation = packet_loss_observation(rtp_metrics["loss_percent"])
        jitter_observation_text = jitter_observation(
            rtp_metrics["average_jitter"],
            rtp_metrics["max_jitter"],
        )
        timings = call.get("signaling_timings", {})
        quality_metrics = call.get("media_quality_metrics", {})
        operations = call.get("signaling_operations", {})
        mos = quality_metrics.get("mos_estimate")
        mos_text = mos_observation(mos) if mos is not None else "MOS indisponivel: nao houve RTP correlacionado."
        operation_items = [
            f"re-INVITE: {operations.get('reinvites', 0)}",
            f"hold: {operations.get('holds', 0)}",
            f"resume: {operations.get('resumes', 0)}",
            f"TRANSFER: {operations.get('transfers', 0)}",
            f"OPTIONS: {operations.get('options', 0)}",
        ]
        direction_lines = [
            f"{direction}: {metric['packet_count']} pacotes, {metric['loss_percent']:.2f}% de perda, jitter max {metric['max_jitter'] * 1000:.1f} ms"
            for direction, metric in rtp_metrics.get("directions", {}).items()
        ]
        direction_html = "".join(
            f"<li style='margin-bottom:4px;'>{self._escape_html(line)}</li>" for line in direction_lines
        ) or "<li>Sem direcoes RTP correlacionadas.</li>"
        evidence_html = "".join(
            f"<li style='margin-bottom:4px;'>{self._escape_html(item)}</li>" for item in evidence
        )
        widget.setHtml(
            f"""
            <div style="font-family:'Segoe UI'; color:{palette['text']};">
                <div style="font-size:20px; font-weight:700; margin-bottom:8px;">{self._escape_html(call['call_id'])}</div>
                <div style="margin-bottom:12px;">
                    {self._chip_html(state_label(call['signaling_state']), self._signal_color(call['signaling_state'], palette), palette)}
                    &nbsp;
                    {self._chip_html(state_label(call['media_state']), self._media_color(call['media_state'], palette), palette)}
                    &nbsp;
                    {self._chip_html('Severidade ' + severity_label(call['severity']), self._severity_color(call['severity'], palette), palette)}
                </div>
                <div style="margin-bottom:8px;"><b>Origem:</b> {self._escape_html(call['source_ip'])}</div>
                <div style="margin-bottom:8px;"><b>Destino:</b> {self._escape_html(call['destination_ip'])}</div>
                <div style="margin-bottom:8px;"><b>Midia negociada:</b> {self._escape_html(state_label(call['media_direction']))}</div>
                <div style="margin-bottom:8px;"><b>Qualidade de midia:</b> {self._escape_html(state_label(call.get('media_quality', 'unknown')))}</div>
                <div style="margin-bottom:8px;"><b>Problema principal:</b> {self._escape_html(finding_title(call['primary_issue']) if call['primary_issue'] else 'Nenhum')}</div>
                <div style="margin-bottom:8px;"><b>Codecs:</b> {self._escape_html(', '.join(call['codec_guesses']) or '-')}</div>
                <div style="margin-bottom:8px;"><b>Duracao:</b> {self._format_duration(call['duration'])}</div>
                <div style="margin-bottom:8px;"><b>INVITE para 100/180/200/ACK:</b> {self._format_optional_duration(timings.get('invite_to_trying'))} / {self._format_optional_duration(timings.get('invite_to_ringing'))} / {self._format_optional_duration(timings.get('invite_to_ok'))} / {self._format_optional_duration(timings.get('invite_to_ack'))}</div>
                <div style="margin-bottom:8px;"><b>Streams RTP:</b> {call['rtp_stream_count']}</div>
                <div style="margin-bottom:8px;"><b>Pacotes RTP:</b> {rtp_metrics['packet_count']}</div>
                <div style="margin-bottom:8px;"><b>Perda de pacotes:</b> {rtp_metrics['loss_percent']:.2f}% ({rtp_metrics['lost_packets']})</div>
                <div style="margin-bottom:8px;"><b>Jitter maximo (RFC 3550):</b> {rtp_metrics['max_jitter'] * 1000:.1f} ms</div>
                <div style="margin-bottom:8px;"><b>Pior variacao entre pacotes:</b> {rtp_metrics.get('peak_transit_variation', 0.0) * 1000:.1f} ms</div>
                <div style="margin-bottom:8px;"><b>RTT (RTCP):</b> {self._format_optional_duration(rtp_metrics.get('rtt'))}</div>
                <div style="margin-bottom:8px;"><b>Pausas por silencio (VAD):</b> {rtp_metrics.get('silence_periods', 0)}</div>
                <div style="margin-bottom:8px;"><b>Fora de ordem:</b> {rtp_metrics['out_of_order_packets']}</div>
                <div style="margin-bottom:14px;"><b>SSRC:</b> {self._escape_html(', '.join(str(ssrc) for ssrc in rtp_metrics['ssrcs']) or '-')}</div>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Interpretacao de qualidade</div>
                <div style="margin-bottom:14px; padding:10px 12px; border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};">
                    <div style="margin-bottom:6px;"><b>{self._escape_html(mos_text)}</b></div>
                    <div style="margin-bottom:6px;">{self._escape_html(loss_observation)}</div>
                    <div style="margin-bottom:6px;">{self._escape_html(jitter_observation_text)}</div>
                    <div style="color:{palette['muted']};">{self._escape_html(quality_reference_note())}</div>
                </div>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Operacoes SIP</div>
                <div style="margin-bottom:14px; padding:10px 12px; border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};">
                    {self._escape_html(' | '.join(operation_items))}
                </div>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">RTP por direcao</div>
                <ul style="margin-top:0; margin-bottom:14px; padding-left:18px;">{direction_html}</ul>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Evidencias</div>
                <ul style="margin-top:0; margin-bottom:14px; padding-left:18px;">{evidence_html}</ul>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Acao recomendada</div>
                <div style="padding:10px 12px; border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};">
                    {self._escape_html(call["recommended_action"] or "Sem recomendacao.")}
                </div>
            </div>
            """
        )

    def _build_sip_flow_html(self, flow):
        palette = THEMES[self.current_theme]
        rows = []

        for message in flow.messages:
            if message.is_request:
                direction = f"{message.source_ip}:{message.source_port} &#8594; {message.destination_ip}:{message.destination_port}"
                kind = self._escape_html(message.method or "REQUEST")
                direction_color = palette["accent"]
            else:
                direction = f"{message.destination_ip}:{message.destination_port} &#8592; {message.source_ip}:{message.source_port}"
                kind = self._escape_html(f"{message.status_code} {message.reason_phrase or ''}".strip())
                direction_color = palette["info"]

            rows.append(
                f"""
                <tr>
                    <td style="padding:10px 12px; border-bottom:1px solid {palette['border']}; color:{palette['muted']};">
                        {message.packet_time:.3f}
                    </td>
                    <td style="padding:10px 12px; border-bottom:1px solid {palette['border']};">
                        <span style="background:{direction_color}; color:{palette['text']}; padding:5px 8px; border-radius:10px; font-weight:600;">
                            {direction}
                        </span>
                    </td>
                    <td style="padding:10px 12px; border-bottom:1px solid {palette['border']}; color:{palette['text']};">
                        {kind}
                    </td>
                    <td style="padding:10px 12px; border-bottom:1px solid {palette['border']}; color:{palette['muted']};">
                        {self._escape_html(message.start_line)}
                    </td>
                </tr>
                """
            )

        return (
            f"""
            <div style="font-family:'Segoe UI'; color:{palette['text']};">
                <div style="font-size:22px; font-weight:700; margin-bottom:6px;">{self._escape_html(flow.call_id)}</div>
                <div style="margin-bottom:16px; color:{palette['muted']};">
                    {self._escape_html(flow.source_ip)} &#8644; {self._escape_html(flow.destination_ip)}
                </div>
                <div style="margin-bottom:16px; padding:12px 14px; border:1px solid {palette['border']}; border-radius:12px; background:{palette['surface']};">
                    <b>Resumo:</b> INVITE={flow.invites} | RESP={flow.responses} | 2xx={flow.success_responses} | ACK={flow.acknowledgements} | BYE={flow.byes} | CANCEL={flow.cancels}
                </div>
                <table style="width:100%; border-collapse:collapse; background:{palette['surface']}; border:1px solid {palette['border']}; border-radius:12px;">
                    <thead>
                        <tr>
                            <th style="text-align:left; padding:10px 12px; border-bottom:1px solid {palette['border']};">Tempo</th>
                            <th style="text-align:left; padding:10px 12px; border-bottom:1px solid {palette['border']};">Fluxo</th>
                            <th style="text-align:left; padding:10px 12px; border-bottom:1px solid {palette['border']};">Mensagem</th>
                            <th style="text-align:left; padding:10px 12px; border-bottom:1px solid {palette['border']};">Start-Line</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows) or f"<tr><td colspan='4' style='padding:14px;'>Sem mensagens SIP.</td></tr>"}
                    </tbody>
                </table>
            </div>
            """
        )

    def _render_diagnostic_detail(self, finding):
        if finding is None:
            self.diagnostic_detail_text.setPlainText("Selecione um incidente para ver as evidencias.")
            return

        evidence = finding.get("evidence_display") or finding.get("evidence", [])
        technical_context = build_finding_evidence_context(self.last_engine_result, finding)
        references = finding.get("references", [])
        lines = [
            f"Falha: {self._finding_title(finding)}",
            f"Codigo: {finding['type']}",
            f"Camada: {finding.get('category', 'Correlacao')}",
            f"De: {finding['source']}",
            f"Para: {finding['destination']}",
            f"Possivel responsavel: {finding.get('responsibility', 'Em investigacao')}",
            f"Confianca da atribuicao: {severity_label(finding.get('responsibility_confidence', 'low'))}",
            "",
            "Por que:",
            finding.get("responsibility_reason", "Sem atribuicao conclusiva."),
            "",
            "Evidencias:",
            *(f"- {item}" for item in evidence[:6]),
            *(
                ["", "Analise tecnica:", *technical_context]
                if technical_context
                else []
            ),
            *(
                [
                    "",
                    "Referencias tecnicas:",
                    *(
                        f"- {item['title']}\n"
                        f"  Aplicacao: {item.get('scope', 'Referencia tecnica do protocolo.')}\n"
                        f"  Fonte: {item['url']}"
                        for item in references
                    ),
                ]
                if references
                else []
            ),
            "",
            "Proxima acao:",
            finding["recommendation"] or "Investigue o fluxo entre os endpoints.",
        ]
        self.diagnostic_detail_text.setPlainText("\n".join(lines))

    def _render_finding_text(self, widget, finding):
        if finding is None:
            widget.setPlainText("Nenhum finding selecionado.")
            return
        palette = THEMES[self.current_theme]
        evidence = finding.get("evidence_display") or finding.get("evidence", [])
        technical_context = build_finding_evidence_context(self.last_engine_result, finding)
        evidence_html = "".join(
            f"<li style='margin-bottom:4px;'>{self._escape_html(item)}</li>"
            for item in evidence
        ) or "<li>Sem evidencias adicionais.</li>"
        technical_context_html = "".join(
            f"<li style='margin-bottom:4px;'>{self._escape_html(item)}</li>"
            for item in technical_context
        ) or "<li>Sem correlacoes adicionais para este finding.</li>"
        references_html = "".join(
            f"<li style='list-style:none; margin:0 0 10px 0; padding:10px 12px; "
            f"border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};'>"
            f"<div style='font-weight:700; margin-bottom:5px;'>{self._escape_html(item['title'])}</div>"
            f"<div style='margin-bottom:5px;'><b>Aplicacao:</b> "
            f"{self._escape_html(item.get('scope', 'Referencia tecnica do protocolo.'))}</div>"
            f"<div style='color:{palette['muted']};'><b>Fonte:</b> "
            f"{self._escape_html(item['url'])}</div></li>"
            for item in finding.get("references", [])
        ) or "<li>Referencia tecnica nao cadastrada.</li>"
        widget.setHtml(
            f"""
            <div style="font-family:'Segoe UI'; color:{palette['text']};">
                <div style="font-size:18px; font-weight:700; margin-bottom:2px;">{self._escape_html(self._finding_title(finding))}</div>
                <div style="color:{palette['muted']}; font-family:Consolas; margin-bottom:8px;">{self._escape_html(finding['type'])}</div>
                <div style="margin-bottom:12px;">
                    {self._chip_html(severity_label(self._display_severity(finding)), self._severity_color(self._display_severity(finding), palette), palette)}
                </div>
                <div style="margin-bottom:8px;"><b>Origem:</b> {self._escape_html(finding['source'])}</div>
                <div style="margin-bottom:12px;"><b>Destino:</b> {self._escape_html(finding['destination'])}</div>
                <div style="margin-bottom:12px;"><b>Camada responsavel:</b> {self._escape_html(finding.get('category', 'Correlacao'))}</div>
                <div style="margin-bottom:8px;"><b>Possivel responsavel:</b> {self._escape_html(finding.get('responsibility', 'Em investigacao'))}</div>
                <div style="margin-bottom:12px;"><b>Confianca da atribuicao:</b> {self._escape_html(severity_label(finding.get('responsibility_confidence', 'low')))}</div>
                <div style="margin-bottom:14px; padding:10px 12px; border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};">
                    {self._escape_html(finding.get('responsibility_reason', 'Sem atribuicao conclusiva.'))}
                </div>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Descricao</div>
                <div style="margin-bottom:14px; padding:10px 12px; border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};">
                    {self._escape_html(finding["description"] or "-")}
                </div>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Evidencias principais</div>
                <ul style="margin-top:0; margin-bottom:14px; padding-left:18px;">{evidence_html}</ul>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Contexto tecnico capturado</div>
                <ul style="margin-top:0; margin-bottom:14px; padding-left:18px;">{technical_context_html}</ul>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Referencias tecnicas</div>
                <ul style="margin:0 0 14px 0; padding:0;">{references_html}</ul>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Recomendacao</div>
                <div style="padding:10px 12px; border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};">
                    {self._escape_html(finding["recommendation"] or "-")}
                </div>
            </div>
            """
        )

    def _finding_lines(self, findings, limit):
        return [
            f"{severity_label(self._display_severity(finding))} | {finding.get('category', 'Correlacao')} | {self._finding_title(finding)}"
            for finding in findings[:limit]
        ]

    def _finding_category_summary(self, findings):
        counts = {}
        for finding in findings:
            category = finding.get("category", "Correlacao")
            counts[category] = counts.get(category, 0) + 1
        return ", ".join(
            f"{category} ({count})"
            for category, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        ) or "Nenhuma"

    def _responsibility_summary(self, findings):
        counts = {}
        for finding in findings:
            responsibility = finding.get("responsibility", "Em investigacao")
            counts[responsibility] = counts.get(responsibility, 0) + 1
        return ", ".join(
            f"{responsibility} ({count})"
            for responsibility, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        ) or "Nenhuma"

    def _finding_key(self, finding, index):
        return finding.get("key", f"{index}:{finding['type']}:{finding['source']}:{finding['destination']}")

    def _set_status(self, text):
        self.sidebar_status.setText(text)
        self.status_bar_label.setText(text)

    def _animate_widget(self, widget, start_opacity, end_opacity, duration):
        effect = widget.graphicsEffect()
        if not isinstance(effect, QGraphicsOpacityEffect):
            effect = QGraphicsOpacityEffect(widget)
            widget.setGraphicsEffect(effect)
        animation = QPropertyAnimation(effect, b"opacity", widget)
        animation.setDuration(duration)
        animation.setStartValue(start_opacity)
        animation.setEndValue(end_opacity)
        animation.setEasingCurve(QEasingCurve.OutCubic)
        self.active_animations.append(animation)

        def _cleanup():
            if animation in self.active_animations:
                self.active_animations.remove(animation)

        animation.finished.connect(_cleanup)
        animation.start()

    def _page_icon(self, page):
        palette = THEMES[self.current_theme]
        return make_nav_icon(page, palette["muted"])

    def _refresh_nav_icons(self):
        for button, page in self.nav_icon_buttons:
            button.setIcon(self._page_icon(page))

    def _toggle_nav_section(self, title, expanded=None):
        section = self.nav_sections.get(title)
        if section is None:
            return
        section["expanded"] = (not section["expanded"]) if expanded is None else expanded
        for button in section["buttons"]:
            button.setVisible(section["expanded"])
        arrow = "\u25BE" if section["expanded"] else "\u25B8"
        section["header"].setText(f"{arrow}  {title.upper()}")

    def _severity_color(self, severity, palette):
        return {
            "high": palette["danger"],
            "medium": palette["warning"],
            "low": palette["low"],
            "info": palette["muted"],
        }.get(severity, palette["muted"])

    def _count_display_severity(self, severity):
        return sum(
            1 for finding in self.last_viewmodel["findings"] if self._display_severity(finding) == severity
        )

    def _display_severity(self, finding):
        return finding.get("display_severity", finding["severity"])

    def _finding_title(self, finding):
        return finding.get("title") or finding_title(finding["type"])

    def _call_status_color(self, call, palette):
        if call["severity"] in {"high", "medium"}:
            return self._severity_color(call["severity"], palette)
        if call["signaling_state"] in {"established", "terminated"}:
            return palette["success"]
        return palette["low"]

    def _call_status_text(self, call):
        state = state_label(call["signaling_state"])
        if call["severity"] in {"high", "medium"}:
            return f"{state} - {severity_label(call['severity'])}"
        return state

    def _signal_color(self, state, palette):
        return {
            "established": palette["success"],
            "completed": palette["success"],
            "terminated": palette["success"],
            "ringing": palette["warning"],
            "setup_incomplete": palette["warning"],
            "missing_ack": palette["warning"],
            "no_response": palette["warning"],
            "incomplete": palette["warning"],
            "failed": palette["danger"],
            "cancelled": palette["danger"],
            "unknown": palette["muted"],
        }.get(state, palette["accent"])

    def _media_color(self, state, palette):
        return {
            "ok": palette["success"],
            "media_present": palette["success"],
            "degraded_media": palette["warning"],
            "one_way_media": palette["danger"],
            "no_media": palette["danger"],
            "inactive_media": palette["muted"],
        }.get(state, palette["accent"])

    def _chip_html(self, label, color, palette):
        return (
            f"<span style=\"background:{color}; color:{palette['text']}; "
            f"padding:5px 9px; border-radius:10px; font-size:9pt; font-weight:600;\">"
            f"{self._escape_html(label)}</span>"
        )

    def _escape_html(self, text):
        value = str(text)
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )


def launch_gui(argv=None):
    argv = list(sys.argv if argv is None else argv)
    app = QApplication.instance() or QApplication(argv)
    app.setWindowIcon(QIcon(str(LOGO_ICON_PATH)))
    window = SipperWindow()
    window.show()
    captures = [arg for arg in argv[1:] if Path(arg).suffix.lower() in CAPTURE_SUFFIXES]
    if captures:
        QTimer.singleShot(0, lambda: window.open_capture(captures[0]))
    app.exec()
