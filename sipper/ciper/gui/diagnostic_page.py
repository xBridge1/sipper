"""The Diagnostico page, the SIP Flow dialog and ticket summaries.

Mixin of ``SipperWindow``; split out of ``ciper/gui/app.py``.
"""

from pathlib import Path
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from ciper.gui.flow_focus import culprit_messages, message_html
from ciper.ticket import build_call_ticket, build_capture_ticket
from ciper.labels import is_actionable
from ciper.gui.theme import THEMES
from ciper.gui.widgets import MetricGrid, PanelCard, SIPLadderWidget, VerdictBanner, _font


class DiagnosticPageMixin:
    def _build_diagnostic_page(self):
        _page, layout = self._new_grid_page("Diagnostico", [4, 5], [0, 1])
        self.diagnostic_priority = PanelCard("Veredito da captura")
        self.diagnostic_incidents = PanelCard("Fila de incidentes (causa raiz primeiro)")
        self.diagnostic_detail = PanelCard("Evidencia e proxima acao")
        self.diagnostic_verdict = VerdictBanner()
        self.diagnostic_scope_text = MetricGrid(columns=4)
        self.diagnostic_incidents_table = self._make_incident_table()
        self.diagnostic_detail_text = self._make_text()
        self.diagnostic_priority.add_widget(self.diagnostic_verdict)
        actions = QWidget()
        actions_layout = QHBoxLayout(actions)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(10)
        self.diagnostic_copy_button = QPushButton("Copiar resumo para chamado")
        self.diagnostic_copy_button.setObjectName("secondaryButton")
        self.diagnostic_copy_button.clicked.connect(self._copy_capture_ticket)
        self.diagnostic_flow_button = QPushButton("Abrir SIP Flow da chamada de referencia")
        self.diagnostic_flow_button.setObjectName("secondaryButton")
        self.diagnostic_flow_button.clicked.connect(self._open_reference_flow)
        self.diagnostic_root_only = QCheckBox("Mostrar so causas raiz")
        self.diagnostic_root_only.toggled.connect(self._render_diagnostic_page)
        actions_layout.addWidget(self.diagnostic_copy_button)
        actions_layout.addWidget(self.diagnostic_flow_button)
        actions_layout.addStretch(1)
        actions_layout.addWidget(self.diagnostic_root_only)
        self.diagnostic_priority.add_widget(actions)
        self.diagnostic_priority.add_widget(self.diagnostic_scope_text)
        self.diagnostic_incidents.add_widget(self.diagnostic_incidents_table)
        self.diagnostic_detail.add_widget(self.diagnostic_detail_text)
        layout.addWidget(self.diagnostic_priority, 0, 0, 1, 2)
        layout.addWidget(self.diagnostic_incidents, 1, 0)
        layout.addWidget(self.diagnostic_detail, 1, 1)
        self._register_page_cards(
            "Diagnostico",
            self.diagnostic_priority,
            self.diagnostic_incidents,
            self.diagnostic_detail,
        )

    def _render_diagnostic_page(self):
        palette = THEMES[self.current_theme]
        if self.last_viewmodel is None:
            self.diagnostic_verdict.set_empty("Abra um PCAP para ver o veredito e o provavel culpado.")
            self.diagnostic_scope_text.set_message("Nenhum diagnostico carregado.")
            self.diagnostic_detail_text.setPlainText("Selecione um incidente para ver as evidencias.")
            self._fill_incident_table(self.diagnostic_incidents_table, [])
            return

        diagnosis = self.last_viewmodel.get("diagnosis") or {}
        incidents = self._sorted_incidents(self.last_viewmodel["findings"])
        actionable = [
            finding
            for finding in incidents
            if finding["severity"] in {"high", "medium"} and is_actionable(finding)
        ]
        self.diagnostic_verdict.set_verdict(diagnosis, palette, self._diagnosis_stats_text(diagnosis))
        calls = diagnosis.get("calls") or {}
        high_count = sum(1 for finding in actionable if self._display_severity(finding) == "high")
        breakdown = diagnosis.get("breakdown") or []
        self.diagnostic_scope_text.set_metrics(
            [
                ("Chamadas com falha", calls.get("fail", 0), "danger" if calls.get("fail") else None),
                ("Audio degradado", calls.get("degraded", 0), "warning" if calls.get("degraded") else None),
                ("Com risco", calls.get("risk", 0), "warning" if calls.get("risk") else None),
                ("Sem problema", calls.get("ok", 0) + calls.get("user", 0), "success" if calls.get("total") else None),
                (
                    "Causas por chamada",
                    "; ".join(f"{item['title']} ({item['calls']})" for item in breakdown[:4]) or "Nenhuma",
                    None,
                    2,
                ),
                ("Incidentes acionaveis", f"{len(actionable)} ({high_count} alta)", "danger" if high_count else None),
                ("Camadas afetadas", self._finding_category_summary(actionable or incidents), None),
            ],
            palette,
        )
        queue = actionable or incidents
        if self.diagnostic_root_only.isChecked():
            queue = [finding for finding in queue if finding.get("is_root_cause")] or queue
        self.diagnostic_copy_button.setEnabled(bool(diagnosis))
        self.diagnostic_flow_button.setEnabled(bool(diagnosis.get("worst_dialog_key")))
        self._fill_incident_table(self.diagnostic_incidents_table, queue)
        self._render_diagnostic_detail(self._selected_finding(queue))

    def _copy_capture_ticket(self):
        if self.last_viewmodel is None:
            return
        text = build_capture_ticket(
            self.last_viewmodel.get("diagnosis") or {},
            Path(getattr(self, "analyzed_file", "") or "").name,
            self.last_viewmodel.get("capture_point"),
        )
        QApplication.clipboard().setText(text)
        self._set_status("Resumo do diagnostico copiado para a area de transferencia")

    def _copy_call_ticket(self):
        call = self._selected_call()
        if call is None:
            self._set_status("Nenhuma chamada selecionada")
            return
        QApplication.clipboard().setText(build_call_ticket(call, Path(getattr(self, "analyzed_file", "") or "").name))
        self._set_status("Resumo da chamada copiado para a area de transferencia")

    def _open_reference_flow(self):
        diagnosis = (self.last_viewmodel or {}).get("diagnosis") or {}
        key = diagnosis.get("worst_dialog_key")
        if key and key in self.call_index:
            self.selected_call_id = key
            self._open_sip_flow_dialog()

    def _call_findings(self, call):
        if self.last_viewmodel is None or call is None:
            return []
        marker = f"Call-ID: {call['call_id']}"
        return [finding for finding in self.last_viewmodel["findings"] if marker in finding.get("evidence", [])]

    def _diagnosis_stats_text(self, diagnosis):
        calls = diagnosis.get("calls") or {}
        parts = []
        capture = (self.last_viewmodel or {}).get("capture_point") or {}
        if capture.get("ip"):
            parts.append(f"ponto de captura: {capture['ip']} ({'auto' if capture.get('auto') else 'configurado'})")
        if calls.get("total"):
            parts.append(f"{calls['total']} chamada(s) analisada(s)")
        if diagnosis.get("worst_call_id"):
            parts.append(f"chamada de referencia: {diagnosis['worst_call_id']}")
        if diagnosis.get("network_issues"):
            parts.append("tambem na rede: " + ", ".join(diagnosis["network_issues"][:3]))
        return " | ".join(parts)

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
        focus = culprit_messages(flow, self._call_findings(call), call.get("verdict") or {})
        ladder.set_highlighted({index: item["title"] for index, item in focus.items()})
        message_selector = QComboBox()
        header_viewer = QTextEdit()
        header_viewer.setReadOnly(True)
        header_viewer.setFont(_font("body"))
        header_viewer.setMinimumHeight(250)
        palette = THEMES[self.current_theme]

        for index, message in enumerate(flow.messages):
            kind = message.method if message.is_request else f"{message.status_code} {message.reason_phrase or ''}".strip()
            marker = "!  " if index in focus else ""
            message_selector.addItem(
                f"{marker}{message.packet_time:.3f} | {kind} | {message.source_ip} -> {message.destination_ip}",
                index,
            )

        def show_header(selector_index):
            message_index = message_selector.itemData(selector_index)
            if message_index is None:
                header_viewer.setPlainText("Nenhuma mensagem SIP selecionada.")
                return
            message = flow.messages[message_index]
            header_viewer.setHtml(
                message_html(message, focus.get(message_index), palette, self._escape_html)
            )

        message_selector.currentIndexChanged.connect(show_header)
        ladder.message_selected.connect(message_selector.setCurrentIndex)
        if focus:
            message_selector.setCurrentIndex(min(focus, key=lambda index: focus[index]["rank"]))
        show_header(message_selector.currentIndex())
        layout.addWidget(ladder, 1)
        layout.addWidget(
            QLabel(
                "Mensagens com '!' contem a evidencia do provavel culpado. Clique em uma seta ou selecione a mensagem."
                if focus
                else "Clique em uma seta ou selecione a mensagem para ver o cabecalho SIP"
            )
        )
        layout.addWidget(message_selector)
        layout.addWidget(header_viewer, 1)

        self._animate_widget(dialog, 0.0, 1.0, 180)
        dialog.exec()
