"""Creation and filling of the calls, findings, incident and RTP tables.

Mixin of ``SipperWindow``; split out of ``ciper/gui/app.py``.
"""

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QColor, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
)
from ciper.labels import severity_label
from ciper.gui.theme import THEMES


class TablesMixin:
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
        table.setHorizontalHeaderLabels(["Prioridade", "Incidente", "De \u2192 Para", "Provavel culpado"])
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
            title = self._finding_title(finding)
            if finding.get("is_root_cause"):
                title = f"Causa raiz · {title}"
            if finding.get("confirmed_by"):
                title = f"{title} (confirmado: {finding['confirmed_by']})"
            values = [
                severity_label(self._display_severity(finding)),
                title,
                f"{finding['source']} → {finding['destination']}",
                finding.get("culprit") or finding.get("responsibility", "Em investigacao"),
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
