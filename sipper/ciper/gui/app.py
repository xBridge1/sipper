import sys
from threading import Event
from pathlib import Path

from PySide6.QtCore import QAbstractAnimation, QEasingCurve, QObject, QPointF, QRectF, QSize, QPropertyAnimation, QThread, Qt, Signal, Slot, QVariantAnimation
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPen, QPixmap
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
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QProgressBar,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QStyle,
)

from ciper.analyzer import analyze_packets
from ciper.analysis_control import AnalysisCancelled, raise_if_cancelled
from ciper.engine import analyze_pcap_file
from ciper.gui.theme import FONTS, THEMES
from ciper.gui.viewmodels import build_dashboard_viewmodel
from ciper.pcap_reader import iter_pcap
from ciper.reporting import build_report_payload, export_csv, export_json, export_pdf
from ciper.rtp import parse_rtp_packet
from ciper.settings import AnalysisSettings, load_settings, save_settings
from ciper.sip import parse_sip_message
from ciper.logging_setup import configure_logging
from scapy.layers.inet import ICMP, IP, TCP, UDP


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOGO_ICON_PATH = PROJECT_ROOT / "logo" / "sipper_1_pulse_preview.ico"
LOGO_PREVIEW_PATH = PROJECT_ROOT / "logo" / "9761bd23-eb2a-4777-8de4-2910814a3f4c.png"
DARK_SPLASH_LOGO_PATH = PROJECT_ROOT / "logo" / "splash.png"
LIGHT_SPLASH_LOGO_PATH = PROJECT_ROOT / "logo" / "splash_black.png"


def _font(key):
    family, size, *rest = FONTS[key]
    font = QFont(family, size)
    if rest and "Semibold" in family:
        font.setWeight(QFont.DemiBold)
    return font


def _animate_chart(widget):
    animation = getattr(widget, "chart_animation", None)
    if animation is None:
        animation = QVariantAnimation(widget)
        animation.setDuration(520)
        animation.setEasingCurve(QEasingCurve.OutCubic)
        animation.valueChanged.connect(
            lambda value, target=widget: _set_chart_progress(target, value)
        )
        widget.chart_animation = animation
    animation.stop()
    widget.chart_progress = 0.0
    animation.setStartValue(0.0)
    animation.setEndValue(1.0)
    animation.start()


def _set_chart_progress(widget, value):
    widget.chart_progress = float(value)
    widget.update()


class AnalysisWorker(QObject):
    progress_changed = Signal(str)
    completed = Signal(object, object, object, object, float)
    failed = Signal(str)

    def __init__(self, file_path, settings):
        super().__init__()
        self.file_path = file_path
        self.settings = settings
        self.cancel_event = Event()
        self.logger = configure_logging()

    def cancel(self):
        self.cancel_event.set()

    @Slot()
    def run(self):
        try:
            if not Path(self.file_path).is_file():
                raise ValueError("Arquivo PCAP nao encontrado")
            size_bytes = Path(self.file_path).stat().st_size
            max_size_bytes = self.settings.max_pcap_size_mb * 1024 * 1024
            if size_bytes > max_size_bytes:
                raise ValueError(
                    f"Arquivo PCAP excede o limite configurado de {self.settings.max_pcap_size_mb} MB"
                )
            self.progress_changed.emit("Lendo arquivo PCAP")
            self.progress_changed.emit("Classificando protocolos")
            packet_analysis = analyze_packets(iter_pcap(self.file_path), self.cancel_event)
            self.progress_changed.emit("Correlacionando rede, SIP e RTP")
            engine_result = analyze_pcap_file(self.file_path, self.settings, self.cancel_event)
            self.progress_changed.emit("Preparando graficos")
            traffic_counts, traffic_labels, capture_duration = _build_traffic_counts(
                _iter_with_cancellation(iter_pcap(self.file_path), self.cancel_event), self.settings.max_traffic_points
            )
            raise_if_cancelled(self.cancel_event)
            self.completed.emit(
                packet_analysis,
                engine_result,
                traffic_counts,
                traffic_labels,
                capture_duration,
            )
        except AnalysisCancelled as error:
            self.failed.emit(str(error))
        except Exception as error:
            self.logger.exception("Falha durante analise de PCAP: %s", self.file_path)
            self.failed.emit(str(error))


def _iter_with_cancellation(packets, cancel_event):
    for packet in packets:
        raise_if_cancelled(cancel_event)
        yield packet


def _build_traffic_counts(packets, max_bucket_count=720):
    names = ["SIP", "RTP", "TCP", "UDP", "ICMP"]
    max_bucket_count = max(1, max_bucket_count)
    buckets = {name: {} for name in names}
    first_time = None
    last_time = None

    for packet in packets:
        if not hasattr(packet, "time"):
            continue
        timestamp = float(packet.time)
        second = int(timestamp)
        first_time = timestamp if first_time is None else min(first_time, timestamp)
        last_time = timestamp if last_time is None else max(last_time, timestamp)
        protocol = _classify_packet_for_traffic(packet)
        if protocol in buckets:
            buckets[protocol][second] = buckets[protocol].get(second, 0) + 1

    if first_time is None or last_time is None:
        return {}, [], 0.0

    first_second = int(first_time)
    last_second = int(last_time)
    span_seconds = max(1, last_second - first_second + 1)
    bucket_width = max(1, (span_seconds + max_bucket_count - 1) // max_bucket_count)
    bucket_count = (span_seconds + bucket_width - 1) // bucket_width
    counters = {name: [0] * bucket_count for name in names}

    for name in names:
        for second, count in buckets[name].items():
            index = min((second - first_second) // bucket_width, bucket_count - 1)
            counters[name][index] += count

    labels = [_format_axis_time(index * bucket_width) for index in range(bucket_count)]
    return counters, labels, last_time - first_time


def _classify_packet_for_traffic(packet):
    if parse_sip_message(packet) is not None:
        return "SIP"
    if parse_rtp_packet(packet) is not None:
        return "RTP"
    if IP in packet and TCP in packet:
        return "TCP"
    if IP in packet and UDP in packet:
        return "UDP"
    if IP in packet and ICMP in packet:
        return "ICMP"
    return None


def _format_axis_time(seconds_offset):
    minutes = int(seconds_offset) // 60
    seconds = int(seconds_offset) % 60
    return f"{minutes:02d}:{seconds:02d}"


class PanelCard(QFrame):
    def __init__(self, title):
        super().__init__()
        self.setObjectName("panelCard")
        self.title_label = QLabel(title)
        self.title_label.setObjectName("panelTitle")
        self.title_label.setFont(_font("subtitle"))
        self.body_layout = QVBoxLayout()
        self.body_layout.setContentsMargins(18, 6, 18, 18)
        self.body_layout.setSpacing(12)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.title_label)
        layout.addLayout(self.body_layout)

    def set_title(self, title):
        self.title_label.setText(title)

    def add_widget(self, widget, stretch=0):
        self.body_layout.addWidget(widget, stretch)


class KPIStat(QFrame):
    def __init__(self, label):
        super().__init__()
        self.setObjectName("kpiStat")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)
        self.value_label = QLabel("0")
        self.value_label.setObjectName("kpiValue")
        self.value_label.setFont(QFont("Segoe UI", 24, QFont.DemiBold))
        self.label = QLabel(label)
        self.label.setObjectName("kpiLabel")
        self.label.setFont(_font("small"))
        layout.addWidget(self.value_label)
        layout.addWidget(self.label)

    def set_value(self, value):
        self.value_label.setText(str(value))


class CallFlowWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.call = None
        self.setMinimumHeight(130)

    def set_call(self, call):
        self.call = call
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), Qt.transparent)

        if self.call is None:
            painter.setPen(QColor("#777777"))
            painter.drawText(self.rect(), Qt.AlignCenter, "Sem fluxo selecionado")
            return

        stages = self._build_stages()
        rect = self.rect().adjusted(18, 18, -18, -18)
        count = max(len(stages), 1)
        gap = rect.width() / count
        y = rect.center().y() - 8

        for index, stage in enumerate(stages):
            x = rect.left() + (gap * index) + (gap / 2)
            if index < len(stages) - 1:
                next_x = rect.left() + (gap * (index + 1)) + (gap / 2)
                painter.setPen(QPen(QColor(stage["line"]), 3, Qt.SolidLine, Qt.RoundCap))
                painter.drawLine(QPointF(x + 14, y), QPointF(next_x - 14, y))

            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(stage["fill"]))
            painter.drawEllipse(QRectF(x - 12, y - 12, 24, 24))
            painter.setPen(QColor(stage["text"]))
            painter.setFont(_font("small"))
            painter.drawText(QRectF(x - 54, y + 18, 108, 18), Qt.AlignCenter, stage["label"])

    def _build_stages(self):
        palette = THEMES["dark"]
        if self.call is not None:
            palette = THEMES["dark"] if self.palette().window().color().lightness() < 128 else THEMES["light"]

        signaling = self.call["signaling_state"]
        media = self.call["media_state"]
        severity = self.call["severity"]

        complete = palette["success"]
        warning = palette["warning"]
        accent = palette["accent"]
        neutral = palette["muted"]
        danger = palette["danger"]
        text = palette["text"]

        setup_fill = complete if signaling in {"established", "completed"} else warning if signaling != "unknown" else neutral
        ack_fill = complete if signaling == "established" else warning if signaling in {"setup_incomplete", "ringing"} else neutral
        media_fill = complete if media == "ok" else warning if media in {"degraded_media", "one_way_media"} else neutral
        quality_fill = danger if severity == "high" else warning if severity == "medium" else accent

        return [
            {"label": "INVITE", "fill": setup_fill, "line": setup_fill, "text": text},
            {"label": "200 OK", "fill": setup_fill, "line": ack_fill, "text": text},
            {"label": "ACK", "fill": ack_fill, "line": media_fill, "text": text},
            {"label": "RTP", "fill": media_fill, "line": quality_fill, "text": text},
            {"label": "Qualidade", "fill": quality_fill, "line": quality_fill, "text": text},
        ]


class DonutChart(QWidget):
    def __init__(self):
        super().__init__()
        self.series = []
        self.total_label = ""
        self.subtitle = ""
        self.chart_progress = 1.0
        self.setMinimumHeight(180)

    def set_series(self, series, total_label="", subtitle=""):
        self.series = series
        self.total_label = total_label
        self.subtitle = subtitle
        _animate_chart(self)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), Qt.transparent)

        if not self.series:
            painter.setPen(QColor("#777777"))
            painter.drawText(self.rect(), Qt.AlignCenter, "Sem dados")
            return

        rect = self.rect().adjusted(12, 12, -12, -12)
        has_legend = rect.width() >= 320
        chart_size = min(rect.height() - 12, rect.width() * (0.42 if has_legend else 0.74), 172)
        chart_size = max(chart_size, 88)
        chart_rect = QRectF(rect.left(), rect.top(), chart_size, chart_size)
        chart_rect.moveTop(rect.top() + (rect.height() - chart_rect.height()) / 2)
        if has_legend:
            chart_rect.moveLeft(rect.left() + 8)
        else:
            chart_rect.moveLeft(rect.left() + (rect.width() - chart_rect.width()) / 2)
        total = sum(item["value"] for item in self.series)
        angle = 90 * 16

        for item in self.series:
            span = 0 if total == 0 else int((item["value"] / total) * -360 * 16 * self.chart_progress)
            painter.setBrush(QColor(item["color"]))
            painter.setPen(QPen(QColor(item["border"]), 1))
            painter.drawPie(chart_rect, angle, span)
            angle += span

        ring_width = max(20, min(34, chart_rect.width() * 0.22))
        inner = chart_rect.adjusted(ring_width, ring_width, -ring_width, -ring_width)
        painter.setBrush(QColor(self.palette().base().color()))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(inner)

        center_x = inner.center().x()
        center_y = inner.center().y()
        value_font = QFont("Segoe UI", 15 if len(self.total_label) > 6 else 18, QFont.DemiBold)
        painter.setPen(QColor(self.palette().text().color()))
        painter.setFont(value_font)
        painter.drawText(QRectF(center_x - 58, center_y - 24, 116, 24), Qt.AlignCenter, self.total_label)

        if self.subtitle:
            painter.setPen(QColor("#9A9A9A"))
            painter.setFont(_font("small"))
            painter.drawText(QRectF(center_x - 46, center_y + 2, 92, 18), Qt.AlignCenter, self.subtitle)

        if has_legend:
            legend_x = int(chart_rect.right()) + 22
            legend_y = int(rect.top()) + 18
            for index, item in enumerate(self.series[:5]):
                y = legend_y + (index * 26)
                painter.setBrush(QColor(item["color"]))
                painter.setPen(Qt.NoPen)
                painter.drawEllipse(QRectF(legend_x, y, 10, 10))
                painter.setPen(QColor(self.palette().text().color()))
                painter.setFont(_font("small"))
                painter.drawText(QRectF(legend_x + 18, y - 2, rect.right() - legend_x - 20, 18), Qt.AlignLeft, item["label"])


class BarChart(QWidget):
    def __init__(self):
        super().__init__()
        self.items = []
        self.mode = "horizontal"
        self.chart_progress = 1.0
        self.setMinimumHeight(180)

    def set_items(self, items, mode="horizontal"):
        self.items = items
        self.mode = mode
        _animate_chart(self)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), Qt.transparent)

        if not self.items:
            painter.setPen(QColor("#777777"))
            painter.drawText(self.rect(), Qt.AlignCenter, "Sem dados")
            return

        values = [item["value"] for item in self.items]
        maximum = max(values) if values else 0
        if maximum <= 0:
            painter.setPen(QColor("#777777"))
            painter.drawText(self.rect(), Qt.AlignCenter, "Sem dados")
            return

        if self.mode == "vertical":
            self._draw_vertical(painter, maximum)
            return
        self._draw_horizontal(painter, maximum)

    def _draw_horizontal(self, painter, maximum):
        rect = self.rect().adjusted(18, 18, -18, -18)
        row_height = 32
        bar_left = rect.left() + 70
        bar_width = rect.width() - 90

        for index, item in enumerate(self.items):
            y = rect.top() + (index * row_height)
            painter.setPen(QColor(self.palette().text().color()))
            painter.setFont(_font("small"))
            painter.drawText(rect.left(), y + 18, item["label"])
            painter.setPen(QPen(QColor(item["track"]), 16, Qt.SolidLine, Qt.RoundCap))
            painter.drawLine(QPointF(bar_left, y + 13), QPointF(bar_left + bar_width, y + 13))
            fill_width = 0 if maximum == 0 else (item["value"] / maximum) * bar_width * self.chart_progress
            painter.setPen(QPen(QColor(item["color"]), 16, Qt.SolidLine, Qt.RoundCap))
            painter.drawLine(QPointF(bar_left, y + 13), QPointF(bar_left + fill_width, y + 13))
            painter.setPen(QColor(self.palette().text().color()))
            painter.drawText(rect.right() - 24, y + 18, str(item["value"]))

    def _draw_vertical(self, painter, maximum):
        rect = self.rect().adjusted(24, 18, -24, -28)
        baseline = rect.bottom()
        count = max(len(self.items), 1)
        slot = rect.width() / count
        width = min(40, slot * 0.56)

        for index, item in enumerate(self.items):
            center_x = rect.left() + (slot * index) + (slot / 2)
            height = 0 if maximum == 0 else (item["value"] / maximum) * (rect.height() - 30) * self.chart_progress
            bar = QRectF(center_x - (width / 2), baseline - height, width, height)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(item["color"]))
            painter.drawRoundedRect(bar, 8, 8)
            painter.setPen(QColor(self.palette().text().color()))
            painter.setFont(_font("small"))
            painter.drawText(QRectF(center_x - 32, baseline - height - 22, 64, 18), Qt.AlignCenter, str(item["value"]))
            painter.drawText(QRectF(center_x - 40, baseline + 8, 80, 18), Qt.AlignCenter, item["label"])


class TrafficChart(QWidget):
    def __init__(self):
        super().__init__()
        self.series = []
        self.labels = []
        self.chart_progress = 1.0
        self.setMinimumHeight(175)

    def set_data(self, series, labels):
        self.series = series
        self.labels = labels
        _animate_chart(self)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), Qt.transparent)

        if not self.series or not any(item["values"] for item in self.series):
            painter.setPen(QColor("#777777"))
            painter.drawText(self.rect(), Qt.AlignCenter, "Sem dados de trafego")
            return

        rect = self.rect().adjusted(44, 20, -18, -34)
        max_value = max((max(item["values"]) if item["values"] else 0) for item in self.series)
        max_value = max(max_value, 1)

        painter.setPen(QPen(QColor(self.palette().mid().color()), 1))
        for step in range(5):
            y = rect.bottom() - (rect.height() * step / 4)
            painter.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))
            painter.setPen(QColor(self.palette().text().color()))
            painter.setFont(_font("small"))
            painter.drawText(QRectF(0, y - 10, rect.left() - 8, 20), Qt.AlignRight | Qt.AlignVCenter, str(int(max_value * step / 4)))
            painter.setPen(QPen(QColor(self.palette().mid().color()), 1))

        count = max((len(item["values"]) for item in self.series), default=0)
        if count < 2:
            return

        for index, item in enumerate(self.series):
            values = item["values"]
            if len(values) < 2:
                continue
            painter.setPen(QPen(QColor(item["color"]), 2.2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            points = []
            for point_index, value in enumerate(values):
                x = rect.left() + (rect.width() * point_index / (count - 1))
                y = rect.bottom() - ((value / max_value) * rect.height() * self.chart_progress)
                points.append(QPointF(x, y))
            for point_index in range(len(points) - 1):
                painter.drawLine(points[point_index], points[point_index + 1])

        painter.setPen(QColor(self.palette().text().color()))
        painter.setFont(_font("small"))
        label_step = max(1, count // 6)
        for index in range(0, count, label_step):
            if index >= len(self.labels):
                continue
            x = rect.left() + (rect.width() * index / (count - 1))
            painter.drawText(QRectF(x - 26, rect.bottom() + 8, 52, 18), Qt.AlignCenter, self.labels[index])

        legend_x = rect.left()
        legend_y = 0
        for index, item in enumerate(self.series):
            x = legend_x + (index * 108)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(item["color"]))
            painter.drawEllipse(QRectF(x, legend_y, 10, 10))
            painter.setPen(QColor(self.palette().text().color()))
            painter.drawText(QRectF(x + 16, legend_y - 4, 84, 18), Qt.AlignLeft | Qt.AlignVCenter, item["label"])


class SIPLadderWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.flow = None
        self.arrow_phase = 0.0
        self.arrow_animation = QVariantAnimation(self)
        self.arrow_animation.setStartValue(0.0)
        self.arrow_animation.setEndValue(1.0)
        self.arrow_animation.setDuration(1800)
        self.arrow_animation.setLoopCount(-1)
        self.arrow_animation.setEasingCurve(QEasingCurve.Linear)
        self.arrow_animation.valueChanged.connect(self._set_arrow_phase)
        self.setMinimumHeight(320)

    def set_flow(self, flow):
        self.flow = flow
        message_count = len(flow.messages) if flow is not None else 0
        self.setMinimumHeight(max(320, 130 + (message_count * 44)))
        if flow is None:
            self.arrow_animation.stop()
        elif self.arrow_animation.state() != QAbstractAnimation.Running:
            self.arrow_animation.start()
        self.update()

    def _set_arrow_phase(self, value):
        self.arrow_phase = float(value)
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), Qt.transparent)

        if self.flow is None:
            painter.setPen(QColor("#777777"))
            painter.drawText(self.rect(), Qt.AlignCenter, "Sem mensagens SIP")
            return

        palette = THEMES["dark"] if self.palette().window().color().lightness() < 128 else THEMES["light"]
        rect = self.rect().adjusted(24, 24, -24, -24)
        left_x = rect.left() + 120
        right_x = rect.right() - 120
        top_y = rect.top() + 34
        bottom_y = rect.bottom() - 10

        painter.setPen(QColor(palette["text"]))
        painter.setFont(QFont("Segoe UI", 11, QFont.DemiBold))
        painter.drawText(QRectF(left_x - 110, rect.top(), 220, 24), Qt.AlignCenter, f"{self.flow.source_ip}:{self.flow.messages[0].source_port if self.flow.messages else 0}")
        painter.drawText(QRectF(right_x - 110, rect.top(), 220, 24), Qt.AlignCenter, f"{self.flow.destination_ip}:{self.flow.messages[0].destination_port if self.flow.messages else 0}")

        painter.setPen(QPen(QColor(palette["border"]), 2, Qt.DashLine))
        painter.drawLine(QPointF(left_x, top_y), QPointF(left_x, bottom_y))
        painter.drawLine(QPointF(right_x, top_y), QPointF(right_x, bottom_y))

        for index, message in enumerate(self.flow.messages):
            y = top_y + 28 + (index * 44)
            is_request = message.is_request
            start_x = left_x if is_request else right_x
            end_x = right_x if is_request else left_x
            arrow_color = self._message_color(message)
            label = message.method if is_request else f"{message.status_code} {message.reason_phrase or ''}".strip()
            time_text = f"{message.packet_time:.3f}"

            painter.setPen(QPen(QColor(arrow_color), 2.6, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            painter.drawLine(QPointF(start_x, y), QPointF(end_x, y))
            if end_x > start_x:
                painter.drawLine(QPointF(end_x - 10, y - 6), QPointF(end_x, y))
                painter.drawLine(QPointF(end_x - 10, y + 6), QPointF(end_x, y))
            else:
                painter.drawLine(QPointF(end_x + 10, y - 6), QPointF(end_x, y))
                painter.drawLine(QPointF(end_x + 10, y + 6), QPointF(end_x, y))

            pulse_phase = (self.arrow_phase + (index * 0.16)) % 1.0
            pulse_x = start_x + ((end_x - start_x) * pulse_phase)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(arrow_color).lighter(130))
            painter.drawEllipse(QRectF(pulse_x - 4, y - 4, 8, 8))

            mid_x = (start_x + end_x) / 2
            label_rect = QRectF(mid_x - 110, y - 18, 220, 20)
            time_rect = QRectF(mid_x - 70, y + 4, 140, 16)
            painter.setPen(QColor(palette["text"]))
            painter.setFont(_font("small"))
            painter.drawText(label_rect, Qt.AlignCenter, label)
            painter.setPen(QColor(palette["muted"]))
            painter.drawText(time_rect, Qt.AlignCenter, time_text)

    def _message_color(self, message):
        if message.is_request:
            return "#3B82F6"
        if 100 <= message.status_code < 200:
            return "#F5A524"
        if 200 <= message.status_code < 300:
            return "#22A06B"
        return "#E5484D"


class SipperWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIPPER")
        self.setWindowIcon(QIcon(str(LOGO_ICON_PATH)))
        self.resize(1600, 1000)
        self.setMinimumSize(1180, 720)
        self.current_theme = "dark"
        self.analysis_settings = load_settings()
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
        self.page_buttons = {}
        self.rtp_nav_buttons = {}
        self.sip_nav_buttons = {}
        self.network_nav_buttons = {}
        self.page_widgets = {}
        self.page_cards = {}
        self.active_animations = []
        self._build_ui()
        self._apply_theme()
        self._render_all()

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
        sidebar_layout.setContentsMargins(22, 20, 22, 20)
        sidebar_layout.setSpacing(14)

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
            ("Resumo", [("Resumo", "Resumo", None, None)]),
            (
                "SIP",
                [
                    ("SIP Flows", "SIP", "sip", "all"),
                    ("SIP Errors", "SIP", "sip", "errors"),
                    ("Call Analysis", "SIP", "sip", "analysis"),
                ],
            ),
            (
                "RTP",
                [
                    ("RTP Flows", "RTP", "rtp", "all"),
                    ("Jitter", "RTP", "rtp", "jitter"),
                    ("Packet Loss", "RTP", "rtp", "loss"),
                    ("Out-of-Order", "RTP", "rtp", "out_of_order"),
                    ("Codecs", "RTP", "rtp", "codecs"),
                ],
            ),
            (
                "Rede",
                [
                    ("TCP Flows", "Rede", "network", "tcp"),
                    ("UDP Flows", "Rede", "network", "udp"),
                    ("ICMP Flows", "Rede", "network", "icmp"),
                    ("Findings", "Findings", None, None),
                ],
            ),
            ("Sistema", [("Estatisticas", "Estatisticas", None, None), ("Configuracoes", "Configuracoes", None, None), ("Sobre", "Sobre", None, None)]),
        )
        self.nav_scroll = QScrollArea()
        self.nav_scroll.setWidgetResizable(True)
        self.nav_scroll.setFrameShape(QFrame.NoFrame)
        self.nav_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        nav_content = QWidget()
        nav_layout = QVBoxLayout(nav_content)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(8)
        self.nav_scroll.setWidget(nav_content)

        for title, pages in nav_sections:
            label = QLabel(title)
            label.setFont(_font("subtitle"))
            nav_layout.addWidget(label)
            for label_text, page, filter_group, filter_name in pages:
                button = QPushButton(label_text)
                button.setIcon(self._page_icon(page))
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
                else:
                    button.clicked.connect(
                        lambda _checked=False, name=filter_name: self._set_network_filter(name)
                    )
                    self.network_nav_buttons[filter_name] = button
                button.setMinimumHeight(40)
                button.setIconSize(QSize(18, 18))
                button.setCursor(Qt.PointingHandCursor)
                nav_layout.addWidget(button)
        nav_layout.addStretch(1)
        sidebar_layout.addWidget(self.nav_scroll, 1)
        self.sidebar_status = QLabel("Pronto")
        self.sidebar_status.setFont(_font("small"))
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
        self.file_input.setPlaceholderText("Selecione um arquivo .pcap ou .pcapng")
        self.file_input.setMinimumWidth(220)
        toolbar_layout.addWidget(self.file_input, 1)
        self.open_button = QPushButton("Abrir PCAP")
        self.open_button.setObjectName("secondaryButton")
        self.open_button.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
        self.open_button.clicked.connect(self._choose_file)
        self.analyze_button = QPushButton("Analisar")
        self.analyze_button.setObjectName("primaryButton")
        self.analyze_button.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        self.analyze_button.clicked.connect(self._analyze_file)
        self.export_button = QPushButton("Exportar")
        self.export_button.setObjectName("secondaryButton")
        self.export_button.setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export_report)
        self.cancel_button = QPushButton("Cancelar")
        self.cancel_button.setObjectName("secondaryButton")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel_analysis)
        self.analysis_progress = QProgressBar()
        self.analysis_progress.setRange(0, 1)
        self.analysis_progress.setValue(0)
        self.analysis_progress.setTextVisible(False)
        self.analysis_progress.setFixedWidth(100)
        self.analysis_progress.setVisible(False)
        self.page_badge = QLabel("Resumo")
        self.page_badge.setObjectName("pageBadge")
        toolbar_layout.addWidget(self.open_button)
        toolbar_layout.addWidget(self.analyze_button)
        toolbar_layout.addWidget(self.cancel_button)
        toolbar_layout.addWidget(self.export_button)
        toolbar_layout.addWidget(self.analysis_progress)
        toolbar_layout.addStretch(1)
        toolbar_layout.addWidget(self.page_badge)

        self.pages = QStackedWidget()
        self._build_pages()

        self.status_bar_label = QLabel("Pronto")
        self.status_bar_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.status_bar_label.setFont(_font("body"))

        content_layout.addWidget(self.toolbar)
        content_layout.addWidget(self.pages, 1)
        content_layout.addWidget(self.status_bar_label)

        root_layout.addWidget(self.sidebar)
        root_layout.addWidget(self.content, 1)

    def _build_pages(self):
        self._build_summary_page()
        self._build_sip_page()
        self._build_rtp_page()
        self._build_network_page()
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
        _page, layout = self._new_grid_page("Resumo", [4, 4, 3], [0, 1, 1, 1])
        self.summary_metrics = PanelCard("Pacotes Analisados")
        self.summary_protocols = PanelCard("Protocolos")
        self.summary_findings = PanelCard("Findings")
        self.summary_calls = PanelCard("Chamadas SIP Detectadas")
        self.summary_rtp_streams = PanelCard("RTP Flows (Resumo)")
        self.summary_call_detail = PanelCard("Detalhes da Chamada")
        self.summary_recent_findings = PanelCard("Findings Recentes")
        self.summary_traffic = PanelCard("Grafico de Trafego")

        self.summary_kpi_row = QWidget()
        self.summary_kpi_layout = QHBoxLayout(self.summary_kpi_row)
        self.summary_kpi_layout.setContentsMargins(0, 0, 0, 0)
        self.summary_kpi_layout.setSpacing(10)
        self.kpi_packets = KPIStat("Pacotes")
        self.kpi_protocols = KPIStat("Protocolos")
        self.kpi_calls = KPIStat("Chamadas")
        self.kpi_findings = KPIStat("Findings")
        for widget in (self.kpi_packets, self.kpi_protocols, self.kpi_calls, self.kpi_findings):
            self.summary_kpi_layout.addWidget(widget)
        self.summary_protocol_chart = DonutChart()
        self.summary_findings_chart = BarChart()
        self.summary_calls_table = self._make_calls_table()
        self.summary_rtp_table = self._make_rtp_table()
        self.summary_flow = CallFlowWidget()
        self.summary_sip_flow_button = QPushButton("Abrir SIP Flow")
        self.summary_sip_flow_button.setObjectName("secondaryButton")
        self.summary_sip_flow_button.clicked.connect(self._open_sip_flow_dialog)
        self.summary_detail_text = self._make_text()
        self.summary_findings_table = self._make_findings_table()
        self.summary_traffic_chart = TrafficChart()

        self.summary_metrics.add_widget(self.summary_kpi_row)
        self.summary_protocols.add_widget(self.summary_protocol_chart)
        self.summary_findings.add_widget(self.summary_findings_chart)
        self.summary_calls.add_widget(self.summary_calls_table)
        self.summary_rtp_streams.add_widget(self.summary_rtp_table)
        self.summary_call_detail.add_widget(self.summary_flow)
        self.summary_call_detail.add_widget(self.summary_sip_flow_button)
        self.summary_call_detail.add_widget(self.summary_detail_text)
        self.summary_recent_findings.add_widget(self.summary_findings_table)
        self.summary_traffic.add_widget(self.summary_traffic_chart)

        layout.addWidget(self.summary_metrics, 0, 0)
        layout.addWidget(self.summary_protocols, 0, 1)
        layout.addWidget(self.summary_findings, 0, 2)
        layout.addWidget(self.summary_calls, 1, 0)
        layout.addWidget(self.summary_rtp_streams, 1, 1)
        layout.addWidget(self.summary_call_detail, 1, 2, 3, 1)
        layout.addWidget(self.summary_recent_findings, 2, 0, 1, 2)
        layout.addWidget(self.summary_traffic, 3, 0, 1, 2)
        self._register_page_cards(
            "Resumo",
            self.summary_metrics,
            self.summary_protocols,
            self.summary_findings,
            self.summary_calls,
            self.summary_rtp_streams,
            self.summary_call_detail,
            self.summary_recent_findings,
            self.summary_traffic,
        )

    def _build_sip_page(self):
        _page, layout = self._new_grid_page("SIP", [5, 4], [0, 1])
        self.sip_state = PanelCard("Estado de Sinalizacao")
        self.sip_findings = PanelCard("Erros SIP")
        self.sip_calls = PanelCard("Fluxos SIP")
        self.sip_detail = PanelCard("Detalhe da Chamada")
        self.sip_state_text = self._make_text()
        self.sip_findings_text = self._make_text()
        self.sip_calls_table = self._make_calls_table()
        self.sip_filter = QComboBox()
        self.sip_filter.addItem("Todos os fluxos", "all")
        self.sip_filter.addItem("Com erro de sinalizacao", "errors")
        self.sip_filter.addItem("Analise de chamadas", "analysis")
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
        _page, layout = self._new_grid_page("RTP", [5, 4], [0, 1])
        self.rtp_streams = PanelCard("RTP Streams")
        self.rtp_health = PanelCard("Saude de Midia")
        self.rtp_calls = PanelCard("Chamadas com Midia")
        self.rtp_detail = PanelCard("Detalhe RTP")
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
        self.rtp_health_text = self._make_text()
        self.rtp_calls_table = self._make_calls_table()
        self.rtp_flow = CallFlowWidget()
        self.rtp_detail_text = self._make_text()
        self.rtp_streams.add_widget(self.rtp_filter)
        self.rtp_streams.add_widget(self.rtp_search)
        self.rtp_streams.add_widget(self.rtp_streams_table)
        self.rtp_health.add_widget(self.rtp_health_text)
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
        self.network_protocols = PanelCard("Protocolos de Rede")
        self.network_health = PanelCard("Saude da Rede")
        self.network_events = PanelCard("Eventos TCP UDP ICMP")
        self.network_detail = PanelCard("Detalhe do Evento")
        self.network_protocols_text = self._make_text()
        self.network_health_text = self._make_text()
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
        self.network_events.add_widget(self.network_filter)
        self.network_events.add_widget(self.network_search)
        self.network_events.add_widget(self.network_events_table)
        self.network_detail.add_widget(self.network_detail_text)
        layout.addWidget(self.network_protocols, 0, 0)
        layout.addWidget(self.network_health, 0, 1)
        layout.addWidget(self.network_events, 1, 0)
        layout.addWidget(self.network_detail, 1, 1)
        self._register_page_cards("Rede", self.network_protocols, self.network_health, self.network_events, self.network_detail)

    def _build_findings_page(self):
        _page, layout = self._new_grid_page("Findings", [6, 4], [0, 1])
        self.findings_summary = PanelCard("Resumo de Findings")
        self.findings_recommendation = PanelCard("Recomendacao")
        self.findings_table_card = PanelCard("Todos os Findings")
        self.findings_detail = PanelCard("Detalhe do Finding")
        self.findings_summary_text = self._make_text()
        self.findings_recommendation_text = self._make_text()
        self.findings_table = self._make_findings_table()
        self.findings_filter = QComboBox()
        self.findings_filter.addItem("Todas as severidades", "all")
        self.findings_filter.addItem("High", "high")
        self.findings_filter.addItem("Medium", "medium")
        self.findings_filter.addItem("Low", "low")
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
        self.stats_protocols_text = self._make_text()
        self.stats_protocol_chart = DonutChart()
        self.stats_calls_text = self._make_text()
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

        self.settings_traffic_points = QSpinBox()
        self.settings_traffic_points.setRange(60, 5000)
        self.settings_traffic_points.setSuffix(" pontos")

        self.settings_max_pcap_size = QSpinBox()
        self.settings_max_pcap_size.setRange(1, 10240)
        self.settings_max_pcap_size.setSuffix(" MB")

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
            ("Perda RTP para severidade alta", self.settings_loss),
            ("Maximo de pontos no grafico", self.settings_traffic_points),
            ("Tamanho maximo do PCAP", self.settings_max_pcap_size),
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
        card.add_widget(self.about_logo)
        card.add_widget(self.about_text)
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
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((240, 130, 130, 110, 90, 100)):
            table.setColumnWidth(column, width)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        table.verticalHeader().setDefaultSectionSize(28)
        table.itemSelectionChanged.connect(self._on_call_selected)
        return table

    def _make_findings_table(self):
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["Severidade", "Tipo", "Origem", "Destino"])
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.setCornerButtonEnabled(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((100, 250, 150, 150)):
            table.setColumnWidth(column, width)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        table.verticalHeader().setDefaultSectionSize(28)
        table.itemSelectionChanged.connect(self._on_finding_selected)
        return table

    def _make_rtp_table(self):
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(
            ["Origem", "Destino", "SSRC", "Pacotes", "Loss", "Jitter (ms)"]
        )
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setShowGrid(False)
        table.setAlternatingRowColors(True)
        table.setWordWrap(False)
        table.setCornerButtonEnabled(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((180, 180, 120, 95, 125, 110)):
            table.setColumnWidth(column, width)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        table.verticalHeader().setDefaultSectionSize(28)
        return table

    def _choose_file(self):
        file_path, _selected = QFileDialog.getOpenFileName(
            self,
            "Selecione um arquivo PCAP",
            "",
            "PCAP Files (*.pcap *.pcapng);;Todos os arquivos (*)",
        )
        if file_path:
            self.file_input.setText(file_path)
            self._set_status("Arquivo carregado")

    def _analyze_file(self):
        file_path = self.file_input.text().strip()
        if not file_path:
            self._set_status("Selecione um arquivo PCAP")
            return

        if self.analysis_thread is not None:
            return

        self._set_analysis_running(True)
        self._set_status("Iniciando analise")
        self.analysis_thread = QThread(self)
        self.analysis_worker = AnalysisWorker(file_path, self.analysis_settings)
        self.analysis_worker.moveToThread(self.analysis_thread)
        self.analysis_thread.started.connect(self.analysis_worker.run)
        self.analysis_worker.progress_changed.connect(self._set_status)
        self.analysis_worker.completed.connect(self._on_analysis_completed)
        self.analysis_worker.failed.connect(self._on_analysis_failed)
        self.analysis_worker.completed.connect(self.analysis_thread.quit)
        self.analysis_worker.failed.connect(self.analysis_thread.quit)
        self.analysis_thread.finished.connect(self.analysis_worker.deleteLater)
        self.analysis_thread.finished.connect(self._cleanup_analysis_worker)
        self.analysis_thread.start()

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
        self.call_index = {call["call_id"]: call for call in self.last_viewmodel["calls"]}
        self.finding_index = {
            self._finding_key(finding, index): finding
            for index, finding in enumerate(self.last_viewmodel["findings"])
        }
        self.selected_call_id = self.last_viewmodel["calls"][0]["call_id"] if self.last_viewmodel["calls"] else None
        self.selected_finding_key = (
            self._finding_key(self.last_viewmodel["findings"][0], 0) if self.last_viewmodel["findings"] else None
        )
        self._render_all()
        self.export_button.setEnabled(True)
        self._set_analysis_running(False)
        self._set_status("Analise concluida com sucesso")

    def _on_analysis_failed(self, error):
        self._set_analysis_running(False)
        if error == "Analise cancelada pelo usuario":
            self._set_status(error)
            return
        self._set_status(f"Falha na analise: {error}")

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

    def closeEvent(self, event):
        if self.analysis_thread is not None:
            self._cancel_analysis()
            self._set_status("Cancelando analise antes de fechar")
            event.ignore()
            return
        super().closeEvent(event)

    def _set_analysis_running(self, is_running):
        self.open_button.setEnabled(not is_running)
        self.analyze_button.setEnabled(not is_running)
        self.cancel_button.setEnabled(is_running)
        self.export_button.setEnabled(not is_running and self.last_viewmodel is not None)
        self.file_input.setReadOnly(is_running)
        self.analysis_progress.setVisible(is_running)
        if is_running:
            self.analysis_progress.setRange(0, 0)
        else:
            self.analysis_progress.setRange(0, 1)
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

    def _refresh_nav_state(self, current):
        for name, button in self.page_buttons.items():
            button.setProperty("active", name == current)
            button.style().unpolish(button)
            button.style().polish(button)

        self._refresh_filter_nav_buttons("RTP", self.rtp_nav_buttons, self.rtp_filter, current)
        self._refresh_filter_nav_buttons("SIP", self.sip_nav_buttons, self.sip_filter, current)
        self._refresh_filter_nav_buttons("Rede", self.network_nav_buttons, self.network_filter, current)

    def _refresh_filter_nav_buttons(self, page, buttons, combo_box, current_page):
        current_filter = combo_box.currentData()
        for filter_name, button in buttons.items():
            button.setProperty("active", current_page == page and filter_name == current_filter)
            button.style().unpolish(button)
            button.style().polish(button)

    def _on_theme_radio_changed(self):
        self.current_theme = "dark" if self.dark_radio.isChecked() else "light"
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
        stylesheet = f"""
            QWidget {{
                background: {palette["bg"]};
                color: {palette["text"]};
                font-family: 'Segoe UI';
                font-size: 10pt;
            }}
            QFrame#sidebar {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {palette["panel_alt"]}, stop:1 {palette["panel"]});
                border: 1px solid {palette["border"]};
                border-radius: 22px;
            }}
            QScrollArea {{
                background: transparent;
                border: none;
            }}
            QScrollArea > QWidget > QWidget {{
                background: transparent;
            }}
            QFrame#kpiStat {{
                background: {palette["surface"]};
                border: 1px solid {palette["border"]};
                border-radius: 16px;
            }}
            QFrame {{
                border: none;
            }}
            QFrame#panelCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {palette["panel"]}, stop:0.65 {palette["surface"]}, stop:1 {palette["panel"]});
                border: 1px solid {palette["border"]};
                border-radius: 20px;
            }}
            QLabel#panelTitle {{
                color: {palette["text"]};
                padding: 16px 18px 4px 18px;
                font-size: 11pt;
            }}
            QLabel#kpiValue {{
                color: {palette["text"]};
            }}
            QLabel#kpiLabel {{
                color: {palette["muted"]};
                letter-spacing: 0.5px;
            }}
            QPushButton {{
                background: {palette["panel_alt"]};
                color: {palette["text"]};
                border: 1px solid transparent;
                border-radius: 14px;
                padding: 12px 14px;
                text-align: left;
            }}
            QPushButton:hover {{
                border: 1px solid {palette["accent"]};
                background: {palette["selection"]};
            }}
            QPushButton[active="true"] {{
                background: {palette["selection"]};
                border: 1px solid {palette["accent"]};
            }}
            QPushButton#primaryButton {{
                background: {palette["accent"]};
                border: 1px solid {palette["accent"]};
                padding: 12px 18px;
            }}
            QPushButton#primaryButton:hover {{
                background: {palette["accent_alt"]};
                border: 1px solid {palette["accent_alt"]};
            }}
            QPushButton#secondaryButton {{
                background: {palette["panel_alt"]};
                border: 1px solid {palette["border"]};
                padding: 12px 18px;
            }}
            QFrame#themeToggle {{
                background: {palette["surface"]};
                border: 1px solid {palette["border"]};
                border-radius: 14px;
            }}
            QRadioButton {{
                background: transparent;
                border: none;
                spacing: 6px;
                padding: 6px 8px;
            }}
            QRadioButton::indicator {{
                width: 14px;
                height: 14px;
                border-radius: 7px;
                border: 1px solid {palette["border"]};
                background: {palette["panel_alt"]};
            }}
            QRadioButton::indicator:checked {{
                background: {palette["accent"]};
                border: 1px solid {palette["accent"]};
            }}
            QLineEdit, QTextEdit, QTableWidget, QComboBox, QSpinBox, QDoubleSpinBox {{
                background: {palette["surface"]};
                border: 1px solid {palette["border"]};
                border-radius: 12px;
                padding: 8px;
            }}
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
                padding: 12px 14px;
            }}
            QComboBox::drop-down {{
                border: none;
                width: 28px;
            }}
            QComboBox QAbstractItemView {{
                background: {palette["panel_alt"]};
                border: 1px solid {palette["border"]};
                selection-background-color: {palette["selection"]};
            }}
            QTextEdit {{
                padding: 10px 12px;
            }}
            QHeaderView::section {{
                background: {palette["panel_alt"]};
                color: {palette["text"]};
                border: none;
                padding: 10px 8px;
            }}
            QTableWidget {{
                gridline-color: transparent;
                alternate-background-color: {palette["panel"]};
                selection-background-color: {palette["selection"]};
            }}
            QTableWidget::item:selected {{
                background: {palette["selection"]};
            }}
            QScrollBar:vertical {{
                background: {palette["surface"]};
                width: 10px;
                margin: 4px 2px 4px 0;
                border-radius: 5px;
            }}
            QScrollBar::handle:vertical {{
                background: {palette["muted"]};
                min-height: 36px;
                border-radius: 5px;
                margin: 1px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {palette["accent"]};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: transparent;
            }}
            QScrollBar:horizontal {{
                background: {palette["surface"]};
                height: 10px;
                margin: 0 4px 2px 4px;
                border-radius: 5px;
            }}
            QScrollBar::handle:horizontal {{
                background: {palette["muted"]};
                min-width: 36px;
                border-radius: 5px;
                margin: 1px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background: {palette["accent"]};
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0;
            }}
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
                background: transparent;
            }}
            QProgressBar {{
                background: {palette["surface"]};
                border: 1px solid {palette["border"]};
                border-radius: 5px;
            }}
            QProgressBar::chunk {{
                background: {palette["accent"]};
                border-radius: 4px;
            }}
            QLabel {{
                background: transparent;
            }}
        """
        self.setStyleSheet(stylesheet)
        self._update_brand_splash()
        self.page_badge.setStyleSheet(
            f"background: {palette['selection']}; color: {palette['text']}; border: 1px solid {palette['accent']}; border-radius: 12px; padding: 8px 12px;"
        )
        self.status_bar_label.setStyleSheet(f"color: {palette['success']};")
        self.sidebar_status.setStyleSheet(f"color: {palette['muted']};")

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
        self._render_sip_page()
        self._render_rtp_page()
        self._render_network_page()
        self._render_findings_page()
        self._render_statistics_page()
        self._render_settings_page()
        self._render_about_page()

    def _render_summary_page(self):
        if self.last_viewmodel is None:
            self.summary_detail_text.setPlainText("Selecione ou carregue uma chamada para ver detalhes.")
            for widget in (self.kpi_packets, self.kpi_protocols, self.kpi_calls, self.kpi_findings):
                widget.set_value(0)
            self._fill_calls_table(self.summary_calls_table, [])
            self._fill_rtp_table(self.summary_rtp_table, [])
            self._fill_findings_table(self.summary_findings_table, [])
            self.summary_protocol_chart.set_series([])
            self.summary_findings_chart.set_items([])
            self.summary_traffic_chart.set_data([], [])
            self.summary_flow.set_call(None)
            self.summary_sip_flow_button.setEnabled(False)
            return

        viewmodel = self.last_viewmodel
        protocols = viewmodel["protocols"]
        self.kpi_packets.set_value(viewmodel["overview"]["packet_count"])
        self.kpi_protocols.set_value(viewmodel["overview"]["protocol_count"])
        self.kpi_calls.set_value(viewmodel["overview"]["call_count"])
        self.kpi_findings.set_value(viewmodel["overview"]["finding_count"])
        self._fill_calls_table(self.summary_calls_table, viewmodel["calls"])
        self._fill_rtp_table(
            self.summary_rtp_table,
            viewmodel["rtp_streams"],
        )
        self._fill_findings_table(self.summary_findings_table, viewmodel["findings"])
        self.summary_traffic_chart.set_data(self.last_traffic_series, self.last_traffic_labels)
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
                    "label": "High",
                    "value": viewmodel["severity_counts"]["high"],
                    "color": palette["danger"],
                    "track": palette["surface"],
                },
                {
                    "label": "Medium",
                    "value": viewmodel["severity_counts"]["medium"],
                    "color": palette["warning"],
                    "track": palette["surface"],
                },
                {
                    "label": "Low",
                    "value": viewmodel["severity_counts"]["low"],
                    "color": palette["info"],
                    "track": palette["surface"],
                },
            ]
        )

    def _render_sip_page(self):
        if self.last_viewmodel is None:
            self.sip_state_text.setPlainText("Abra um PCAP para analisar sinalizacao SIP.")
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
            [finding for finding in self.last_viewmodel["findings"] if finding["type"].startswith("sip_")],
            filter_name,
        )
        established = sum(1 for call in calls if call["signaling_state"] == "established")
        degraded = sum(1 for call in calls if call["severity"] in {"high", "medium"})
        self.sip_calls.set_title(self._sip_filter_title(filter_name))
        self.sip_state_text.setPlainText(
            "\n".join(
                [
                    f"Fluxos SIP correlacionados: {len(calls)}",
                    f"Chamadas estabelecidas: {established}",
                    f"Chamadas com risco: {degraded}",
                ]
            )
        )
        self.sip_findings_text.setPlainText("\n".join(self._finding_lines(sip_findings, 12)) or "Nenhum finding SIP detectado.")
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
        return calls

    def _filter_sip_findings(self, findings, filter_name):
        if filter_name == "errors":
            return [finding for finding in findings if finding["type"] != "sip_call_established"]
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
            "all": "SIP Flows",
            "errors": "SIP Errors",
            "analysis": "Call Analysis",
        }
        return titles.get(filter_name, "SIP Flows")

    def _render_rtp_page(self):
        if self.last_viewmodel is None:
            self.rtp_health_text.setPlainText("Nenhum finding RTP carregado.")
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
            [finding for finding in self.last_viewmodel["findings"] if finding["type"].startswith("rtp_")],
            filter_name,
        )
        self.rtp_streams.set_title(self._rtp_filter_title(filter_name))
        self._fill_rtp_table(self.rtp_streams_table, streams)
        self.rtp_health_text.setPlainText("\n".join(self._finding_lines(rtp_findings, 12)) or "Nenhum finding RTP detectado.")
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
        finding_type = {
            "jitter": "rtp_high_jitter",
            "loss": "rtp_packet_loss",
            "out_of_order": "rtp_out_of_order",
        }.get(filter_name)

        if finding_type is None:
            return findings

        return [finding for finding in findings if finding["type"] == finding_type]

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
            "all": "RTP Flows",
            "jitter": "RTP - Jitter",
            "loss": "RTP - Packet Loss",
            "out_of_order": "RTP - Out-of-Order",
            "codecs": "RTP - Codecs",
        }
        return titles.get(filter_name, "RTP Flows")

    def _render_network_page(self):
        if self.last_viewmodel is None:
            self.network_protocols_text.setPlainText("Abra um PCAP para analisar rede.")
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
        self.network_protocols_text.setPlainText(
            "\n".join([f"{item['name']}: {item['count']} ({item['share']:.1%})" for item in protocols])
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
            "all": "Eventos TCP UDP ICMP",
            "tcp": "TCP Flows",
            "udp": "UDP Flows",
            "icmp": "ICMP Flows",
        }
        return titles.get(filter_name, "Eventos TCP UDP ICMP")

    def _render_findings_page(self):
        if self.last_viewmodel is None:
            self.findings_summary_text.setPlainText("Abra um PCAP para ver os findings.")
            self.findings_recommendation_text.setPlainText("Nenhuma recomendacao carregada.")
            self.findings_detail_text.setPlainText("Sem finding selecionado.")
            self._fill_findings_table(self.findings_table, [])
            return

        filter_name = self.findings_filter.currentData()
        findings = self._filter_findings_by_severity(self.last_viewmodel["findings"], filter_name)
        findings = self._filter_findings_by_search(findings, self.findings_search.text())
        self.findings_table_card.set_title(self._findings_filter_title(filter_name))
        top = findings[0] if findings else None
        self.findings_summary_text.setPlainText(
            "\n".join(
                [
                    f"Total: {len(findings)}",
                    f"High: {self.last_viewmodel['severity_counts']['high']}",
                    f"Medium: {self.last_viewmodel['severity_counts']['medium']}",
                    f"Low: {self.last_viewmodel['severity_counts']['low']}",
                ]
            )
        )
        self.findings_recommendation_text.setPlainText(
            top["recommendation"] if top else "Nenhuma recomendacao disponivel."
        )
        self._fill_findings_table(self.findings_table, findings)
        self._render_finding_text(self.findings_detail_text, self._selected_finding(findings))

    def _filter_findings_by_severity(self, findings, filter_name):
        if filter_name in {"high", "medium", "low"}:
            return [finding for finding in findings if finding["severity"] == filter_name]
        return findings

    def _filter_findings_by_search(self, findings, query):
        query = query.strip().lower()
        if not query:
            return findings
        return [
            finding
            for finding in findings
            if query in finding["type"].lower()
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
            self.stats_protocols_text.setPlainText("Abra um PCAP para gerar estatisticas.")
            self.stats_calls_text.setPlainText("Nenhuma chamada carregada.")
            self.stats_traffic_chart.set_data([], [])
            self.stats_protocol_chart.set_series([])
            self.stats_calls_chart.set_items([], "vertical")
            return

        protocols = self.last_viewmodel["protocols"]
        calls = self.last_viewmodel["calls"]
        self.stats_traffic_chart.set_data(self.last_traffic_series, self.last_traffic_labels)
        self.stats_protocols_text.setPlainText(
            "\n".join([f"{item['name']}: {item['count']} ({item['share']:.1%})" for item in protocols])
        )
        self.stats_calls_text.setPlainText(
            "\n".join(
                [
                    f"Chamadas: {len(calls)}",
                    f"Duracao da captura: {self._format_duration(self.capture_duration)}",
                    f"Midia com problema: {sum(1 for call in calls if call['media_state'] != 'ok')}",
                    f"Sinalizacao com problema: {sum(1 for call in calls if call['signaling_state'] != 'established')}",
                    f"High severity: {sum(1 for call in calls if call['severity'] == 'high')}",
                ]
            )
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
                {"label": "SIP OK", "value": sum(1 for call in calls if call["signaling_state"] == "established"), "color": palette["success"], "track": palette["surface"]},
                {"label": "RTP OK", "value": sum(1 for call in calls if call["media_state"] == "ok"), "color": palette["accent"], "track": palette["surface"]},
                {"label": "High", "value": sum(1 for call in calls if call["severity"] == "high"), "color": palette["danger"], "track": palette["surface"]},
                {"label": "Medium", "value": sum(1 for call in calls if call["severity"] == "medium"), "color": palette["warning"], "track": palette["surface"]},
            ],
            "vertical",
        )

    def _render_settings_page(self):
        self.settings_jitter.setValue(self.analysis_settings.rtp_high_jitter_threshold * 1000)
        self.settings_loss.setValue(self.analysis_settings.rtp_loss_high_threshold)
        self.settings_traffic_points.setValue(self.analysis_settings.max_traffic_points)
        self.settings_max_pcap_size.setValue(self.analysis_settings.max_pcap_size_mb)
        self.settings_export_directory.setText(self.analysis_settings.export_directory)

    def _choose_export_directory(self):
        directory = QFileDialog.getExistingDirectory(
            self,
            "Escolha a pasta padrao para relatorios",
            self.settings_export_directory.text(),
        )
        if directory:
            self.settings_export_directory.setText(directory)

    def _save_settings(self):
        self.analysis_settings = AnalysisSettings(
            rtp_high_jitter_threshold=self.settings_jitter.value() / 1000,
            rtp_loss_high_threshold=self.settings_loss.value(),
            max_traffic_points=self.settings_traffic_points.value(),
            max_pcap_size_mb=self.settings_max_pcap_size.value(),
            export_directory=self.settings_export_directory.text().strip() or str(Path.home()),
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
                call["severity"].upper(),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setData(Qt.UserRole, call["call_id"])
                if column == 5:
                    item.setBackground(QColor(self._severity_color(call["severity"], palette)))
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
            values = [finding["severity"], finding["type"], finding["source"], finding["destination"]]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setData(Qt.UserRole, key)
                if column == 0:
                    item.setBackground(QColor(self._severity_color(finding["severity"], palette)))
                    item.setForeground(QColor(palette["text"]))
                table.setItem(row, column, item)
        self._restore_finding_selection(table)
        table.blockSignals(False)

    def _fill_rtp_table(self, table, streams):
        table.setRowCount(len(streams))
        for row, stream in enumerate(streams):
            values = [
                stream["source"],
                stream["destination"],
                f"0x{stream['ssrc']:08X}",
                str(stream["packet_count"]),
                f"{stream['loss_percent']:.2f}% ({stream['lost_packets']})",
                f"{stream['average_jitter'] * 1000:.1f}",
            ]
            for column, value in enumerate(values):
                table.setItem(row, column, QTableWidgetItem(value))

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
        if finding is not None:
            self.findings_recommendation_text.setPlainText(finding["recommendation"] or "Sem recomendacao.")

    def _open_sip_flow_dialog(self):
        call = self._selected_call()
        if call is None or self.last_engine_result is None:
            self._set_status("Nenhuma chamada SIP selecionada")
            return

        sip_flows = self.last_engine_result.get("sip_flows", {})
        flow = sip_flows.get(call["call_id"])

        if flow is None:
            self._set_status("Fluxo SIP nao encontrado para a chamada selecionada")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"SIP Flow - {call['call_id']}")
        dialog.resize(980, 720)
        layout = QVBoxLayout(dialog)

        ladder = SIPLadderWidget()
        ladder.set_flow(flow)
        viewer = QTextEdit()
        viewer.setReadOnly(True)
        viewer.setAcceptRichText(True)
        viewer.setFont(_font("body"))
        viewer.setHtml(self._build_sip_flow_html(flow))
        layout.addWidget(ladder, 1)
        layout.addWidget(viewer)

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
        return f"{timestamp:.3f}"

    def _format_optional_duration(self, seconds_value):
        if seconds_value is None:
            return "-"
        return f"{seconds_value * 1000:.0f} ms"

    def _selected_call(self):
        if self.selected_call_id and self.selected_call_id in self.call_index:
            return self.call_index[self.selected_call_id]
        if self.last_viewmodel and self.last_viewmodel["calls"]:
            self.selected_call_id = self.last_viewmodel["calls"][0]["call_id"]
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
        evidence = call["key_evidence"] or ["Sem evidencias resumidas."]
        rtp_metrics = call["rtp_metrics"]
        timings = call.get("signaling_timings", {})
        direction_lines = [
            f"{direction}: {metric['packet_count']} pacotes, {metric['loss_percent']:.2f}% loss, {metric['max_jitter'] * 1000:.1f} ms jitter"
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
                    {self._chip_html(call['signaling_state'].upper(), self._signal_color(call['signaling_state'], palette), palette)}
                    &nbsp;
                    {self._chip_html(call['media_state'].upper(), self._media_color(call['media_state'], palette), palette)}
                    &nbsp;
                    {self._chip_html(call['severity'].upper(), self._severity_color(call['severity'], palette), palette)}
                </div>
                <div style="margin-bottom:8px;"><b>Origem:</b> {self._escape_html(call['source_ip'])}</div>
                <div style="margin-bottom:8px;"><b>Destino:</b> {self._escape_html(call['destination_ip'])}</div>
                <div style="margin-bottom:8px;"><b>Midia negociada:</b> {self._escape_html(call['media_direction'])}</div>
                <div style="margin-bottom:8px;"><b>Qualidade de midia:</b> {self._escape_html(call.get('media_quality', 'unknown'))}</div>
                <div style="margin-bottom:8px;"><b>Issue principal:</b> {self._escape_html(call['primary_issue'] or '-')}</div>
                <div style="margin-bottom:8px;"><b>Codecs:</b> {self._escape_html(', '.join(call['codec_guesses']) or '-')}</div>
                <div style="margin-bottom:8px;"><b>Duracao:</b> {self._format_duration(call['duration'])}</div>
                <div style="margin-bottom:8px;"><b>INVITE para 100/180/200/ACK:</b> {self._format_optional_duration(timings.get('invite_to_trying'))} / {self._format_optional_duration(timings.get('invite_to_ringing'))} / {self._format_optional_duration(timings.get('invite_to_ok'))} / {self._format_optional_duration(timings.get('invite_to_ack'))}</div>
                <div style="margin-bottom:8px;"><b>Streams RTP:</b> {call['rtp_stream_count']}</div>
                <div style="margin-bottom:8px;"><b>Pacotes RTP:</b> {rtp_metrics['packet_count']}</div>
                <div style="margin-bottom:8px;"><b>Packet loss:</b> {rtp_metrics['loss_percent']:.2f}% ({rtp_metrics['lost_packets']})</div>
                <div style="margin-bottom:8px;"><b>Jitter medio/maximo:</b> {rtp_metrics['average_jitter'] * 1000:.1f} / {rtp_metrics['max_jitter'] * 1000:.1f} ms</div>
                <div style="margin-bottom:8px;"><b>Out-of-order:</b> {rtp_metrics['out_of_order_packets']}</div>
                <div style="margin-bottom:14px;"><b>SSRC:</b> {self._escape_html(', '.join(str(ssrc) for ssrc in rtp_metrics['ssrcs']) or '-')}</div>
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

    def _render_finding_text(self, widget, finding):
        if finding is None:
            widget.setPlainText("Nenhum finding selecionado.")
            return
        palette = THEMES[self.current_theme]
        widget.setHtml(
            f"""
            <div style="font-family:'Segoe UI'; color:{palette['text']};">
                <div style="font-size:18px; font-weight:700; margin-bottom:8px;">{self._escape_html(finding['type'])}</div>
                <div style="margin-bottom:12px;">
                    {self._chip_html(finding['severity'].upper(), self._severity_color(finding['severity'], palette), palette)}
                </div>
                <div style="margin-bottom:8px;"><b>Origem:</b> {self._escape_html(finding['source'])}</div>
                <div style="margin-bottom:12px;"><b>Destino:</b> {self._escape_html(finding['destination'])}</div>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Descricao</div>
                <div style="margin-bottom:14px; padding:10px 12px; border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};">
                    {self._escape_html(finding["description"] or "-")}
                </div>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Recomendacao</div>
                <div style="padding:10px 12px; border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};">
                    {self._escape_html(finding["recommendation"] or "-")}
                </div>
            </div>
            """
        )

    def _finding_lines(self, findings, limit):
        return [
            f"{finding['severity'].upper()} | {finding['type']} | {finding['source']} -> {finding['destination']}"
            for finding in findings[:limit]
        ]

    def _finding_key(self, finding, index):
        return f"{index}:{finding['type']}:{finding['source']}:{finding['destination']}"

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
        icon_map = {
            "Resumo": QStyle.SP_ComputerIcon,
            "SIP": QStyle.SP_DialogYesButton,
            "RTP": QStyle.SP_MediaVolume,
            "Rede": QStyle.SP_DriveNetIcon,
            "Findings": QStyle.SP_MessageBoxWarning,
            "Estatisticas": QStyle.SP_FileDialogDetailedView,
            "Configuracoes": QStyle.SP_FileDialogContentsView,
            "Sobre": QStyle.SP_MessageBoxInformation,
        }
        return self.style().standardIcon(icon_map.get(page, QStyle.SP_FileIcon))

    def _severity_color(self, severity, palette):
        return {
            "high": palette["danger"],
            "medium": palette["warning"],
            "low": palette["success"],
        }.get(severity, palette["muted"])

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


def launch_gui():
    app = QApplication.instance() or QApplication(sys.argv)
    app.setWindowIcon(QIcon(str(LOGO_ICON_PATH)))
    window = SipperWindow()
    window.show()
    app.exec()
