"""Reusable dashboard widgets: cards, KPI tiles, charts and the SIP ladder."""

from PySide6.QtCore import QAbstractAnimation, QEasingCurve, QPointF, QRectF, Qt, Signal, QVariantAnimation
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import QFrame, QGridLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

from ciper.gui.theme import FONTS, THEMES


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




class PanelCard(QFrame):
    def __init__(self, title):
        super().__init__()
        self.setObjectName("panelCard")
        self.title_label = QLabel(title)
        self.title_label.setObjectName("panelTitle")
        self.title_label.setFont(_font("subtitle"))
        # The title must not absorb spare height, or it floats mid-card.
        self.title_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
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
        value_width = 40
        bar_width = max(10, rect.width() - 70 - value_width - 12)

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
            painter.drawText(
                QRectF(rect.right() - value_width, y + 4, value_width, 18),
                Qt.AlignRight | Qt.AlignVCenter,
                str(item["value"]),
            )

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
    """Packets per time bucket.

    Series much smaller than the dominant one (e.g. SIP next to RTP) are drawn
    against a secondary right axis so they do not flatten into the baseline.
    Optional markers (calls starting/ending) are drawn as vertical ticks.
    """

    SECONDARY_RATIO = 0.15

    def __init__(self):
        super().__init__()
        self.series = []
        self.labels = []
        self.markers = []
        self.chart_progress = 1.0
        self.setMinimumHeight(190)

    def set_data(self, series, labels, markers=None):
        self.series = series
        self.labels = labels
        self.markers = markers or []
        _animate_chart(self)

    def _split_axes(self):
        maxima = {index: max(item["values"]) if item["values"] else 0 for index, item in enumerate(self.series)}
        overall = max(maxima.values(), default=0)
        secondary = {
            index
            for index, value in maxima.items()
            if overall and 0 < value < overall * self.SECONDARY_RATIO
        }
        if len(secondary) == len(self.series):
            secondary = set()
        primary_max = max((value for index, value in maxima.items() if index not in secondary), default=1)
        secondary_max = max((value for index, value in maxima.items() if index in secondary), default=1)
        return secondary, max(primary_max, 1), max(secondary_max, 1)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), Qt.transparent)

        if not self.series or not any(item["values"] for item in self.series):
            painter.setPen(QColor("#777777"))
            painter.drawText(self.rect(), Qt.AlignCenter, "Sem dados de trafego")
            return

        secondary, primary_max, secondary_max = self._split_axes()
        right_margin = 48 if secondary else 18
        rect = self.rect().adjusted(48, 30, -right_margin, -34)
        text_color = QColor(self.palette().text().color())
        grid_pen = QPen(QColor(self.palette().mid().color()), 1)
        secondary_color = QColor(self.series[min(secondary)]["color"]) if secondary else text_color

        painter.setFont(_font("small"))
        for step in range(5):
            y = rect.bottom() - (rect.height() * step / 4)
            painter.setPen(grid_pen)
            painter.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))
            painter.setPen(text_color)
            painter.drawText(QRectF(0, y - 10, rect.left() - 8, 20), Qt.AlignRight | Qt.AlignVCenter, _compact(primary_max * step / 4))
            if secondary:
                painter.setPen(secondary_color)
                painter.drawText(QRectF(rect.right() + 6, y - 10, right_margin - 6, 20), Qt.AlignLeft | Qt.AlignVCenter, _compact(secondary_max * step / 4))

        count = max((len(item["values"]) for item in self.series), default=0)
        if count < 2:
            return

        palette = THEMES["dark"] if self.palette().window().color().lightness() < 128 else THEMES["light"]
        for marker in self.markers:
            fraction = marker.get("position")
            if fraction is None or not -0.05 <= fraction <= 1.05:
                continue
            fraction = min(1.0, max(0.0, fraction))
            x = rect.left() + rect.width() * fraction
            color = QColor(marker.get("color") or palette["muted"])
            color.setAlpha(150)
            painter.setPen(QPen(color, 1, Qt.DashLine))
            painter.drawLine(QPointF(x, rect.top()), QPointF(x, rect.bottom()))
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(marker.get("color") or palette["muted"]))
            painter.drawEllipse(QRectF(x - 3.5, rect.top() - 3.5, 7, 7))

        for index, item in enumerate(self.series):
            values = item["values"]
            if len(values) < 2:
                continue
            scale = secondary_max if index in secondary else primary_max
            style = Qt.DashLine if index in secondary else Qt.SolidLine
            painter.setPen(QPen(QColor(item["color"]), 2.2, style, Qt.RoundCap, Qt.RoundJoin))
            points = [
                QPointF(
                    rect.left() + (rect.width() * point_index / (count - 1)),
                    rect.bottom() - ((value / scale) * rect.height() * self.chart_progress),
                )
                for point_index, value in enumerate(values)
            ]
            for point_index in range(len(points) - 1):
                painter.drawLine(points[point_index], points[point_index + 1])

        painter.setPen(text_color)
        label_step = max(1, count // 6)
        for index in range(0, count, label_step):
            if index >= len(self.labels):
                continue
            x = rect.left() + (rect.width() * index / (count - 1))
            painter.drawText(QRectF(x - 26, rect.bottom() + 8, 52, 18), Qt.AlignCenter, self.labels[index])

        x = rect.left()
        for index, item in enumerate(self.series):
            label = item["label"] + (" (eixo dir.)" if index in secondary else "")
            width = painter.fontMetrics().horizontalAdvance(label) + 34
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(item["color"]))
            painter.drawEllipse(QRectF(x, 4, 10, 10))
            painter.setPen(text_color)
            painter.drawText(QRectF(x + 16, 0, width, 18), Qt.AlignLeft | Qt.AlignVCenter, label)
            x += width
        if self.markers:
            painter.setPen(QColor(palette["muted"]))
            painter.drawText(QRectF(x, 0, 220, 18), Qt.AlignLeft | Qt.AlignVCenter, "| marcas: inicio/fim de chamada")


def _compact(value):
    value = float(value)
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 10_000:
        return f"{value / 1000:.0f}k"
    if value >= 1000:
        return f"{value / 1000:.1f}k"
    if value < 10 and abs(value - round(value)) > 0.05:
        return f"{value:.1f}"
    return str(int(round(value)))


class MetricGrid(QWidget):
    """Compact label/value tiles that replace "Chave: valor" text dumps."""

    def __init__(self, columns=3):
        super().__init__()
        self.columns = max(1, columns)
        self.layout_grid = QGridLayout(self)
        self.layout_grid.setContentsMargins(0, 0, 0, 0)
        self.layout_grid.setHorizontalSpacing(10)
        self.layout_grid.setVerticalSpacing(10)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        self.tiles = []

    def clear(self):
        while self.layout_grid.count():
            item = self.layout_grid.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        self.tiles = []

    def set_message(self, text):
        self.clear()
        label = QLabel(text)
        label.setObjectName("mutedLabel")
        label.setWordWrap(True)
        self.layout_grid.addWidget(label, 0, 0, 1, self.columns)
        self.tiles.append(label)

    def set_metrics(self, metrics, palette=None):
        """``metrics``: iterable of (label, value[, tone[, span]]).

        tone is one of danger, warning, success, low or None; span is how many
        columns the tile takes (long values such as a finding title).
        """
        self.clear()
        palette = palette or THEMES["dark"]
        row = column = 0
        for metric in metrics:
            label, value, *rest = metric
            tone = rest[0] if rest else None
            span = min(self.columns, rest[1]) if len(rest) > 1 else 1
            if column + span > self.columns:
                row += 1
                column = 0
            tile = QFrame()
            tile.setObjectName("metricTile")
            tile_layout = QVBoxLayout(tile)
            tile_layout.setContentsMargins(12, 9, 12, 9)
            tile_layout.setSpacing(2)
            caption = QLabel(str(label))
            caption.setObjectName("metricLabel")
            caption.setFont(_font("small"))
            value_label = QLabel(str(value))
            value_label.setObjectName("metricValue")
            value_label.setWordWrap(True)
            value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            if tone and tone in palette:
                value_label.setStyleSheet(f"color: {palette[tone]};")
            tile_layout.addWidget(caption)
            tile_layout.addWidget(value_label)
            self.layout_grid.addWidget(tile, row, column, 1, span)
            self.tiles.append(tile)
            column += span
            if column >= self.columns:
                row += 1
                column = 0
        for index in range(self.columns):
            self.layout_grid.setColumnStretch(index, 1)

    def values(self):
        """Visible text of every tile, for tests and copy/paste."""
        texts = []
        for tile in self.tiles:
            if isinstance(tile, QLabel):
                texts.append(tile.text())
                continue
            labels = tile.findChildren(QLabel)
            texts.append(": ".join(label.text() for label in labels))
        return texts


class StreamTimelineChart(QWidget):
    """RFC 3550 jitter over time for one RTP stream, with loss markers."""

    def __init__(self):
        super().__init__()
        self.points = []
        self.losses = []
        self.title = ""
        self.threshold = None
        self.chart_progress = 1.0
        self.setMinimumHeight(150)

    def set_stream(self, points, losses=None, title="", threshold=None):
        self.points = points or []
        self.losses = losses or []
        self.title = title
        self.threshold = threshold
        _animate_chart(self)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), Qt.transparent)
        palette = THEMES["dark"] if self.palette().window().color().lightness() < 128 else THEMES["light"]
        text_color = QColor(palette["text"])

        if len(self.points) < 2:
            painter.setPen(QColor(palette["muted"]))
            painter.drawText(self.rect(), Qt.AlignCenter, "Selecione um stream RTP para ver jitter e perdas no tempo")
            return

        rect = self.rect().adjusted(48, 28, -16, -30)
        duration = max(self.points[-1][0], 0.001)
        peak = max(value for _time, value in self.points)
        if self.threshold:
            peak = max(peak, self.threshold * 1.2)
        peak = max(peak, 0.001)

        painter.setFont(_font("small"))
        painter.setPen(text_color)
        painter.drawText(QRectF(rect.left(), 2, rect.width(), 18), Qt.AlignLeft | Qt.AlignVCenter, self.title)
        for step in range(4):
            y = rect.bottom() - rect.height() * step / 3
            painter.setPen(QPen(QColor(palette["border"]), 1))
            painter.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))
            painter.setPen(QColor(palette["muted"]))
            painter.drawText(QRectF(0, y - 9, rect.left() - 6, 18), Qt.AlignRight | Qt.AlignVCenter, f"{peak * 1000 * step / 3:.0f} ms")

        if self.threshold:
            y = rect.bottom() - rect.height() * (self.threshold / peak)
            painter.setPen(QPen(QColor(palette["warning"]), 1, Qt.DashLine))
            painter.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))

        for loss_time, count in self.losses:
            x = rect.left() + rect.width() * min(1.0, loss_time / duration)
            painter.setPen(QPen(QColor(palette["danger"]), 2 if count > 1 else 1))
            painter.drawLine(QPointF(x, rect.top()), QPointF(x, rect.bottom()))

        path = QPainterPath()
        for index, (point_time, value) in enumerate(self.points):
            x = rect.left() + rect.width() * (point_time / duration)
            y = rect.bottom() - rect.height() * (value / peak) * self.chart_progress
            if index == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        painter.setPen(QPen(QColor("#36D6C8" if palette is THEMES["dark"] else "#1AA59B"), 2))
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(path)

        painter.setPen(QColor(palette["muted"]))
        painter.drawText(QRectF(rect.left(), rect.bottom() + 8, 80, 18), Qt.AlignLeft, "0 s")
        painter.drawText(QRectF(rect.right() - 80, rect.bottom() + 8, 80, 18), Qt.AlignRight, f"{duration:.1f} s")
        legend = "linha: jitter RFC 3550   vermelho: perdas"
        if self.threshold:
            legend += "   tracejado: limite"
        painter.drawText(QRectF(rect.left() + 80, rect.bottom() + 8, rect.width() - 160, 18), Qt.AlignCenter, legend)


NAV_ICON_KINDS = {
    "Resumo": "grid",
    "Diagnostico": "alert",
    "SIP": "arrows",
    "RTP": "wave",
    "Rede": "nodes",
    "Seguranca": "shield",
    "Findings": "list",
    "Estatisticas": "bars",
    "Configuracoes": "gear",
    "Sobre": "info",
}


def make_nav_icon(page, color, size=18):
    """Monochrome line icon drawn in code, so it follows the theme color."""
    kind = NAV_ICON_KINDS.get(page, "dot")
    pixmap = QPixmap(size * 2, size * 2)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.scale(2, 2)
    pen = QPen(QColor(color), 1.6, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    s = size
    if kind == "grid":
        for x, y in ((2, 2), (10, 2), (2, 10), (10, 10)):
            painter.drawRoundedRect(QRectF(x, y, 6, 6), 1.5, 1.5)
    elif kind == "alert":
        path = QPainterPath()
        path.moveTo(s / 2, 2)
        path.lineTo(s - 2, s - 3)
        path.lineTo(2, s - 3)
        path.closeSubpath()
        painter.drawPath(path)
        painter.drawLine(QPointF(s / 2, 7), QPointF(s / 2, 10.5))
        painter.drawPoint(QPointF(s / 2, 13))
    elif kind == "arrows":
        painter.drawLine(QPointF(3, 6), QPointF(15, 6))
        painter.drawLine(QPointF(12, 3), QPointF(15, 6))
        painter.drawLine(QPointF(12, 9), QPointF(15, 6))
        painter.drawLine(QPointF(15, 12), QPointF(3, 12))
        painter.drawLine(QPointF(6, 9), QPointF(3, 12))
        painter.drawLine(QPointF(6, 15), QPointF(3, 12))
    elif kind == "wave":
        for x, height in ((3, 4), (6.5, 10), (10, 14), (13.5, 7)):
            painter.drawLine(QPointF(x, s / 2 - height / 2), QPointF(x, s / 2 + height / 2))
    elif kind == "nodes":
        for x, y in ((4, 4), (14, 4), (9, 14)):
            painter.drawEllipse(QPointF(x, y), 2.2, 2.2)
        painter.drawLine(QPointF(6, 4), QPointF(12, 4))
        painter.drawLine(QPointF(5, 6), QPointF(8, 12))
        painter.drawLine(QPointF(13, 6), QPointF(10, 12))
    elif kind == "shield":
        path = QPainterPath()
        path.moveTo(s / 2, 2)
        path.lineTo(s - 3, 4.5)
        path.cubicTo(s - 3, 11, s / 2 + 3, 14.5, s / 2, 16)
        path.cubicTo(s / 2 - 3, 14.5, 3, 11, 3, 4.5)
        path.closeSubpath()
        painter.drawPath(path)
    elif kind == "list":
        for y in (4, 9, 14):
            painter.drawPoint(QPointF(3, y))
            painter.drawLine(QPointF(6, y), QPointF(15, y))
    elif kind == "bars":
        painter.drawLine(QPointF(2, 16), QPointF(16, 16))
        for x, top in ((4.5, 9), (9, 4), (13.5, 11)):
            painter.drawLine(QPointF(x, 15), QPointF(x, top))
    elif kind == "gear":
        painter.drawEllipse(QPointF(s / 2, s / 2), 3, 3)
        painter.drawEllipse(QPointF(s / 2, s / 2), 6.5, 6.5)
    elif kind == "info":
        painter.drawEllipse(QPointF(s / 2, s / 2), 7, 7)
        painter.drawLine(QPointF(s / 2, 8), QPointF(s / 2, 12.5))
        painter.drawPoint(QPointF(s / 2, 5.5))
    else:
        painter.drawEllipse(QPointF(s / 2, s / 2), 2.5, 2.5)
    painter.end()
    return QIcon(pixmap)


class SIPLadderWidget(QWidget):
    message_selected = Signal(int)

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

    def mousePressEvent(self, event):
        if self.flow is None:
            return

        rect = self.rect().adjusted(24, 24, -24, -24)
        first_message_y = rect.top() + 62
        index = round((event.position().y() - first_message_y) / 44)

        if 0 <= index < len(self.flow.messages):
            message_y = first_message_y + (index * 44)
            if abs(event.position().y() - message_y) <= 18:
                self.message_selected.emit(index)
                event.accept()
                return

        super().mousePressEvent(event)
