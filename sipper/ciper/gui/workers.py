"""Background workers and traffic aggregation used by the main window."""

from pathlib import Path
from threading import Event

from PySide6.QtCore import QObject, Signal, Slot

from ciper.analysis_control import AnalysisCancelled, raise_if_cancelled
from ciper.analyzer import PacketAnalysisAccumulator, classify_packet
from ciper.engine import analyze_pcap_file
from ciper.logging_setup import configure_logging
from ciper.packets import ensure_decoded
from ciper.updater import check_for_update


class AnalysisWorker(QObject):
    progress_changed = Signal(str)
    progress_value = Signal(str, float)
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
            packet_analysis = PacketAnalysisAccumulator(self.cancel_event)
            traffic_analysis = TrafficAccumulator(self.settings.max_traffic_points)

            def collect_packet_metrics(packet):
                packet_analysis.add(packet)
                traffic_analysis.add(packet)

            engine_result = analyze_pcap_file(
                self.file_path,
                self.settings,
                self.cancel_event,
                collect_packet_metrics,
                progress=self.progress_value.emit,
            )
            self.progress_value.emit("Preparando graficos", 1.0)
            traffic_counts, traffic_labels, capture_duration = traffic_analysis.result()
            raise_if_cancelled(self.cancel_event)
            self.completed.emit(
                packet_analysis.result(),
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


class UpdateCheckWorker(QObject):
    completed = Signal(object)

    @Slot()
    def run(self):
        self.completed.emit(check_for_update())




class TrafficAccumulator:
    def __init__(self, max_bucket_count=720):
        self.names = ["SIP", "RTP", "TCP", "UDP", "ICMP"]
        self.max_bucket_count = max(1, max_bucket_count)
        self.buckets = {name: {} for name in self.names}
        self.first_time = None
        self.last_time = None

    def add(self, packet):
        if not hasattr(packet, "time"):
            return
        packet = ensure_decoded(packet)
        timestamp = packet.time
        second = int(timestamp)
        self.first_time = timestamp if self.first_time is None else min(self.first_time, timestamp)
        self.last_time = timestamp if self.last_time is None else max(self.last_time, timestamp)
        protocol = _classify_packet_for_traffic(packet)
        if protocol in self.buckets:
            self.buckets[protocol][second] = self.buckets[protocol].get(second, 0) + 1

    def result(self):
        if self.first_time is None or self.last_time is None:
            return {}, [], 0.0

        first_second = int(self.first_time)
        last_second = int(self.last_time)
        span_seconds = max(1, last_second - first_second + 1)
        bucket_width = max(1, (span_seconds + self.max_bucket_count - 1) // self.max_bucket_count)
        bucket_count = (span_seconds + bucket_width - 1) // bucket_width
        counters = {name: [0] * bucket_count for name in self.names}

        for name in self.names:
            for second, count in self.buckets[name].items():
                index = min((second - first_second) // bucket_width, bucket_count - 1)
                counters[name][index] += count

        labels = [_format_axis_time(index * bucket_width) for index in range(bucket_count)]
        return counters, labels, self.last_time - self.first_time


def _build_traffic_counts(packets, max_bucket_count=720):
    accumulator = TrafficAccumulator(max_bucket_count)
    for packet in packets:
        accumulator.add(packet)
    return accumulator.result()


def _classify_packet_for_traffic(packet):
    kind = classify_packet(packet)
    return kind if kind != "Other" else None


def _format_axis_time(seconds_offset):
    minutes = int(seconds_offset) // 60
    seconds = int(seconds_offset) % 60
    return f"{minutes:02d}:{seconds:02d}"
