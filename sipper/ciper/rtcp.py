"""RTCP sender/receiver report parsing (RFC 3550 section 6.4).

Receiver reports carry what the *far end* measured about a stream: fraction
lost, cumulative loss and interarrival jitter. Combined with the matching
sender report they also give a round-trip time estimate, which a passive
capture cannot otherwise measure.
"""

from dataclasses import dataclass, field

from ciper.packets import ensure_decoded
from ciper.rtp import RTP_DEFAULT_CLOCK_RATE, _is_rtcp_packet

RTCP_SENDER_REPORT = 200
RTCP_RECEIVER_REPORT = 201


@dataclass
class RTCPReportBlock:
    reporter_ip: str
    reporter_port: int
    receiver_ip: str
    reporter_ssrc: int
    source_ssrc: int
    fraction_lost: float
    cumulative_lost: int
    highest_sequence: int
    jitter_units: int
    last_sr: int
    delay_since_last_sr: int
    packet_time: float


@dataclass
class RTCPStreamReport:
    """Aggregated view of every report block received about one media SSRC."""

    source_ssrc: int
    reporter_ip: str
    receiver_ip: str
    report_count: int = 0
    max_fraction_lost: float = 0.0
    cumulative_lost: int = 0
    max_jitter_units: int = 0
    rtt_samples: list[float] = field(default_factory=list)
    clock_rate: int = RTP_DEFAULT_CLOCK_RATE

    @property
    def max_jitter(self):
        return self.max_jitter_units / self.clock_rate if self.clock_rate else 0.0

    @property
    def max_rtt(self):
        return max(self.rtt_samples, default=None)

    @property
    def average_rtt(self):
        if not self.rtt_samples:
            return None
        return sum(self.rtt_samples) / len(self.rtt_samples)


def parse_rtcp_packet(packet):
    """Return (sender_reports, report_blocks) for one UDP packet, or None."""
    packet = ensure_decoded(packet)
    if not packet.ip_version or packet.transport != "UDP":
        return None
    payload = packet.payload
    if len(payload) < 8 or payload[0] >> 6 != 2 or not _is_rtcp_packet(payload):
        return None

    sender_reports = []
    blocks = []
    offset = 0
    while offset + 4 <= len(payload):
        report_count = payload[offset] & 0x1F
        packet_type = payload[offset + 1]
        length = (((payload[offset + 2] << 8) | payload[offset + 3]) + 1) * 4
        chunk = payload[offset:offset + length]
        offset += length
        if len(chunk) < 8:
            break
        reporter_ssrc = int.from_bytes(chunk[4:8], "big")
        if packet_type == RTCP_SENDER_REPORT and len(chunk) >= 28:
            ntp_middle = int.from_bytes(chunk[10:14], "big")
            sender_reports.append((reporter_ssrc, ntp_middle, float(packet.time)))
            block_offset = 28
        elif packet_type == RTCP_RECEIVER_REPORT:
            block_offset = 8
        else:
            continue
        for index in range(report_count):
            start = block_offset + index * 24
            block = chunk[start:start + 24]
            if len(block) < 24:
                break
            cumulative = int.from_bytes(block[5:8], "big")
            if cumulative & 0x800000:
                cumulative -= 0x1000000
            blocks.append(
                RTCPReportBlock(
                    reporter_ip=packet.src,
                    reporter_port=packet.sport,
                    receiver_ip=packet.dst,
                    reporter_ssrc=reporter_ssrc,
                    source_ssrc=int.from_bytes(block[0:4], "big"),
                    fraction_lost=block[4] / 256,
                    cumulative_lost=cumulative,
                    highest_sequence=int.from_bytes(block[8:12], "big"),
                    jitter_units=int.from_bytes(block[12:16], "big"),
                    last_sr=int.from_bytes(block[16:20], "big"),
                    delay_since_last_sr=int.from_bytes(block[20:24], "big"),
                    packet_time=float(packet.time),
                )
            )
    return sender_reports, blocks


def build_rtcp_reports(packets, rtp_streams=None):
    """Aggregate RTCP report blocks per reported media SSRC.

    RTT uses the capture times of the sender report (identified by its NTP
    middle 32 bits) and of the receiver report that echoes it as LSR, minus
    the reported DLSR: ``rtt = (t_rr - t_sr) - dlsr``. It is exact when the
    capture point is next to the sender of the SR and an estimate otherwise.
    """
    clock_rates = {}
    for stream in (rtp_streams or {}).values():
        clock_rates.setdefault(stream.ssrc, stream.clock_rate)

    sr_times = {}
    blocks = []
    for packet in packets:
        parsed = parse_rtcp_packet(packet)
        if parsed is None:
            continue
        sender_reports, report_blocks = parsed
        for reporter_ssrc, ntp_middle, packet_time in sender_reports:
            sr_times[(reporter_ssrc, ntp_middle)] = packet_time
        blocks.extend(report_blocks)

    reports = {}
    for block in blocks:
        key = (block.source_ssrc, block.reporter_ip)
        report = reports.get(key)
        if report is None:
            report = reports[key] = RTCPStreamReport(
                source_ssrc=block.source_ssrc,
                reporter_ip=block.reporter_ip,
                receiver_ip=block.receiver_ip,
                clock_rate=clock_rates.get(block.source_ssrc, RTP_DEFAULT_CLOCK_RATE),
            )
        report.report_count += 1
        report.max_fraction_lost = max(report.max_fraction_lost, block.fraction_lost)
        report.cumulative_lost = max(report.cumulative_lost, block.cumulative_lost)
        report.max_jitter_units = max(report.max_jitter_units, block.jitter_units)
        if block.last_sr:
            sr_time = sr_times.get((block.source_ssrc, block.last_sr))
            if sr_time is not None:
                rtt = (block.packet_time - sr_time) - block.delay_since_last_sr / 65536
                if 0 <= rtt < 10:
                    report.rtt_samples.append(rtt)
    return reports
