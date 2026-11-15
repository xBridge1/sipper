from collections import Counter

from ciper.analysis_control import raise_if_cancelled
from ciper.packets import _UNSET, ensure_decoded
from ciper.rtp import parse_rtp_packet
from ciper.sip import parse_sip_message


def classify_packet(packet):
    """Return the display protocol of a packet: SIP, RTP, TCP, UDP, ICMP, Other or None.

    ``None`` means the frame carries no IPv4/IPv6 layer. The result is cached on
    the decoded packet, so the dashboard counters, the traffic chart and the
    engine all share a single SIP/RTP parse per packet.
    """
    packet = ensure_decoded(packet)
    kind = packet._kind
    if kind is not _UNSET:
        return kind

    if not packet.ip_version:
        kind = None
    elif parse_sip_message(packet) is not None:
        kind = "SIP"
    elif parse_rtp_packet(packet) is not None:
        kind = "RTP"
    elif packet.transport == "TCP":
        kind = "TCP"
    elif packet.transport == "UDP":
        kind = "UDP"
    elif packet.transport == "ICMP":
        kind = "ICMP"
    else:
        kind = "Other"

    packet._kind = kind
    return kind


class PacketAnalysisAccumulator:
    def __init__(self, cancel_event=None):
        self.cancel_event = cancel_event
        self.protocols = Counter()
        self.source_ips = Counter()
        self.destination_ips = Counter()
        self.tcp_connections = Counter()

    def add(self, packet):
        raise_if_cancelled(self.cancel_event)
        packet = ensure_decoded(packet)
        kind = classify_packet(packet)
        if kind is None:
            return

        self.source_ips[packet.src] += 1
        self.destination_ips[packet.dst] += 1
        self.protocols[kind] += 1

        if kind == "TCP":
            self.tcp_connections[(packet.src, packet.sport, packet.dst, packet.dport)] += 1

    def result(self):
        return {
            "protocols": self.protocols,
            "source_ips": self.source_ips,
            "destination_ips": self.destination_ips,
            "tcp_connections": self.tcp_connections,
        }


def analyze_packets(packets, cancel_event=None):
    accumulator = PacketAnalysisAccumulator(cancel_event)

    for packet in packets:
        accumulator.add(packet)

    return accumulator.result()
