from collections import Counter

from scapy.layers.inet import IP, TCP, UDP, ICMP

from ciper.rtp import parse_rtp_packet
from ciper.sip import parse_sip_message
from ciper.analysis_control import raise_if_cancelled


class PacketAnalysisAccumulator:
    def __init__(self, cancel_event=None):
        self.cancel_event = cancel_event
        self.protocols = Counter()
        self.source_ips = Counter()
        self.destination_ips = Counter()
        self.tcp_connections = Counter()

    def add(self, packet):
        raise_if_cancelled(self.cancel_event)
        if IP not in packet:
            return

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        self.source_ips[source_ip] += 1
        self.destination_ips[destination_ip] += 1

        if parse_sip_message(packet) is not None:
            self.protocols["SIP"] += 1

        elif parse_rtp_packet(packet) is not None:
            self.protocols["RTP"] += 1

        elif TCP in packet:
            self.protocols["TCP"] += 1

            connection = (
                source_ip,
                packet[TCP].sport,
                destination_ip,
                packet[TCP].dport,
            )

            self.tcp_connections[connection] += 1

        elif UDP in packet:
            self.protocols["UDP"] += 1

        elif ICMP in packet:
            self.protocols["ICMP"] += 1

        else:
            self.protocols["Other"] += 1

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
