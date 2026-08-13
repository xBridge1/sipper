from dataclasses import dataclass

from scapy.layers.inet import IP, UDP


@dataclass
class UDPPacketEvent:
    direction: str
    payload_length: int
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int


def track_udp_packets(packets, flow):
    events = []

    for packet in packets:
        if IP not in packet or UDP not in packet:
            continue

        udp = packet[UDP]

        if (
            packet[IP].src == flow.source_ip
            and udp.sport == flow.source_port
            and packet[IP].dst == flow.destination_ip
            and udp.dport == flow.destination_port
        ):
            direction = "forward"

        elif (
            packet[IP].src == flow.destination_ip
            and udp.sport == flow.destination_port
            and packet[IP].dst == flow.source_ip
            and udp.dport == flow.source_port
        ):
            direction = "reverse"

        else:
            continue

        payload_length = len(bytes(udp.payload))

        events.append(
            UDPPacketEvent(
                direction=direction,
                payload_length=payload_length,
                source_ip=packet[IP].src,
                source_port=udp.sport,
                destination_ip=packet[IP].dst,
                destination_port=udp.dport,
            )
        )

    return events