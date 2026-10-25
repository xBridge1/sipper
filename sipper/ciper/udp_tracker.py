from dataclasses import dataclass

from scapy.layers.inet import UDP

from ciper.network import get_ip_addresses, get_network_layer


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
        if get_network_layer(packet) is None or UDP not in packet:
            continue

        udp = packet[UDP]
        source_ip, destination_ip = get_ip_addresses(packet)

        if (
            source_ip == flow.source_ip
            and udp.sport == flow.source_port
            and destination_ip == flow.destination_ip
            and udp.dport == flow.destination_port
        ):
            direction = "forward"

        elif (
            source_ip == flow.destination_ip
            and udp.sport == flow.destination_port
            and destination_ip == flow.source_ip
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
                source_ip=source_ip,
                source_port=udp.sport,
                destination_ip=destination_ip,
                destination_port=udp.dport,
            )
        )

    return events
