from dataclasses import dataclass

from ciper.packets import ensure_decoded


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
        packet = ensure_decoded(packet)
        if not packet.ip_version or packet.transport != "UDP":
            continue

        source_ip = packet.src
        destination_ip = packet.dst

        if (
            source_ip == flow.source_ip
            and packet.sport == flow.source_port
            and destination_ip == flow.destination_ip
            and packet.dport == flow.destination_port
        ):
            direction = "forward"

        elif (
            source_ip == flow.destination_ip
            and packet.sport == flow.destination_port
            and destination_ip == flow.source_ip
            and packet.dport == flow.source_port
        ):
            direction = "reverse"

        else:
            continue

        events.append(
            UDPPacketEvent(
                direction=direction,
                payload_length=len(packet.payload),
                source_ip=source_ip,
                source_port=packet.sport,
                destination_ip=destination_ip,
                destination_port=packet.dport,
            )
        )

    return events
