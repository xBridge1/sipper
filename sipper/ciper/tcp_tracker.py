from dataclasses import dataclass

from ciper.packets import ensure_decoded


@dataclass
class TCPPacketEvent:
    event_type: str
    sequence: int
    acknowledgement: int
    payload_length: int
    direction: str


def track_tcp_packets(packets, flow):
    events = []

    seen_segments = set()

    for packet in packets:
        packet = ensure_decoded(packet)
        if packet.transport != "TCP":
            continue

        sequence = packet.tcp_seq
        # Payload real do TCP, sem cabecalho e sem padding Ethernet.
        payload_length = len(packet.payload)

        if packet.src == flow.source_ip and packet.sport == flow.source_port:
            direction = "forward"
        else:
            direction = "reverse"

        segment_key = (direction, sequence, payload_length)

        if payload_length > 0 and segment_key in seen_segments:
            event_type = "retransmission"
        else:
            event_type = "new"

        if payload_length > 0:
            seen_segments.add(segment_key)

        events.append(
            TCPPacketEvent(
                event_type=event_type,
                sequence=sequence,
                acknowledgement=packet.tcp_ack,
                payload_length=payload_length,
                direction=direction,
            )
        )

    return events
