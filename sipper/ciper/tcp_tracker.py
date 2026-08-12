from dataclasses import dataclass

from scapy.layers.inet import TCP


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
        if TCP not in packet:
            continue

        sequence = int(packet[TCP].seq)
        acknowledgement = int(packet[TCP].ack)

        # O payload real do TCP começa depois do cabeçalho TCP.
        payload_length = len(bytes(packet[TCP].payload))

        if (
            packet.src == flow.source_ip
            and packet.sport == flow.source_port
        ):
            direction = "forward"
        else:
            direction = "reverse"

        segment_key = (
            direction,
            sequence,
            payload_length,
        )

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
                acknowledgement=acknowledgement,
                payload_length=payload_length,
                direction=direction,
            )
        )

    return events