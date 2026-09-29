from collections import defaultdict
from dataclasses import dataclass

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6ExtHdrFragment
from scapy.packet import Raw

from ciper.network import get_ip_addresses, get_network_layer


@dataclass
class TCPPayloadBlock:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    payload: bytes
    first_timestamp: float
    segmented: bool
    fragmented: bool


def reassemble_tcp_payloads(packets):
    groups = defaultdict(list)

    for position, packet in enumerate(packets):
        if TCP not in packet or Raw not in packet or get_network_layer(packet) is None:
            continue

        payload = bytes(packet[Raw].load)
        if not payload:
            continue

        source_ip, destination_ip = get_ip_addresses(packet)
        key = (source_ip, destination_ip, int(packet[TCP].sport), int(packet[TCP].dport))
        groups[key].append(
            (
                int(packet[TCP].seq),
                position,
                float(packet.time),
                payload,
                _is_ip_fragmented(packet),
            )
        )

    blocks = []
    for (source_ip, destination_ip, source_port, destination_port), segments in groups.items():
        blocks.extend(
            _reassemble_direction(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                segments,
            )
        )

    return sorted(blocks, key=lambda block: block.first_timestamp)


def _reassemble_direction(source_ip, destination_ip, source_port, destination_port, segments):
    has_sequence_numbers = any(sequence != 0 for sequence, *_ in segments)
    ordered_segments = (
        sorted(segments, key=lambda segment: (segment[0], segment[1]))
        if has_sequence_numbers
        else sorted(segments, key=lambda segment: segment[1])
    )

    blocks = []
    payload = bytearray()
    first_timestamp = None
    segment_count = 0
    fragmented = False
    next_sequence = None

    def finish_block():
        if not payload:
            return
        blocks.append(
            TCPPayloadBlock(
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                payload=bytes(payload),
                first_timestamp=first_timestamp,
                segmented=segment_count > 1,
                fragmented=fragmented,
            )
        )

    for sequence, _position, timestamp, segment_payload, is_fragmented in ordered_segments:
        if not payload:
            payload.extend(segment_payload)
            first_timestamp = timestamp
            segment_count = 1
            fragmented = is_fragmented
            next_sequence = sequence + len(segment_payload) if has_sequence_numbers else None
            continue

        if not has_sequence_numbers:
            payload.extend(segment_payload)
            segment_count += 1
            fragmented = fragmented or is_fragmented
            continue

        if sequence > next_sequence:
            finish_block()
            payload = bytearray(segment_payload)
            first_timestamp = timestamp
            segment_count = 1
            fragmented = is_fragmented
            next_sequence = sequence + len(segment_payload)
            continue

        overlap = next_sequence - sequence
        if overlap >= len(segment_payload):
            continue

        payload.extend(segment_payload[overlap:])
        segment_count += 1
        fragmented = fragmented or is_fragmented
        next_sequence += len(segment_payload) - overlap

    finish_block()
    return blocks


def _is_ip_fragmented(packet):
    return bool(
        (IP in packet and (packet[IP].flags.MF or packet[IP].frag > 0))
        or IPv6ExtHdrFragment in packet
    )
