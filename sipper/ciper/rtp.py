from dataclasses import dataclass, field

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw


RTP_PAYLOAD_TYPE_NAMES = {
    0: "PCMU",
    3: "GSM",
    4: "G723",
    8: "PCMA",
    9: "G722",
    18: "G729",
}


@dataclass
class RTPPacket:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    sequence: int
    timestamp: int
    ssrc: int
    payload_type: int
    marker: int
    payload_length: int
    packet_time: float


@dataclass
class RTPStream:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    ssrc: int
    packets: list[RTPPacket] = field(default_factory=list)
    packet_count: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    lost_packets: int = 0
    out_of_order_packets: int = 0
    timestamp_anomalies: int = 0
    interruptions: int = 0
    max_jitter: float = 0.0
    jitter_samples: list[float] = field(default_factory=list)
    payload_types: set[int] = field(default_factory=set)

    @property
    def duration(self):
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return self.last_timestamp - self.first_timestamp

    @property
    def codec_guesses(self):
        guesses = []

        for payload_type in sorted(self.payload_types):
            guess = RTP_PAYLOAD_TYPE_NAMES.get(payload_type)

            if guess is not None:
                guesses.append(guess)

        return guesses

    @property
    def average_jitter(self):
        if not self.jitter_samples:
            return 0.0
        return sum(self.jitter_samples) / len(self.jitter_samples)


def parse_rtp_packet(packet):
    if (IP not in packet and IPv6 not in packet) or UDP not in packet or Raw not in packet:
        return None

    payload = bytes(packet[Raw].load)

    if len(payload) < 12:
        return None

    version = payload[0] >> 6
    if version != 2:
        return None

    payload_type = payload[1] & 0x7F
    csrc_count = payload[0] & 0x0F
    has_extension = bool(payload[0] & 0x10)
    has_padding = bool(payload[0] & 0x20)
    header_length = 12 + (csrc_count * 4)

    if len(payload) < header_length:
        return None

    if has_extension:
        if len(payload) < header_length + 4:
            return None
        extension_length = (payload[header_length + 2] << 8) | payload[header_length + 3]
        header_length += 4 + (extension_length * 4)

        if len(payload) < header_length:
            return None

    padding_length = payload[-1] if has_padding else 0

    if padding_length > len(payload) - header_length:
        return None

    sequence = (payload[2] << 8) | payload[3]
    timestamp = (
        (payload[4] << 24)
        | (payload[5] << 16)
        | (payload[6] << 8)
        | payload[7]
    )
    ssrc = (
        (payload[8] << 24)
        | (payload[9] << 16)
        | (payload[10] << 8)
        | payload[11]
    )

    network_layer = packet[IP] if IP in packet else packet[IPv6]

    return RTPPacket(
        source_ip=network_layer.src,
        destination_ip=network_layer.dst,
        source_port=packet[UDP].sport,
        destination_port=packet[UDP].dport,
        sequence=sequence,
        timestamp=timestamp,
        ssrc=ssrc,
        payload_type=payload_type,
        marker=(payload[1] >> 7) & 0x01,
        payload_length=len(payload) - header_length - padding_length,
        packet_time=float(packet.time),
    )


def build_rtp_streams(packets):
    streams = {}

    for packet in packets:
        parsed = parse_rtp_packet(packet)
        if parsed is None:
            continue

        key = (
            parsed.source_ip,
            parsed.destination_ip,
            parsed.source_port,
            parsed.destination_port,
            parsed.ssrc,
        )

        if key not in streams:
            streams[key] = RTPStream(
                source_ip=parsed.source_ip,
                destination_ip=parsed.destination_ip,
                source_port=parsed.source_port,
                destination_port=parsed.destination_port,
                ssrc=parsed.ssrc,
            )

        stream = streams[key]
        stream.packets.append(parsed)
        stream.packet_count += 1
        stream.payload_types.add(parsed.payload_type)

        if stream.first_timestamp is None:
            stream.first_timestamp = parsed.packet_time
        stream.last_timestamp = parsed.packet_time

    for stream in streams.values():
        _finalize_stream(stream)

    return streams


def _finalize_stream(stream):
    previous_packet = None
    previous_delta = None

    for packet in stream.packets:
        if previous_packet is None:
            previous_packet = packet
            continue

        sequence_delta = (packet.sequence - previous_packet.sequence) & 0xFFFF
        if 1 < sequence_delta <= 0x7FFF:
            stream.lost_packets += sequence_delta - 1
        elif sequence_delta == 0 or sequence_delta > 0x7FFF:
            stream.out_of_order_packets += 1

        timestamp_delta = (packet.timestamp - previous_packet.timestamp) & 0xFFFFFFFF
        if timestamp_delta == 0 or timestamp_delta > 0x7FFFFFFF:
            stream.timestamp_anomalies += 1

        arrival_delta = packet.packet_time - previous_packet.packet_time
        if arrival_delta > 1.0:
            stream.interruptions += 1

        if previous_delta is not None:
            jitter = abs(arrival_delta - previous_delta)
            stream.jitter_samples.append(jitter)
            if jitter > stream.max_jitter:
                stream.max_jitter = jitter

        previous_delta = arrival_delta
        previous_packet = packet
