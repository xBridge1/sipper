from dataclasses import dataclass, field

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw


RTP_PAYLOAD_TYPE_NAMES = {
    0: "PCMU",
    2: "G721",
    3: "GSM",
    4: "G723",
    5: "DVI4/8000",
    6: "DVI4/16000",
    7: "LPC",
    8: "PCMA",
    9: "G722",
    10: "L16/44100",
    11: "L16/44100 stereo",
    12: "QCELP",
    13: "CN",
    14: "MPA",
    15: "G728",
    16: "DVI4/11025",
    17: "DVI4/22050",
    18: "G729",
}

RTP_CLOCK_RATES = {
    0: 8000,
    2: 8000,
    3: 8000,
    4: 8000,
    5: 8000,
    6: 16000,
    7: 8000,
    8: 8000,
    9: 8000,
    10: 44100,
    11: 44100,
    12: 8000,
    13: 8000,
    14: 90000,
    15: 8000,
    16: 11025,
    17: 22050,
    18: 8000,
}
RTP_DEFAULT_CLOCK_RATE = 8000


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
    clock_rate: int = RTP_DEFAULT_CLOCK_RATE
    rfc_jitter: float = 0.0
    max_transit_variation: float = 0.0

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

    if _is_rtcp_packet(payload):
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


def _is_rtcp_packet(payload):
    packet_type = payload[1]
    minimum_lengths = {
        200: 28,
        201: 8,
        202: 4,
        203: 4,
        204: 8,
        205: 12,
        206: 12,
        207: 8,
    }

    if packet_type not in minimum_lengths or len(payload) < minimum_lengths[packet_type]:
        return False

    if payload[2:] == b"\x00" * (len(payload) - 2):
        return True

    offset = 0
    while offset < len(payload):
        if len(payload) - offset < 4 or payload[offset] >> 6 != 2:
            return False
        current_type = payload[offset + 1]
        if current_type not in minimum_lengths:
            return False
        record_length = ((payload[offset + 2] << 8) | payload[offset + 3]) + 1
        record_length *= 4
        if record_length < minimum_lengths[current_type] or offset + record_length > len(payload):
            return False
        offset += record_length

    return offset == len(payload)


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
    previous_transit = None
    jitter_units = 0.0

    for packet in stream.packets:
        clock_rate = RTP_CLOCK_RATES.get(packet.payload_type, RTP_DEFAULT_CLOCK_RATE)
        stream.clock_rate = clock_rate

        if previous_packet is None:
            previous_packet = packet
            previous_transit = packet.packet_time * clock_rate - packet.timestamp
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

        transit = packet.packet_time * clock_rate - packet.timestamp
        transit_variation = abs(transit - previous_transit)
        jitter_units += (transit_variation - jitter_units) / 16
        rfc_jitter_seconds = jitter_units / clock_rate
        transit_variation_seconds = transit_variation / clock_rate
        stream.jitter_samples.append(rfc_jitter_seconds)
        stream.rfc_jitter = rfc_jitter_seconds
        stream.max_transit_variation = max(stream.max_transit_variation, transit_variation_seconds)
        stream.max_jitter = max(stream.max_jitter, transit_variation_seconds)

        previous_transit = transit
        previous_packet = packet
