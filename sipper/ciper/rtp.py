from dataclasses import dataclass, field

from ciper.packets import _UNSET, ensure_decoded


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

# Payloads that are not continuous audio: comfort noise (RFC 3389) and named
# telephone events / DTMF (RFC 4733). They must not count as codec changes,
# timestamp anomalies or jitter samples.
RTP_COMFORT_NOISE_PAYLOAD_TYPE = 13
AUXILIARY_CODEC_NAMES = {"cn", "telephone-event", "comfort-noise"}
TELEPHONE_EVENT_PAYLOAD_LENGTH = 4

# Arrival gaps above this are either silence suppression or an interruption.
RTP_GAP_SECONDS = 1.0
# RFC 3550 appendix A.1: a jump above this is a sequence resync, not loss.
RTP_MAX_DROPOUT = 3000
RTP_MAX_MISORDER = 100
# Candidate streams not announced in SDP need this many packets to be trusted.
RTP_MIN_UNANNOUNCED_PACKETS = 10


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
    duplicate_packets: int = 0
    unique_packet_count: int = 0
    loss_observed_packet_count: int = 0
    timestamp_anomalies: int = 0
    interruptions: int = 0
    max_jitter: float = 0.0
    jitter_samples: list[float] = field(default_factory=list)
    payload_types: set[int] = field(default_factory=set)
    clock_rate: int = RTP_DEFAULT_CLOCK_RATE
    rfc_jitter: float = 0.0
    max_transit_variation: float = 0.0
    max_jitter_pair: tuple[RTPPacket, RTPPacket] | None = None
    auxiliary_payload_types: set[int] = field(default_factory=set)
    silence_periods: int = 0
    longest_gap: float = 0.0
    longest_interruption: float = 0.0
    sequence_resets: int = 0
    media_packet_count: int = 0
    announced: bool = False
    # (arrival time, RFC 3550 jitter) per media packet and (arrival time,
    # missing packets) per sequence gap, for timeline charts.
    jitter_series: list[tuple[float, float]] = field(default_factory=list)
    loss_events: list[tuple[float, int]] = field(default_factory=list)

    @property
    def media_payload_types(self):
        return self.payload_types - self.auxiliary_payload_types

    @property
    def peak_transit_variation(self):
        return self.max_transit_variation

    @property
    def expected_packets(self):
        observed = self.loss_observed_packet_count or self.unique_packet_count or self.packet_count
        return observed + self.lost_packets

    @property
    def loss_percent(self):
        expected = self.expected_packets
        return self.lost_packets / expected * 100 if expected else 0.0

    @property
    def duration(self):
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return self.last_timestamp - self.first_timestamp

    @property
    def codec_guesses(self):
        guesses = []

        for payload_type in sorted(self.media_payload_types or self.payload_types):
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
    packet = ensure_decoded(packet)
    cached = packet._rtp
    if cached is not _UNSET:
        return cached
    parsed = _parse_rtp(packet)
    packet._rtp = parsed
    return parsed


def _parse_rtp(packet):
    if not packet.ip_version or packet.transport != "UDP":
        return None

    payload = packet.payload

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

    return RTPPacket(
        source_ip=packet.src,
        destination_ip=packet.dst,
        source_port=packet.sport,
        destination_port=packet.dport,
        sequence=sequence,
        timestamp=timestamp,
        ssrc=ssrc,
        payload_type=payload_type,
        marker=(payload[1] >> 7) & 0x01,
        payload_length=len(payload) - header_length - padding_length,
        packet_time=packet.time,
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


def build_rtp_streams(packets, clock_rates=None, payload_names=None):
    """Group RTP packets by (path, SSRC) and compute per-stream statistics.

    ``clock_rates`` and ``payload_names`` come from SDP and are keyed by
    ``(address, port, payload_type)``.
    """
    streams = {}
    clock_rates = clock_rates or {}
    payload_names = payload_names or {}

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
        stream.auxiliary_payload_types = _auxiliary_payload_types(stream, payload_names)
        _finalize_stream(stream, clock_rates)

    return streams


def filter_rtp_candidates(
    streams,
    announced_endpoints=(),
    signaled_host_pairs=(),
    min_packets=RTP_MIN_UNANNOUNCED_PACKETS,
):
    """Drop UDP flows that only look like RTP by accident.

    Any UDP payload whose first byte is 0x80 parses as RTP version 2, so short
    or incoherent flows are kept only when SDP announced one of their ports or
    a SIP dialog exists between the same two hosts.
    """
    announced_endpoints = set(announced_endpoints)
    signaled_host_pairs = set(signaled_host_pairs)
    kept = {}
    for key, stream in streams.items():
        announced = (
            (stream.source_ip, stream.source_port) in announced_endpoints
            or (stream.destination_ip, stream.destination_port) in announced_endpoints
        )
        stream.announced = announced
        signaled = frozenset((stream.source_ip, stream.destination_ip)) in signaled_host_pairs
        if announced or signaled or _looks_like_real_rtp(stream, min_packets):
            kept[key] = stream
    return kept


def _looks_like_real_rtp(stream, min_packets):
    if stream.packet_count < min_packets:
        return False
    if stream.sequence_resets * 4 > stream.packet_count:
        return False
    if len(stream.media_payload_types) > 3:
        return False
    comparable = max(1, stream.media_packet_count - 1)
    return stream.timestamp_anomalies * 2 <= comparable


def _auxiliary_payload_types(stream, payload_names):
    auxiliary = set()
    lengths = {}
    for packet in stream.packets:
        lengths.setdefault(packet.payload_type, set()).add(packet.payload_length)

    for payload_type, observed_lengths in lengths.items():
        if payload_type == RTP_COMFORT_NOISE_PAYLOAD_TYPE:
            auxiliary.add(payload_type)
            continue
        name = _payload_name(stream, payload_type, payload_names)
        if name is not None:
            if name.lower() in AUXILIARY_CODEC_NAMES:
                auxiliary.add(payload_type)
            continue
        # Unnamed dynamic payload whose packets all carry a 4-byte RFC 4733
        # event block: almost certainly DTMF.
        if 96 <= payload_type <= 127 and observed_lengths == {TELEPHONE_EVENT_PAYLOAD_LENGTH}:
            auxiliary.add(payload_type)
    return auxiliary


def _payload_name(stream, payload_type, payload_names):
    return _resolve_payload_name(
        payload_names.get((stream.source_ip, stream.source_port, payload_type))
    ) or _resolve_payload_name(
        payload_names.get((stream.destination_ip, stream.destination_port, payload_type))
    )


def _resolve_payload_name(value):
    if isinstance(value, str) or value is None:
        return value
    # SDP history: [(effective_time, name), ...]; the latest offer wins.
    return max(value, key=lambda item: item[0])[1] if value else None


def _finalize_stream(stream, clock_rates):
    auxiliary = stream.auxiliary_payload_types
    previous_arrival = None
    previous_extended = None
    previous_media = None
    previous_clock_rate = None
    jitter_units = 0.0
    seen_sequences = set()
    highest_sequence = None
    window_base = None
    window_seen = 0
    lost_packets = 0
    observed_in_windows = 0

    for packet in stream.packets:
        clock_rate = _get_clock_rate(packet, clock_rates)
        is_media = packet.payload_type not in auxiliary
        if is_media:
            stream.clock_rate = clock_rate

        extended_sequence, resync = _classify_sequence(packet.sequence, highest_sequence)
        if extended_sequence in seen_sequences:
            stream.duplicate_packets += 1
            continue

        if resync:
            # Sequence resync (endpoint restart, SBC splice): close the loss
            # window instead of reporting thousands of lost packets.
            stream.sequence_resets += 1
            lost_packets += max(0, highest_sequence - window_base + 1 - window_seen)
            observed_in_windows += window_seen
            window_base = extended_sequence
            window_seen = 0
            highest_sequence = None
            previous_media = None
            previous_extended = None

        seen_sequences.add(extended_sequence)
        if window_base is None:
            window_base = extended_sequence
        if extended_sequence >= window_base:
            window_seen += 1

        if highest_sequence is not None and extended_sequence < highest_sequence:
            stream.out_of_order_packets += 1
            continue

        if highest_sequence is not None and extended_sequence > highest_sequence + 1:
            stream.loss_events.append((packet.packet_time, extended_sequence - highest_sequence - 1))
        highest_sequence = extended_sequence

        if previous_arrival is not None:
            gap = packet.packet_time - previous_arrival.packet_time
            if gap > RTP_GAP_SECONDS:
                stream.longest_gap = max(stream.longest_gap, gap)
                if _is_silence_gap(packet, previous_arrival, extended_sequence, previous_extended, gap, clock_rate, auxiliary):
                    stream.silence_periods += 1
                else:
                    stream.interruptions += 1
                    stream.longest_interruption = max(stream.longest_interruption, gap)
        previous_arrival = packet
        previous_extended = extended_sequence

        if not is_media:
            continue
        stream.media_packet_count += 1

        if previous_media is None or clock_rate != previous_clock_rate:
            previous_media = packet
            previous_clock_rate = clock_rate
            continue

        timestamp_delta = (packet.timestamp - previous_media.timestamp) & 0xFFFFFFFF
        if timestamp_delta == 0 or timestamp_delta > 0x7FFFFFFF:
            stream.timestamp_anomalies += 1

        arrival_delta = packet.packet_time - previous_media.packet_time
        signed_timestamp_delta = timestamp_delta if timestamp_delta <= 0x7FFFFFFF else timestamp_delta - 0x100000000
        arrival_units = arrival_delta * clock_rate
        transit_variation = abs(arrival_units - signed_timestamp_delta)
        jitter_units += (transit_variation - jitter_units) / 16
        rfc_jitter_seconds = jitter_units / clock_rate
        transit_variation_seconds = transit_variation / clock_rate
        stream.jitter_samples.append(rfc_jitter_seconds)
        stream.jitter_series.append((packet.packet_time, rfc_jitter_seconds))
        stream.rfc_jitter = rfc_jitter_seconds
        # max_jitter is the worst smoothed RFC 3550 jitter; a single delayed
        # packet only moves it by 1/16 of its transit variation.
        stream.max_jitter = max(stream.max_jitter, rfc_jitter_seconds)
        if transit_variation_seconds > stream.max_transit_variation:
            stream.max_transit_variation = transit_variation_seconds
            stream.max_jitter_pair = (previous_media, packet)

        previous_media = packet
        previous_clock_rate = clock_rate

    stream.unique_packet_count = len(seen_sequences)
    if highest_sequence is not None and window_base is not None:
        lost_packets += max(0, highest_sequence - window_base + 1 - window_seen)
        observed_in_windows += window_seen
    stream.loss_observed_packet_count = observed_in_windows
    stream.lost_packets = lost_packets


def _classify_sequence(sequence, highest_sequence):
    """Extend a 16-bit sequence number as in RFC 3550 appendix A.1.

    Returns (extended_sequence, resync). Forward jumps below MAX_DROPOUT are
    normal progress (with loss), small backward steps are reordering, and
    anything else is a source resync rather than 30000 lost packets.
    """
    if highest_sequence is None:
        return sequence, False
    delta = (sequence - highest_sequence) & 0xFFFF
    if delta < RTP_MAX_DROPOUT:
        return highest_sequence + delta, False
    if delta > 0x10000 - RTP_MAX_MISORDER:
        return highest_sequence - (0x10000 - delta), False
    return highest_sequence + delta, True


def _is_silence_gap(packet, previous, extended_sequence, previous_extended, gap, clock_rate, auxiliary):
    """True when a long arrival gap is silence suppression, not a stall.

    With VAD the sender stops transmitting but keeps its sequence numbers
    contiguous, usually announces the pause with comfort noise and marks the
    first packet of the next talkspurt. Its RTP clock keeps running, so the
    timestamp advances by roughly the same time as the arrival gap.
    """
    if previous_extended is None or extended_sequence != previous_extended + 1:
        return False
    if previous.payload_type in auxiliary or packet.marker:
        return True
    timestamp_delta = (packet.timestamp - previous.timestamp) & 0xFFFFFFFF
    if timestamp_delta > 0x7FFFFFFF:
        return False
    media_gap = timestamp_delta / clock_rate
    return abs(media_gap - gap) <= max(0.2, gap * 0.25)


def _get_clock_rate(packet, clock_rates):
    return (
        _resolve_clock_rate(
            clock_rates.get((packet.source_ip, packet.source_port, packet.payload_type)),
            packet.packet_time,
        )
        or _resolve_clock_rate(
            clock_rates.get((packet.destination_ip, packet.destination_port, packet.payload_type)),
            packet.packet_time,
        )
        or RTP_CLOCK_RATES.get(packet.payload_type, RTP_DEFAULT_CLOCK_RATE)
    )


def _resolve_clock_rate(value, packet_time):
    if isinstance(value, (int, float)):
        return int(value)
    if not value:
        return None

    eligible = [
        (effective_time, clock_rate)
        for effective_time, clock_rate in value
        if effective_time <= float(packet_time)
    ]
    if not eligible:
        return None
    return max(eligible, key=lambda item: item[0])[1]
