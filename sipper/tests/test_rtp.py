import pytest

from scapy.layers.inet import IP, UDP

from ciper.detectors.rtp import detect_rtp_payload_type_change, detect_rtp_ssrc_change
from ciper.engine import analyze_pcap
from ciper.rtp import build_rtp_streams, parse_rtp_packet
from ciper.settings import AnalysisSettings


def make_rtp_packet(
    src,
    dst,
    sport,
    dport,
    sequence,
    timestamp,
    ssrc,
    payload_type=0,
    marker=0,
    payload=b"\x00" * 160,
):
    first_byte = 0x80
    second_byte = (marker << 7) | (payload_type & 0x7F)
    header = bytes(
        [
            first_byte,
            second_byte,
            (sequence >> 8) & 0xFF,
            sequence & 0xFF,
            (timestamp >> 24) & 0xFF,
            (timestamp >> 16) & 0xFF,
            (timestamp >> 8) & 0xFF,
            timestamp & 0xFF,
            (ssrc >> 24) & 0xFF,
            (ssrc >> 16) & 0xFF,
            (ssrc >> 8) & 0xFF,
            ssrc & 0xFF,
        ]
    )
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / (header + payload)


def make_rtp_stream(
    src="10.0.0.1",
    dst="10.0.0.2",
    sport=4000,
    dport=4002,
    count=20,
    first_sequence=100,
    ssrc=1234,
    start_time=100.0,
    skip=(),
    payload_type=0,
):
    """A clean 20 ms G.711 stream; ``skip`` drops sequence offsets (loss)."""
    packets = []
    for index in range(count):
        if index in skip:
            continue
        packet = make_rtp_packet(
            src, dst, sport, dport, first_sequence + index, 160 * (index + 1), ssrc, payload_type=payload_type
        )
        if start_time is not None:
            packet.time = start_time + index * 0.02
        packets.append(packet)
    return packets


def test_parse_rtp_packet():
    packet = make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 1234)

    parsed = parse_rtp_packet(packet)

    assert parsed is not None
    assert parsed.sequence == 100
    assert parsed.timestamp == 160
    assert parsed.ssrc == 1234
    assert parsed.payload_type == 0


def test_parse_rtp_packet_accepts_dynamic_payload_type():
    packet = make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 1234, payload_type=111)

    parsed = parse_rtp_packet(packet)

    assert parsed is not None
    assert parsed.payload_type == 111


def test_parse_rtp_packet_ignores_rtcp_packets():
    rtcp_sender_report = b"\x80\xc8" + (b"\x00" * 26)
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=4001, dport=4003) / rtcp_sender_report

    assert parse_rtp_packet(packet) is None


def test_parse_rtp_packet_handles_csrc_extension_and_padding():
    header = bytes(
        [
            0xB1,
            0x80,
            0,
            100,
            0,
            0,
            0,
            160,
            0,
            0,
            4,
            210,
        ]
    )
    csrc = b"\x00\x00\x00\x01"
    extension = b"\xBE\xDE\x00\x01\x00\x00\x00\x00"
    payload = b"DATA"
    padding = b"\x04\x04\x04\x04"
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=4000, dport=4002) / (header + csrc + extension + payload + padding)

    parsed = parse_rtp_packet(packet)

    assert parsed is not None
    assert parsed.payload_length == 4


def test_build_rtp_streams_handles_sequence_and_timestamp_rollover():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 65535, 0xFFFFFF00, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 0, 160, 1234),
    ]

    stream = next(iter(build_rtp_streams(packets).values()))

    assert stream.lost_packets == 0
    assert stream.out_of_order_packets == 0
    assert stream.timestamp_anomalies == 0


def test_build_rtp_streams_groups_by_ssrc():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 320, 1234),
    ]
    packets[0].time = 100.0
    packets[1].time = 100.02

    streams = build_rtp_streams(packets)
    stream = next(iter(streams.values()))

    assert len(streams) == 1
    assert stream.ssrc == 1234
    assert stream.packet_count == 2
    assert stream.duration == pytest.approx(0.02)


def test_engine_detects_rtp_packet_loss():
    packets = make_rtp_stream(count=20, skip={5})

    result = analyze_pcap(packets)
    assert "rtp_packet_loss" in {f.type for f in result["findings"]}


def test_engine_applies_rtp_loss_severity_setting():
    packets = make_rtp_stream(count=20, skip={5, 9})

    default = analyze_pcap(packets)
    relaxed = analyze_pcap(packets, AnalysisSettings(rtp_loss_high_threshold=3))

    def loss(result):
        return next(finding for finding in result["findings"] if finding.type == "rtp_packet_loss")

    assert loss(default).severity == "high"
    assert loss(relaxed).severity == "medium"


def test_rtp_loss_severity_follows_percentage_not_raw_count():
    # 2 lost packets out of 1000 (0.2%) is noticeable, not critical.
    packets = make_rtp_stream(count=1000, skip={100, 600})

    finding = next(
        finding for finding in analyze_pcap(packets)["findings"] if finding.type == "rtp_packet_loss"
    )

    assert finding.severity == "medium"


def test_engine_detects_rtp_out_of_order():
    packets = make_rtp_stream(count=20)
    packets[5], packets[6] = packets[6], packets[5]

    result = analyze_pcap(packets)
    assert "rtp_out_of_order" in {f.type for f in result["findings"]}


def test_engine_detects_rtp_jitter():
    # Sustained jitter: every other packet arrives 60 ms late.
    packets = make_rtp_stream(count=60)
    for index, packet in enumerate(packets):
        if index % 2:
            packet.time += 0.06

    result = analyze_pcap(packets)
    assert "rtp_high_jitter" in {f.type for f in result["findings"]}


def test_single_late_packet_does_not_raise_high_jitter():
    packets = make_rtp_stream(count=60)
    packets[30].time += 0.14

    result = analyze_pcap(packets)
    assert "rtp_high_jitter" not in {f.type for f in result["findings"]}


def test_engine_detects_rtp_payload_type_change_and_ssrc_change():
    packets = [
        *make_rtp_stream(count=10, payload_type=0),
        *make_rtp_stream(count=10, first_sequence=110, payload_type=8, start_time=100.2),
        *make_rtp_stream(count=12, ssrc=9999, payload_type=8, start_time=100.4),
    ]
    # PT 0 and PT 8 share SSRC 1234: shift the second half's timestamps on.
    for index, packet in enumerate(packets[10:20]):
        packet[UDP].payload.load = packet[UDP].payload.load[:4] + (160 * (index + 11)).to_bytes(4, "big") + packet[UDP].payload.load[8:]

    result = analyze_pcap(packets)
    types = {f.type for f in result["findings"]}

    assert "rtp_payload_type_change" in types
    assert "rtp_ssrc_change" in types


def test_sequential_calls_reusing_media_path_do_not_raise_rtp_change_alerts():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 1111, payload_type=0),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 320, 1111, payload_type=0),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 2222, payload_type=8),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 320, 2222, payload_type=8),
    ]
    for packet, timestamp in zip(packets, (1.0, 1.02, 10.0, 10.02)):
        packet.time = timestamp

    streams = build_rtp_streams(packets)

    assert detect_rtp_payload_type_change(streams) == []
    assert detect_rtp_ssrc_change(streams) == []


def test_engine_detects_rtp_timestamp_anomaly_and_stream_interruption():
    packets = make_rtp_stream(count=20)
    # Repeated timestamp on packet 3, then a 2.5 s stall with contiguous
    # sequence numbers but no RTP clock advance: not silence suppression.
    packets[3] = make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 103, 160 * 3, 1234)
    packets[3].time = 100.06
    for packet in packets[10:]:
        packet.time += 2.5

    result = analyze_pcap(packets)
    types = {f.type for f in result["findings"]}

    assert "rtp_timestamp_anomaly" in types
    assert "rtp_stream_interruption" in types


def test_engine_detects_probable_one_way_audio():
    packets = make_rtp_stream(count=20)

    result = analyze_pcap(packets)
    assert "rtp_one_way_audio" in {f.type for f in result["findings"]}


def test_engine_detects_sip_established_without_rtp():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-no-rtp\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: call-no-rtp\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"ACK sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-no-rtp\r\n"
            b"CSeq: 1 ACK\r\n\r\n"
        ),
    ]

    result = analyze_pcap(packets)
    assert "sip_call_established_without_rtp" in {f.type for f in result["findings"]}


def test_engine_detects_sip_call_with_one_way_audio():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-one-way\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: call-one-way\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"ACK sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-one-way\r\n"
            b"CSeq: 1 ACK\r\n\r\n"
        ),
        *make_rtp_stream("192.168.1.10", "192.168.1.20", count=20, start_time=None),
    ]

    result = analyze_pcap(packets)
    assert "sip_call_one_way_audio" in {f.type for f in result["findings"]}


def test_engine_detects_rtp_without_sip():
    packets = make_rtp_stream(count=20)

    result = analyze_pcap(packets)
    assert "rtp_without_sip" in {f.type for f in result["findings"]}


def test_engine_detects_rtp_after_bye():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-bye-media\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: call-bye-media\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"ACK sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-bye-media\r\n"
            b"CSeq: 1 ACK\r\n\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"BYE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-bye-media\r\n"
            b"CSeq: 2 BYE\r\n\r\n"
        ),
        make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 100, 160, 1234),
    ]
    packets[0].time = 100.0
    packets[1].time = 100.1
    packets[2].time = 100.2
    packets[3].time = 100.3
    packets[4].time = 101.0

    result = analyze_pcap(packets)
    assert "rtp_after_bye" in {f.type for f in result["findings"]}


def test_comfort_noise_and_silence_suppression_are_not_media_problems():
    # PCMA with VAD: a CN packet, a 3.4 s pause with contiguous sequence numbers,
    # then the next talkspurt with the marker bit set (as in RTP-Protocol.pcap).
    packets = make_rtp_stream(count=20, payload_type=8)
    cn = make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 120, 160 * 21, 1234, payload_type=13, payload=b"\x40")
    cn.time = 100.40
    resumed = []
    for index in range(20):
        packet = make_rtp_packet(
            "10.0.0.1", "10.0.0.2", 4000, 4002, 121 + index, 160 * 21 + 27680 + 160 * index, 1234,
            payload_type=8, marker=1 if index == 0 else 0,
        )
        packet.time = 103.86 + index * 0.02
        resumed.append(packet)

    streams = build_rtp_streams([*packets, cn, *resumed])
    stream = next(iter(streams.values()))

    assert stream.interruptions == 0
    assert stream.silence_periods == 1
    assert stream.media_payload_types == {8}
    assert detect_rtp_payload_type_change(streams) == []


def test_dtmf_events_do_not_count_as_codec_change_or_timestamp_anomaly():
    packets = make_rtp_stream(count=20)
    # RFC 4733: event packets repeat the event start timestamp, 4-byte payload.
    for index in range(4):
        event = make_rtp_packet(
            "10.0.0.1", "10.0.0.2", 4000, 4002, 120 + index, 160 * 21, 1234,
            payload_type=101, payload=b"\x01\x0a\x00\xa0",
        )
        event.time = 100.40 + index * 0.02
        packets.append(event)

    stream = next(iter(build_rtp_streams(packets).values()))

    assert stream.auxiliary_payload_types == {101}
    assert stream.timestamp_anomalies == 0
    assert detect_rtp_payload_type_change({1: stream}) == []


def test_short_unannounced_udp_flow_is_not_treated_as_rtp():
    packets = make_rtp_stream(count=5)

    result = analyze_pcap(packets)

    assert result["rtp_streams"] == {}
    assert "rtp_without_sip" not in {f.type for f in result["findings"]}


def test_sequence_resync_is_not_reported_as_massive_loss():
    packets = [
        *make_rtp_stream(count=20),
        *make_rtp_stream(count=20, first_sequence=40000, start_time=100.4),
    ]
    for index, packet in enumerate(packets[20:]):
        packet[UDP].payload.load = packet[UDP].payload.load[:4] + (160 * (index + 21)).to_bytes(4, "big") + packet[UDP].payload.load[8:]

    stream = next(iter(build_rtp_streams(packets).values()))

    assert stream.sequence_resets == 1
    assert stream.lost_packets == 0
