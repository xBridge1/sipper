import pytest

from scapy.layers.inet import IP, UDP

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
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 102, 480, 1234),
    ]

    result = analyze_pcap(packets)
    assert "rtp_packet_loss" in {f.type for f in result["findings"]}


def test_engine_applies_rtp_loss_severity_setting():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 320, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 103, 640, 1234),
    ]

    result = analyze_pcap(packets, AnalysisSettings(rtp_loss_high_threshold=3))
    finding = next(finding for finding in result["findings"] if finding.type == "rtp_packet_loss")

    assert finding.severity == "medium"


def test_engine_detects_rtp_out_of_order():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 99, 320, 1234),
    ]

    result = analyze_pcap(packets)
    assert "rtp_out_of_order" in {f.type for f in result["findings"]}


def test_engine_detects_rtp_jitter():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 320, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 102, 480, 1234),
    ]
    packets[0].time = 100.0
    packets[1].time = 100.02
    packets[2].time = 100.10

    result = analyze_pcap(packets)
    assert "rtp_high_jitter" in {f.type for f in result["findings"]}


def test_engine_detects_rtp_payload_type_change_and_ssrc_change():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 1234, payload_type=0),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 320, 1234, payload_type=8),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 102, 480, 9999, payload_type=8),
    ]

    result = analyze_pcap(packets)
    types = {f.type for f in result["findings"]}

    assert "rtp_payload_type_change" in types
    assert "rtp_ssrc_change" in types


def test_engine_detects_rtp_timestamp_anomaly_and_stream_interruption():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 160, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 102, 320, 1234),
    ]
    packets[0].time = 100.0
    packets[1].time = 100.02
    packets[2].time = 102.5

    result = analyze_pcap(packets)
    types = {f.type for f in result["findings"]}

    assert "rtp_timestamp_anomaly" in types
    assert "rtp_stream_interruption" in types


def test_engine_detects_probable_one_way_audio():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 320, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 102, 480, 1234),
    ]
    packets[0].time = 100.0
    packets[1].time = 100.02
    packets[2].time = 100.04

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
        make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 100, 160, 1234),
        make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 101, 320, 1234),
        make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 102, 480, 1234),
    ]

    result = analyze_pcap(packets)
    assert "sip_call_one_way_audio" in {f.type for f in result["findings"]}


def test_engine_detects_rtp_without_sip():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 160, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 320, 1234),
    ]

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
