from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from ciper.detectors.tls import detect_tls_weak_cipher_suites
from ciper.engine import analyze_pcap
from ciper.flows import build_tcp_flows
from ciper.rtp import build_rtp_streams
from ciper.tls import build_tls_flows
from ciper.voip_quality import estimate_mos


def _rtp_packet(sequence, timestamp, packet_time):
    header = bytes(
        [
            0x80,
            0,
            (sequence >> 8) & 0xFF,
            sequence & 0xFF,
            (timestamp >> 24) & 0xFF,
            (timestamp >> 16) & 0xFF,
            (timestamp >> 8) & 0xFF,
            timestamp & 0xFF,
            0,
            0,
            4,
            210,
        ]
    )
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=4000, dport=4002) / (header + b"\x00" * 160)
    packet.time = packet_time
    return packet


def _tls_record(content_type, payload):
    return bytes([content_type]) + b"\x03\x03" + len(payload).to_bytes(2, "big") + payload


def _client_hello_with_sni_and_weak_cipher():
    server_name = b"pbx.example.test"
    name_list = b"\x00" + len(server_name).to_bytes(2, "big") + server_name
    sni_data = len(name_list).to_bytes(2, "big") + name_list
    sni = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
    versions = b"\x00\x2b\x00\x05\x04\x03\x03\x03\x04"
    extensions = sni + versions
    return (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x04\x00\x05\x13\x01"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )


def test_rtp_jitter_uses_rtp_timestamp_clock_rate():
    stream = next(
        iter(
            build_rtp_streams(
                [
                    _rtp_packet(100, 0, 100.00),
                    _rtp_packet(101, 160, 100.02),
                    _rtp_packet(102, 320, 100.10),
                ]
            ).values()
        )
    )

    assert stream.clock_rate == 8000
    assert round(stream.rfc_jitter, 5) == 0.00375
    assert round(stream.max_jitter, 5) == 0.00375
    assert round(stream.peak_transit_variation, 3) == 0.060


def test_mos_estimate_declines_with_loss_and_jitter():
    good = estimate_mos(0.0, 0.005, "PCMA")
    poor = estimate_mos(5.0, 0.120, "PCMA")

    assert 4.0 <= good <= 4.5
    assert 1.0 <= poor < good


def test_tls_extracts_sni_versions_ciphers_and_reports_weak_cipher_offer():
    hello = _client_hello_with_sni_and_weak_cipher()
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, seq=1)
        / Raw(_tls_record(22, handshake))
    )

    flow = next(iter(build_tls_flows(build_tcp_flows([packet])).values()))
    findings = detect_tls_weak_cipher_suites({"flow": flow})

    assert flow.server_names == {"pbx.example.test"}
    assert "TLS 1.3" in flow.offered_versions
    assert 0x0005 in flow.offered_cipher_suites
    assert [finding.type for finding in findings] == ["tls_weak_cipher_suite"]


def test_engine_detects_sip_register_and_transfer_failures():
    register = (
        b"REGISTER sip:pbx.example.test SIP/2.0\r\n"
        b"Call-ID: register-failure\r\nCSeq: 1 REGISTER\r\n\r\n"
    )
    register_error = (
        b"SIP/2.0 403 Forbidden\r\n"
        b"Call-ID: register-failure\r\nCSeq: 1 REGISTER\r\n\r\n"
    )
    refer = (
        b"REFER sip:200@example.test SIP/2.0\r\n"
        b"Call-ID: transfer-failure\r\nCSeq: 1 REFER\r\n\r\n"
    )
    refer_error = (
        b"SIP/2.0 603 Decline\r\n"
        b"Call-ID: transfer-failure\r\nCSeq: 1 REFER\r\n\r\n"
    )
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5060, dport=5060) / register,
        IP(src="192.168.1.20", dst="192.168.1.10") / UDP(sport=5060, dport=5060) / register_error,
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5060, dport=5060) / refer,
        IP(src="192.168.1.20", dst="192.168.1.10") / UDP(sport=5060, dport=5060) / refer_error,
    ]

    finding_types = {finding.type for finding in analyze_pcap(packets)["findings"]}

    assert "sip_register_failure" in finding_types
    assert "sip_transfer_failure" in finding_types


def test_call_summary_reports_hold_resume_operations():
    offer = (
        b"INVITE sip:200@example.test SIP/2.0\r\nCall-ID: hold-resume\r\nCSeq: 1 INVITE\r\n\r\n"
        b"v=0\r\nm=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n"
    )
    hold = (
        b"INVITE sip:200@example.test SIP/2.0\r\nCall-ID: hold-resume\r\nCSeq: 2 INVITE\r\n\r\n"
        b"v=0\r\nm=audio 4000 RTP/AVP 0\r\na=sendonly\r\n"
    )
    resume = (
        b"INVITE sip:200@example.test SIP/2.0\r\nCall-ID: hold-resume\r\nCSeq: 3 INVITE\r\n\r\n"
        b"v=0\r\nm=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n"
    )
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5060, dport=5060) / offer,
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5060, dport=5060) / hold,
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5060, dport=5060) / resume,
    ]

    summary = analyze_pcap(packets)["call_summaries"][0]

    assert summary["signaling_operations"]["reinvites"] == 2
    assert summary["signaling_operations"]["holds"] == 1
    assert summary["signaling_operations"]["resumes"] == 1
    assert summary["media_quality_metrics"]["mos_estimate"] is None


def test_engine_consumes_packet_generators_without_eager_copy():
    consumed = []

    def packets():
        for index in range(3):
            consumed.append(index)
            yield IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=50000, dport=5060) / b"HELLO"

    result = analyze_pcap(packets())

    assert consumed == [0, 1, 2]
    assert result["analysis_stats"]["packet_count"] == 3
