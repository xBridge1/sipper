from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

from ciper.detectors.tls import detect_tls_fatal_alerts, detect_tls_malformed_records
from ciper.detectors.rtp import detect_rtp_one_way_audio
from ciper.detectors.udp import detect_udp_no_response
from ciper.engine import analyze_pcap
from ciper.flows import build_tcp_flows
from ciper.rtp import build_rtp_streams, parse_rtp_packet
from ciper.sip import build_sip_flows, parse_sip_message
from ciper.tls import build_tls_flows
from ciper.udp_flows import build_udp_flows


def _tls_record(content_type, payload, version=b"\x03\x03"):
    return bytes([content_type]) + version + len(payload).to_bytes(2, "big") + payload


def _tls_handshake(handshake_type, body=b"\x03\x03"):
    return bytes([handshake_type]) + len(body).to_bytes(3, "big") + body


def _sip_invite(call_id, extra_headers=b"", body=b""):
    return (
        b"INVITE sip:100@example.test SIP/2.0\r\n"
        + f"Call-ID: {call_id}\r\n".encode()
        + b"CSeq: 1 INVITE\r\n"
        + extra_headers
        + f"Content-Length: {len(body)}\r\n\r\n".encode()
        + body
    )


def _rtp_packet(
    payload_type=0,
    marker=0,
    sequence=100,
    payload=b"\x00" * 160,
    source="10.0.0.1",
    destination="10.0.0.2",
    source_port=4000,
    destination_port=4002,
):
    header = bytes(
        [
            0x80,
            (marker << 7) | payload_type,
            (sequence >> 8) & 0xFF,
            sequence & 0xFF,
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
    return IP(src=source, dst=destination) / UDP(sport=source_port, dport=destination_port) / (header + payload)


def test_sip_parser_ignores_malformed_status_and_sdp_media_lines():
    malformed_status = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / b"SIP/2.0 ABC Bad\r\nCall-ID: bad-status\r\n\r\n"
    )
    malformed_sdp = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / _sip_invite("bad-sdp", body=b"v=0\r\nm=audio\r\nm=video 70000 RTP/AVP 96\r\n")
    )

    assert parse_sip_message(malformed_status) is None
    message = parse_sip_message(malformed_sdp)
    assert message is not None
    assert message.sdp_media == []


def test_sip_tcp_reassembly_orders_segments_and_ignores_retransmissions():
    message = _sip_invite("reassembled", body=b"v=0\r\nm=audio 4000 RTP/AVP 0\r\n")
    split_at = 45
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=5060, dport=5060, seq=100 + split_at)
        / message[split_at:],
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=5060, dport=5060, seq=100)
        / message[:split_at],
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=5060, dport=5060, seq=100 + split_at)
        / message[split_at:],
    ]

    flows = build_sip_flows(packets)

    assert len(flows) == 1
    flow = next(iter(flows.values()))
    assert flow.invites == 1
    assert flow.messages[0].sdp_media[0].port == 4000


def test_tls_reassembly_handles_out_of_order_tcp_segments_and_split_handshakes():
    handshake = _tls_handshake(1, b"\x03\x03\x01\x02")
    records = _tls_record(22, handshake[:5]) + _tls_record(22, handshake[5:])
    split_at = 9
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, seq=500 + split_at)
        / Raw(records[split_at:]),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, seq=500)
        / Raw(records[:split_at]),
    ]

    tls_flows = build_tls_flows(build_tcp_flows(packets))

    tls_flow = next(iter(tls_flows.values()))
    assert tls_flow.client_hello_count == 1


def test_tls_invalid_first_record_is_retained_for_detection():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, seq=1)
        / Raw(b"\xff\x03\x03\x00\x00"),
    ]

    tls_flows = build_tls_flows(build_tcp_flows(packets))
    findings = detect_tls_malformed_records(tls_flows)

    assert len(tls_flows) == 1
    assert [finding.type for finding in findings] == ["tls_malformed_record"]


def test_non_tls_tcp_payload_is_not_reported_as_a_malformed_tls_record():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80, seq=1)
        / Raw(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
    ]

    tls_flows = build_tls_flows(build_tcp_flows(packets))

    assert tls_flows == {}


def test_tls_alert_80_is_reported_as_internal_error():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, seq=1)
        / Raw(_tls_record(21, b"\x02\x50")),
    ]

    findings = detect_tls_fatal_alerts(build_tls_flows(build_tcp_flows(packets)))

    assert "Fatal alert: internal_error" in findings[0].evidence


def test_ipv6_tcp_udp_and_tls_flows_are_tracked():
    tls_packet = (
        IPv6(src="2001:db8::10", dst="2001:db8::20")
        / TCP(sport=50000, dport=443, seq=1)
        / Raw(_tls_record(22, _tls_handshake(1)))
    )
    udp_packet = (
        IPv6(src="2001:db8::10", dst="2001:db8::20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO"
    )

    tcp_flows = build_tcp_flows([tls_packet])
    udp_flows = build_udp_flows([udp_packet])

    assert len(tcp_flows) == 1
    assert len(build_tls_flows(tcp_flows)) == 1
    assert len(udp_flows) == 1


def test_ipv6_tcp_handshake_reset_is_reported_without_ipv4_assumptions():
    packets = [
        IPv6(src="2001:db8::10", dst="2001:db8::20")
        / TCP(sport=50000, dport=443, flags="S"),
        IPv6(src="2001:db8::20", dst="2001:db8::10")
        / TCP(sport=443, dport=50000, flags="RA"),
    ]

    result = analyze_pcap(packets)

    assert "tcp_handshake_reset" in {finding.type for finding in result["findings"]}


def test_ipv6_udp_no_response_is_detected():
    packet = (
        IPv6(src="2001:db8::10", dst="2001:db8::20")
        / UDP(sport=50000, dport=53)
        / b"query"
    )

    result = analyze_pcap([packet])

    assert "udp_no_response" in {finding.type for finding in result["findings"]}


def test_rtp_marker_payload_type_is_not_mistaken_for_rtcp():
    parsed = parse_rtp_packet(_rtp_packet(payload_type=72, marker=1))

    assert parsed is not None
    assert parsed.marker == 1
    assert parsed.payload_type == 72


def test_each_orphan_rtp_stream_is_reported_without_sip():
    first = _rtp_packet(sequence=100)
    second = _rtp_packet(sequence=200)
    second[UDP].sport = 5000
    second[UDP].dport = 5002

    result = analyze_pcap([first, second])

    assert sum(finding.type == "rtp_without_sip" for finding in result["findings"]) == 2


def test_unrelated_sip_flow_does_not_hide_orphan_rtp_stream():
    sip = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / _sip_invite("unrelated-sip")
    )
    rtp_packets = [
        _rtp_packet(source="10.0.0.1", destination="10.0.0.2", sequence=100),
        _rtp_packet(source="10.0.0.1", destination="10.0.0.2", sequence=101),
    ]

    result = analyze_pcap([sip, *rtp_packets])

    assert any(
        finding.type == "rtp_without_sip"
        and finding.source_ip == "10.0.0.1"
        and finding.destination_ip == "10.0.0.2"
        for finding in result["findings"]
    )


def test_opposite_rtp_on_another_port_pair_does_not_hide_one_way_audio():
    packets = [
        *[
            _rtp_packet(
                source="10.0.0.1",
                destination="10.0.0.2",
                source_port=4000,
                destination_port=4002,
                sequence=sequence,
            )
            for sequence in (100, 101, 102)
        ],
        *[
            _rtp_packet(
                source="10.0.0.2",
                destination="10.0.0.1",
                source_port=5002,
                destination_port=5000,
                sequence=sequence,
            )
            for sequence in (200, 201, 202)
        ],
    ]

    findings = detect_rtp_one_way_audio(build_rtp_streams(packets))

    assert any(
        finding.source_ip == "10.0.0.1"
        and "Source port: 4000" in finding.evidence
        for finding in findings
    )


def test_sip_forked_dialogs_are_not_merged_by_call_id():
    invite = _sip_invite("forked", b"From: <sip:a@example.test>;tag=caller\r\n")
    response_a = (
        b"SIP/2.0 200 OK\r\nCall-ID: forked\r\n"
        b"From: <sip:a@example.test>;tag=caller\r\n"
        b"To: <sip:b@example.test>;tag=branch-a\r\nCSeq: 1 INVITE\r\n\r\n"
    )
    response_b = response_a.replace(b"branch-a", b"branch-b")
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5060, dport=5060) / invite,
        IP(src="192.168.1.20", dst="192.168.1.10") / UDP(sport=5060, dport=5060) / response_a,
        IP(src="192.168.1.30", dst="192.168.1.10") / UDP(sport=5060, dport=5060) / response_b,
    ]

    flows = build_sip_flows(packets)

    assert len(flows) == 2
    assert all(flow.invites == 1 for flow in flows.values())


def test_call_media_correlation_uses_the_sdp_media_port():
    first_call = _sip_invite(
        "media-a",
        body=b"v=0\r\nc=IN IP4 192.168.1.10\r\nm=audio 4000 RTP/AVP 0\r\n",
    )
    second_call = _sip_invite(
        "media-b",
        body=b"v=0\r\nc=IN IP4 192.168.1.10\r\nm=audio 5000 RTP/AVP 0\r\n",
    )
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5060, dport=5060) / first_call,
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5062, dport=5060) / second_call,
        _rtp_packet(
            source="192.168.1.10",
            destination="192.168.1.20",
            source_port=4000,
            destination_port=4002,
        ),
    ]

    summaries = {summary["call_id"]: summary for summary in analyze_pcap(packets)["call_summaries"]}

    assert summaries["media-a"]["rtp_stream_count"] == 1
    assert summaries["media-b"]["rtp_stream_count"] == 0


def test_udp_ack_without_response_does_not_raise_request_alert():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"ACK sip:100@example.test SIP/2.0\r\nCall-ID: ack-only\r\n\r\n",
    ]

    findings = detect_udp_no_response(build_udp_flows(packets))

    assert findings == []


def test_rtp_after_bye_ignores_unrelated_media_streams():
    invite = _sip_invite(
        "bye-related",
        body=b"v=0\r\nc=IN IP4 192.168.1.10\r\nm=audio 4000 RTP/AVP 0\r\n",
    )
    ok = (
        b"SIP/2.0 200 OK\r\nCall-ID: bye-related\r\nCSeq: 1 INVITE\r\n"
        b"Content-Length: 50\r\n\r\nv=0\r\nc=IN IP4 192.168.1.20\r\nm=audio 4002 RTP/AVP 0\r\n"
    )
    bye = b"BYE sip:100@example.test SIP/2.0\r\nCall-ID: bye-related\r\nCSeq: 2 BYE\r\n\r\n"
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5060, dport=5060) / invite,
        IP(src="192.168.1.20", dst="192.168.1.10") / UDP(sport=5060, dport=5060) / ok,
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5060, dport=5060) / bye,
        _rtp_packet(),
    ]
    for index, packet in enumerate(packets):
        packet.time = float(index)

    result = analyze_pcap(packets)

    assert "rtp_after_bye" not in {finding.type for finding in result["findings"]}


def test_rtp_after_bye_allows_a_short_in_flight_packet_grace_period():
    invite = _sip_invite("bye-grace")
    ok = b"SIP/2.0 200 OK\r\nCall-ID: bye-grace\r\nCSeq: 1 INVITE\r\n\r\n"
    bye = b"BYE sip:100@example.test SIP/2.0\r\nCall-ID: bye-grace\r\nCSeq: 2 BYE\r\n\r\n"
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5060, dport=5060) / invite,
        IP(src="192.168.1.20", dst="192.168.1.10") / UDP(sport=5060, dport=5060) / ok,
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5060, dport=5060) / bye,
        _rtp_packet(source="192.168.1.10", destination="192.168.1.20"),
    ]
    for packet, timestamp in zip(packets, (1.0, 1.1, 2.0, 2.05)):
        packet.time = timestamp

    result = analyze_pcap(packets)

    assert "rtp_after_bye" not in {finding.type for finding in result["findings"]}
