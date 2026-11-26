from scapy.layers.inet import IP, TCP, UDP

from ciper.engine import analyze_pcap
from ciper.settings import AnalysisSettings
from ciper.sip import parse_sip_message

CALLER = "198.51.100.10"
PBX = "10.0.0.20"

SDP = (
    b"v=0\r\n"
    b"o=- 1 1 IN IP4 198.51.100.10\r\n"
    b"s=-\r\n"
    b"c=IN IP4 198.51.100.10\r\n"
    b"t=0 0\r\n"
    b"m=audio 4000 RTP/AVP 0 101\r\n"
    b"a=rtpmap:0 PCMU/8000\r\n"
    b"a=rtpmap:101 telephone-event/8000\r\n"
    b"a=sendrecv\r\n"
)


def _packet(payload, source=CALLER, destination=PBX, timestamp=1.0, transport="udp"):
    layer = TCP(sport=5060, dport=5060, flags="PA", seq=1) if transport == "tcp" else UDP(sport=5060, dport=5060)
    packet = IP(src=source, dst=destination) / layer / payload
    packet.time = timestamp
    return packet


def _invite(call_id="hygiene", extra=b"", start=b"INVITE sip:1000@10.0.0.20 SIP/2.0", headers=None, body=SDP):
    default = [
        b"Via: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-1",
        b"Max-Forwards: 70",
        b'From: "Alice" <sip:alice@198.51.100.10>;tag=from1',
        b"To: <sip:1000@10.0.0.20>",
        b"Call-ID: " + call_id.encode(),
        b"CSeq: 1 INVITE",
        b"Contact: <sip:alice@198.51.100.10:5060>",
        b"Content-Type: application/sdp",
    ]
    lines = headers if headers is not None else default
    head = b"\r\n".join([start, *lines]) + b"\r\n" + extra
    return head + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def _response(code, reason, call_id="hygiene", cseq=b"1 INVITE", to_tag=b";tag=to1", extra=b""):
    return (
        b"SIP/2.0 " + str(code).encode() + b" " + reason + b"\r\n"
        b"Via: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-1\r\n"
        b'From: "Alice" <sip:alice@198.51.100.10>;tag=from1\r\n'
        b"To: <sip:1000@10.0.0.20>" + to_tag + b"\r\n"
        b"Call-ID: " + call_id.encode() + b"\r\n"
        b"CSeq: " + cseq + b"\r\n" + extra + b"Content-Length: 0\r\n\r\n"
    )


def _types(result):
    return {finding.type for finding in result["findings"]}


def _finding(result, finding_type):
    return next(finding for finding in result["findings"] if finding.type == finding_type)


def test_clean_realistic_call_has_no_hygiene_findings():
    result = analyze_pcap(
        [
            _packet(_invite()),
            _packet(_response(100, b"Trying", to_tag=b""), PBX, CALLER, 1.01),
            _packet(
                _response(200, b"OK", extra=b"Contact: <sip:1000@10.0.0.20:5060>\r\n"),
                PBX,
                CALLER,
                1.5,
            ),
        ],
        AnalysisSettings(target_platform="freeswitch", target_platform_ips=PBX),
    )

    hygiene = {item for item in _types(result) if item.startswith(("sip_header_", "sip_sdp_", "sip_request_uri"))}
    assert hygiene == set()


def test_latin1_display_name_is_kept_and_reported():
    payload = _invite().replace(b'"Alice"', b'"Jo\xe3o"')
    message = parse_sip_message(_packet(payload))

    assert message is not None, "non UTF-8 messages must not be dropped"
    assert message.invalid_utf8_headers == ["from"]

    finding = _finding(analyze_pcap([_packet(payload)]), "sip_header_invalid_encoding")
    assert finding.severity == "high"
    assert finding.culprit_ip == CALLER
    assert any(line.startswith("From:") for line in finding.offending_lines)


def test_duplicate_header_rejected_with_400_is_confirmed_root_cause():
    invite = _invite(extra=b"Call-ID: other-copy\r\n")
    result = analyze_pcap(
        [
            _packet(invite),
            _packet(_response(400, b"Bad Request"), PBX, CALLER, 1.1),
        ]
    )

    finding = _finding(result, "sip_header_duplicate_singleton")
    assert finding.severity == "high"
    assert finding.confirmed_by == "400 Bad Request"
    assert "Call-ID" in " ".join(finding.evidence)

    verdict = result["call_summaries"][0]["verdict"]
    assert verdict["status"] == "fail"
    assert verdict["root_type"] == "sip_header_duplicate_singleton"
    assert verdict["culprit_ip"] == CALLER
    assert verdict["confirmed_by"] == "400 Bad Request"
    assert verdict["confidence_label"] == "Alta"
    assert result["diagnosis"]["root_type"] == "sip_header_duplicate_singleton"


def test_freeswitch_variable_expansion_in_header_is_flagged():
    result = analyze_pcap([_packet(_invite(extra=b"X-Customer: ${system(id)}\r\n"))])

    finding = _finding(result, "sip_header_variable_injection")
    assert finding.severity == "high"
    assert any("X-Customer" in line for line in finding.offending_lines)


def test_request_uri_with_space_is_kept_and_reported():
    payload = _invite(start=b"INVITE sip:10 00@10.0.0.20 SIP/2.0")
    message = parse_sip_message(_packet(payload))

    assert message is not None
    assert message.request_uri == "sip:10 00@10.0.0.20"
    finding = _finding(analyze_pcap([_packet(payload)]), "sip_request_uri_invalid")
    assert finding.severity == "high"


def test_unescaped_hash_in_request_uri_is_medium():
    payload = _invite(start=b"INVITE sip:*31#1000@10.0.0.20 SIP/2.0")
    finding = _finding(analyze_pcap([_packet(payload)]), "sip_request_uri_invalid")

    assert finding.severity == "medium"
    assert any("#" in item for item in finding.evidence)


def test_invite_without_contact_and_cseq_mismatch():
    headers = [
        b"Via: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-1",
        b"Max-Forwards: 70",
        b"From: <sip:alice@198.51.100.10>;tag=from1",
        b"To: <sip:1000@10.0.0.20>",
        b"Call-ID: no-contact",
        b"CSeq: 1 OPTIONS",
        b"Content-Type: application/sdp",
    ]
    types = _types(analyze_pcap([_packet(_invite(headers=headers))]))

    assert "sip_header_missing_contact" in types
    assert "sip_header_cseq_mismatch" in types


def test_max_forwards_zero_is_flagged():
    payload = _invite().replace(b"Max-Forwards: 70", b"Max-Forwards: 0")
    finding = _finding(analyze_pcap([_packet(payload)]), "sip_header_max_forwards")

    assert finding.severity == "high"


def test_require_unsupported_by_freeswitch_confirmed_by_420():
    invite = _invite(extra=b"Require: precondition\r\n")
    result = analyze_pcap(
        [
            _packet(invite),
            _packet(_response(420, b"Bad Extension", extra=b"Unsupported: precondition\r\n"), PBX, CALLER, 1.1),
        ],
        AnalysisSettings(target_platform="freeswitch", target_platform_ips=PBX),
    )

    finding = _finding(result, "sip_header_require_unsupported")
    assert finding.confirmed_by == "420 Bad Extension"
    assert finding.severity == "high"
    verdict = result["call_summaries"][0]["verdict"]
    assert verdict["root_type"] == "sip_header_require_unsupported"


def test_bare_lf_and_unquoted_comma_in_contact():
    payload = _invite().replace(
        b"Contact: <sip:alice@198.51.100.10:5060>",
        b"Contact: Silva, Joao <sip:alice@198.51.100.10:5060>",
    )
    head, body = payload.split(b"\r\n\r\n", 1)
    payload = head.replace(b"\r\n", b"\n") + b"\n\n" + body
    types = _types(analyze_pcap([_packet(payload)]))

    assert "sip_header_bare_lf" in types
    assert "sip_header_malformed_address" in types


def test_incomplete_sdp_and_dynamic_payload_without_rtpmap():
    body = b"v=0\r\nc=IN IP4 198.51.100.10\r\nm=audio 4000 RTP/AVP 0 96\r\n"
    types = _types(analyze_pcap([_packet(_invite(body=body))]))

    assert "sip_sdp_malformed" in types
    assert "sip_sdp_dynamic_payload_without_rtpmap" in types


def test_tcp_message_without_content_length():
    payload = (
        b"OPTIONS sip:10.0.0.20 SIP/2.0\r\n"
        b"Via: SIP/2.0/TCP 198.51.100.10:5060;branch=z9hG4bK-2\r\n"
        b"Max-Forwards: 70\r\n"
        b"From: <sip:alice@198.51.100.10>;tag=a\r\n"
        b"To: <sip:10.0.0.20>\r\n"
        b"Call-ID: tcp-no-length\r\n"
        b"CSeq: 1 OPTIONS\r\n\r\n"
    )
    types = _types(analyze_pcap([_packet(payload, transport="tcp")]))

    assert "sip_header_tcp_missing_content_length" in types


def test_control_character_in_header():
    payload = _invite().replace(b'"Alice"', b'"Ali\x00ce"')
    finding = _finding(analyze_pcap([_packet(payload)]), "sip_header_control_characters")

    assert any("\\x00" in line for line in finding.offending_lines)
