from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from ciper.engine import analyze_pcap
from ciper.sip import build_sip_flows, parse_sip_message


def test_parse_sip_invite_message():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-123\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        )
    )

    message = parse_sip_message(packet)

    assert message is not None
    assert message.is_request is True
    assert message.method == "INVITE"
    assert message.call_id == "call-123"


def test_parse_sip_message_extracts_sdp_audio_media_and_codec():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: sdp-call\r\n"
            b"Content-Type: application/sdp\r\n\r\n"
            b"v=0\r\n"
            b"c=IN IP4 192.168.1.10\r\n"
            b"m=audio 4000 RTP/AVP 0 8 101\r\n"
            b"a=rtpmap:0 PCMU/8000\r\n"
            b"a=rtpmap:8 PCMA/8000\r\n"
            b"a=rtpmap:101 telephone-event/8000\r\n"
        )
    )

    message = parse_sip_message(packet)

    assert message is not None
    assert len(message.sdp_media) == 1
    assert message.sdp_media[0].port == 4000
    assert message.sdp_media[0].connection_address == "192.168.1.10"
    assert message.sdp_media[0].codecs == {0: "PCMU", 8: "PCMA", 101: "telephone-event"}


def test_parse_sip_message_extracts_sdp_media_direction():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: direction-call\r\n\r\n"
            b"v=0\r\n"
            b"a=sendonly\r\n"
            b"m=audio 4000 RTP/AVP 0\r\n"
        )
    )

    message = parse_sip_message(packet)

    assert message is not None
    assert message.sdp_media[0].direction == "sendonly"


def test_parse_sip_message_supports_compact_headers_ipv6_and_sdp_details():
    packet = (
        IPv6(src="2001:db8::10", dst="2001:db8::20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"i: compact-call\r\n"
            b"f: <sip:100@pbx.local>;tag=caller-tag\r\n"
            b"t: <sip:200@pbx.local>;tag=callee-tag\r\n"
            b"v: SIP/2.0/UDP edge.local;branch=z9hG4bK-123\r\n"
            b"m: <sip:100@2001:db8::10>\r\n"
            b"CSeq: 10 INVITE\r\n\r\n"
            b"v=0\r\n"
            b"c=IN IP6 2001:db8::10\r\n"
            b"m=audio 4000/2 RTP/AVP 0\r\n"
            b"a=mid:audio-main\r\n"
            b"a=rtcp:4001 IN IP6 2001:db8::10\r\n"
            b"a=rtcp-mux\r\n"
        )
    )

    message = parse_sip_message(packet)

    assert message is not None
    assert message.call_id == "compact-call"
    assert message.source_ip == "2001:db8::10"
    assert message.cseq_method == "INVITE"
    assert message.from_tag == "caller-tag"
    assert message.to_tag == "callee-tag"
    assert message.via_branch == "z9hG4bK-123"
    assert message.contact == "<sip:100@2001:db8::10>"
    assert message.sdp_media[0].port == 4000
    assert message.sdp_media[0].rtcp_port == 4001
    assert message.sdp_media[0].media_id == "audio-main"
    assert message.sdp_media[0].rtcp_mux is True


def test_parse_sip_response_message():
    packet = (
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 180 Ringing\r\n"
            b"Call-ID: call-123\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        )
    )

    message = parse_sip_message(packet)

    assert message is not None
    assert message.is_request is False
    assert message.status_code == 180
    assert message.reason_phrase == "Ringing"
    assert message.call_id == "call-123"


def test_build_sip_flows_groups_by_call_id():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-abc\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 100 Trying\r\n"
            b"Call-ID: call-abc\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
    ]

    flows = build_sip_flows(packets)

    assert len(flows) == 1

    flow = flows["call-abc"]

    assert flow.call_id == "call-abc"
    assert len(flow.messages) == 2
    assert flow.invites == 1
    assert flow.responses == 1


def test_build_sip_flows_reassembles_tcp_segments_using_content_length():
    sdp = b"v=0\r\nm=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"
    message = (
        b"INVITE sip:100@pbx.local SIP/2.0\r\n"
        b"Call-ID: tcp-segmented\r\n"
        + f"Content-Length: {len(sdp)}\r\n\r\n".encode()
        + sdp
    )
    split_at = len(message) - 16
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=5060, dport=5060, seq=100) / message[:split_at],
        IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=5060, dport=5060, seq=100 + split_at) / message[split_at:],
    ]

    flows = build_sip_flows(packets)

    assert len(flows) == 1
    assert flows["tcp-segmented"].invites == 1
    assert flows["tcp-segmented"].messages[0].sdp_media[0].codecs == {8: "PCMA"}


def test_build_sip_flows_tracks_ack_and_error_responses():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-state\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 486 Busy Here\r\n"
            b"Call-ID: call-state\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"ACK sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-state\r\n"
            b"CSeq: 1 ACK\r\n"
            b"\r\n"
        ),
    ]

    flows = build_sip_flows(packets)
    flow = flows["call-state"]

    assert flow.acknowledgements == 1
    assert flow.error_responses == 1


def test_build_sip_flows_tracks_bye_cancel_and_large_headers():
    large_from = b"From: " + (b"a" * 1100) + b"\r\n"

    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"CANCEL sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-cancel\r\n"
            b"CSeq: 1 CANCEL\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"BYE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-cancel\r\n"
            b"CSeq: 2 BYE\r\n"
            + large_from
            + b"\r\n"
        ),
    ]

    flows = build_sip_flows(packets)
    flow = flows["call-cancel"]

    assert flow.cancels == 1
    assert flow.byes == 1
    assert flow.large_header_messages == 1


def test_engine_detects_sip_invite_no_response():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-no-response\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "sip_invite_no_response" in finding_types


def test_engine_detects_sip_error_response():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-failed\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 486 Busy Here\r\n"
            b"Call-ID: call-failed\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "sip_error_response" in finding_types


def test_engine_detects_sip_call_established():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-ok\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 100 Trying\r\n"
            b"Call-ID: call-ok\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 180 Ringing\r\n"
            b"Call-ID: call-ok\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: call-ok\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"ACK sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-ok\r\n"
            b"CSeq: 1 ACK\r\n"
            b"\r\n"
        ),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "sip_call_established" in finding_types


def test_engine_detects_sip_ok_without_ack():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-no-ack\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: call-no-ack\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "sip_ok_without_ack" in finding_types


def test_engine_detects_sip_call_cancelled():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-cancelled\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"CANCEL sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-cancelled\r\n"
            b"CSeq: 2 CANCEL\r\n"
            b"\r\n"
        ),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "sip_call_cancelled" in finding_types


def test_engine_detects_sip_call_terminated():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-terminated\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: call-terminated\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"ACK sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-terminated\r\n"
            b"CSeq: 1 ACK\r\n"
            b"\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"BYE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-terminated\r\n"
            b"CSeq: 2 BYE\r\n"
            b"\r\n"
        ),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "sip_call_terminated" in finding_types


def test_engine_detects_sip_large_header():
    large_contact = b"Contact: " + (b"b" * 1200) + b"\r\n"

    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-large-header\r\n"
            b"CSeq: 1 INVITE\r\n"
            + large_contact
            + b"\r\n"
        ),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "sip_large_header" in finding_types


def test_engine_detects_sip_signaling_fragmentation_risk():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20", flags="MF")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-fragmented\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"\r\n"
        ),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "sip_signaling_fragmentation" in finding_types
