from scapy.layers.inet import IP, UDP

from ciper.engine import _get_related_call_findings, analyze_pcap
from ciper.findings import Finding
from ciper.gui.evidence import build_finding_evidence_context
from ciper.rtp import build_rtp_streams
from ciper.sip import SIPFlow, build_sip_flows
from tests.test_rtp import make_rtp_packet


def _sip_packet(payload, reverse=False):
    source = "10.0.0.2" if reverse else "10.0.0.1"
    destination = "10.0.0.1" if reverse else "10.0.0.2"
    return IP(src=source, dst=destination) / UDP(sport=5060, dport=5060) / payload


def test_rtp_reordering_does_not_create_packet_loss():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 0, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 102, 320, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 160, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 103, 480, 1234),
    ]
    for index, packet in enumerate(packets):
        packet.time = 100.0 + index * 0.02

    stream = next(iter(build_rtp_streams(packets).values()))

    assert stream.lost_packets == 0
    assert stream.out_of_order_packets == 1


def test_rtp_packet_from_before_capture_start_does_not_create_loss():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 65535, 0, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 0, 160, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 1, 320, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 65530, 0xFFFFFCE0, 1234),
    ]
    for index, packet in enumerate(packets):
        packet.time = 100.0 + index * 0.02

    stream = next(iter(build_rtp_streams(packets).values()))

    assert stream.lost_packets == 0
    assert stream.out_of_order_packets == 1


def test_rtp_timestamp_wrap_does_not_create_jitter_or_anomaly():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 0xFFFFFFA0, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 64, 1234),
    ]
    packets[0].time = 100.0
    packets[1].time = 100.02

    stream = next(iter(build_rtp_streams(packets).values()))

    assert stream.timestamp_anomalies == 0
    assert stream.max_jitter < 0.001


def test_dynamic_rtp_clock_rate_comes_from_sdp():
    packets = [
        _sip_packet(
            b"INVITE sip:200@pbx SIP/2.0\r\nCall-ID: opus-call\r\nCSeq: 1 INVITE\r\n\r\n"
            b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\n"
        ),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 0, 1234, payload_type=111),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 960, 1234, payload_type=111),
    ]
    packets[0].time = 100.0
    packets[1].time = 100.1
    packets[2].time = 100.12

    result = analyze_pcap(packets)
    stream = next(iter(result["rtp_streams"].values()))

    assert stream.clock_rate == 48000
    assert stream.max_jitter < 0.001
    assert "rtp_high_jitter" not in {finding.type for finding in result["findings"]}


def test_dynamic_rtp_clock_rate_is_scoped_by_sdp_time():
    first_sip = _sip_packet(
        b"INVITE sip:200@pbx SIP/2.0\r\nCall-ID: opus-call\r\nCSeq: 1 INVITE\r\n\r\n"
        b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 111\r\na=rtpmap:111 opus/48000/2\r\n"
    )
    second_sip = _sip_packet(
        b"INVITE sip:200@pbx SIP/2.0\r\nCall-ID: wideband-call\r\nCSeq: 1 INVITE\r\n\r\n"
        b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 111\r\na=rtpmap:111 wideband/16000\r\n"
    )
    first_rtp = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 0, 1111, payload_type=111),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 960, 1111, payload_type=111),
    ]
    second_rtp = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 200, 0, 2222, payload_type=111),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 201, 320, 2222, payload_type=111),
    ]
    first_sip.time = 1.0
    first_rtp[0].time = 2.0
    first_rtp[1].time = 2.02
    second_sip.time = 10.0
    second_rtp[0].time = 11.0
    second_rtp[1].time = 11.02

    result = analyze_pcap([first_sip, *first_rtp, second_sip, *second_rtp])
    streams = {stream.ssrc: stream for stream in result["rtp_streams"].values()}

    assert streams[1111].clock_rate == 48000
    assert streams[1111].max_jitter < 0.001
    assert streams[2222].clock_rate == 16000
    assert streams[2222].max_jitter < 0.001


def test_successful_authenticated_register_is_not_reported_as_failure():
    packets = [
        _sip_packet(b"REGISTER sip:pbx SIP/2.0\r\nCall-ID: auth\r\nCSeq: 1 REGISTER\r\n\r\n"),
        _sip_packet(b"SIP/2.0 401 Unauthorized\r\nCall-ID: auth\r\nCSeq: 1 REGISTER\r\n\r\n", True),
        _sip_packet(b"REGISTER sip:pbx SIP/2.0\r\nCall-ID: auth\r\nCSeq: 2 REGISTER\r\n\r\n"),
        _sip_packet(b"SIP/2.0 200 OK\r\nCall-ID: auth\r\nCSeq: 2 REGISTER\r\n\r\n", True),
    ]

    finding_types = {finding.type for finding in analyze_pcap(packets)["findings"]}

    assert "sip_register_failure" not in finding_types
    assert "sip_error_response" not in finding_types
    assert "sip_ok_without_ack" not in finding_types


def test_authenticated_invite_in_progress_has_consistent_state():
    packets = [
        _sip_packet(b"INVITE sip:200@pbx SIP/2.0\r\nCall-ID: invite-auth\r\nCSeq: 1 INVITE\r\n\r\n"),
        _sip_packet(
            b"SIP/2.0 401 Unauthorized\r\nCall-ID: invite-auth\r\nCSeq: 1 INVITE\r\n\r\n",
            True,
        ),
        _sip_packet(b"INVITE sip:200@pbx SIP/2.0\r\nCall-ID: invite-auth\r\nCSeq: 2 INVITE\r\n\r\n"),
        _sip_packet(b"SIP/2.0 100 Trying\r\nCall-ID: invite-auth\r\nCSeq: 2 INVITE\r\n\r\n", True),
    ]

    result = analyze_pcap(packets)
    summary = result["call_summaries"][0]

    assert summary["signaling_state"] == "incomplete"
    assert "sip_error_response" not in summary["finding_types"]
    # The synthetic INVITE has no Via/Contact, which the header hygiene check
    # rightly reports; the 401 challenge itself must never be the issue.
    assert summary["primary_issue"] in {None} or summary["primary_issue"].startswith("sip_header_")
    assert summary["verdict"]["root_type"] != "sip_error_response"


def test_invite_retransmission_is_not_counted_as_reinvite():
    invite = (
        b"INVITE sip:200@pbx SIP/2.0\r\nCall-ID: retransmit\r\n"
        b"CSeq: 1 INVITE\r\nVia: SIP/2.0/UDP edge;branch=z9hG4bK-one\r\n\r\n"
    )

    flow = next(iter(build_sip_flows([_sip_packet(invite), _sip_packet(invite)]).values()))

    assert flow.invites == 1
    assert flow.reinvites == 0


def test_call_summary_does_not_inherit_other_call_finding_on_same_endpoints():
    flow = SIPFlow(call_id="call-a", source_ip="10.0.0.1", destination_ip="10.0.0.2")
    finding = Finding(
        type="sip_error_response",
        severity="high",
        confidence=0.95,
        source_ip="10.0.0.2",
        destination_ip="10.0.0.1",
        description="Failure in another call",
        evidence=["Call-ID: call-b"],
    )

    assert _get_related_call_findings(flow, [finding], []) == []


def test_rtp_finding_requires_matching_ssrc_and_endpoints():
    flow = SIPFlow(call_id="call-a", source_ip="10.0.0.1", destination_ip="10.0.0.2")
    related_stream = next(
        iter(
            build_rtp_streams(
                [make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 1, 160, 1234)]
            ).values()
        )
    )
    finding = Finding(
        type="rtp_packet_loss",
        severity="high",
        confidence=0.95,
        source_ip="10.0.0.3",
        destination_ip="10.0.0.4",
        description="Same SSRC on another path",
        evidence=["SSRC: 1234"],
    )

    assert _get_related_call_findings(flow, [finding], [related_stream]) == []


def test_forked_sip_dialogs_keep_endpoints_and_findings_separate():
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.9")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:200@pbx SIP/2.0\r\nCall-ID: forked-call\r\n"
            b"From: <sip:100@pbx>;tag=caller\r\nCSeq: 1 INVITE\r\n\r\n"
        ),
        IP(src="10.0.0.2", dst="10.0.0.1")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\nCall-ID: forked-call\r\n"
            b"From: <sip:100@pbx>;tag=caller\r\nTo: <sip:200@pbx>;tag=answered\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        ),
        IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=5060, dport=5060)
        / (
            b"ACK sip:200@pbx SIP/2.0\r\nCall-ID: forked-call\r\n"
            b"From: <sip:100@pbx>;tag=caller\r\nTo: <sip:200@pbx>;tag=answered\r\n"
            b"CSeq: 1 ACK\r\n\r\n"
        ),
        IP(src="10.0.0.3", dst="10.0.0.1")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 486 Busy Here\r\nCall-ID: forked-call\r\n"
            b"From: <sip:100@pbx>;tag=caller\r\nTo: <sip:200@pbx>;tag=busy\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        ),
    ]

    summaries = {
        summary["dialog_key"]: summary
        for summary in analyze_pcap(packets)["call_summaries"]
    }
    answered = summaries["forked-call|caller|answered"]
    busy = summaries["forked-call|caller|busy"]

    assert answered["source_ip"] == "10.0.0.1"
    assert answered["destination_ip"] == "10.0.0.2"
    assert answered["signaling_state"] == "established"
    assert "sip_error_response" not in answered["finding_types"]
    assert busy["source_ip"] == "10.0.0.1"
    assert busy["destination_ip"] == "10.0.0.3"
    assert busy["signaling_state"] == "failed"
    assert "sip_call_established" not in busy["finding_types"]


def test_reverse_direction_bye_stays_in_the_existing_dialog():
    packets = [
        _sip_packet(
            b"INVITE sip:200@pbx SIP/2.0\r\nCall-ID: reverse-bye\r\n"
            b"From: <sip:100@pbx>;tag=caller\r\nCSeq: 1 INVITE\r\n\r\n"
        ),
        _sip_packet(
            b"SIP/2.0 200 OK\r\nCall-ID: reverse-bye\r\n"
            b"From: <sip:100@pbx>;tag=caller\r\nTo: <sip:200@pbx>;tag=callee\r\n"
            b"CSeq: 1 INVITE\r\n\r\n",
            True,
        ),
        _sip_packet(
            b"ACK sip:200@pbx SIP/2.0\r\nCall-ID: reverse-bye\r\n"
            b"From: <sip:100@pbx>;tag=caller\r\nTo: <sip:200@pbx>;tag=callee\r\n"
            b"CSeq: 1 ACK\r\n\r\n"
        ),
        _sip_packet(
            b"BYE sip:100@pbx SIP/2.0\r\nCall-ID: reverse-bye\r\n"
            b"From: <sip:200@pbx>;tag=callee\r\nTo: <sip:100@pbx>;tag=caller\r\n"
            b"CSeq: 2 BYE\r\n\r\n",
            True,
        ),
    ]

    result = analyze_pcap(packets)

    assert len(result["sip_flows"]) == 1
    assert len(result["call_summaries"]) == 1
    assert result["call_summaries"][0]["signaling_state"] == "terminated"


def test_jitter_evidence_uses_the_packet_pair_recorded_by_the_engine():
    packets = [
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 100, 0, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 101, 160, 1234),
        make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 4002, 102, 320, 1234),
    ]
    packets[0].time = 1.0
    packets[1].time = 1.02
    packets[2].time = 1.50
    stream = next(iter(build_rtp_streams(packets).values()))
    finding = {
        "type": "rtp_high_jitter",
        "source": "10.0.0.1",
        "destination": "10.0.0.2",
        "evidence": ["SSRC: 1234"],
    }

    context = build_finding_evidence_context(
        {"sip_flows": {}, "rtp_streams": {"affected": stream}, "fragment_groups": {}},
        finding,
    )

    assert any("seq 101" in item and "seq 102" in item for item in context if item.startswith("PIOR PICO:"))
