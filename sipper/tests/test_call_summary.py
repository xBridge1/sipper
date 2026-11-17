from scapy.layers.inet import IP, UDP

from ciper.engine import analyze_pcap
from tests.test_rtp import make_rtp_packet


def _timed_sip_packet(source, destination, payload, timestamp):
    packet = IP(src=source, dst=destination) / UDP(sport=5060, dport=5060) / payload
    packet.time = timestamp
    return packet


def test_engine_builds_call_summary_for_established_call_with_media_issue():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-summary\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: call-summary\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"ACK sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-summary\r\n"
            b"CSeq: 1 ACK\r\n\r\n"
        ),
        *[
            make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, sequence, 160 * (sequence - 99), 1234)
            for sequence in range(100, 115)
            if sequence != 101
        ],
    ]

    result = analyze_pcap(packets)

    assert "call_summaries" in result
    assert len(result["call_summaries"]) == 1

    summary = result["call_summaries"][0]

    assert summary["call_id"] == "call-summary"
    assert summary["signaling_state"] == "established"
    assert summary["media_state"] == "one_way_media"
    assert summary["has_rtp"] is True
    assert summary["severity"] == "high"
    assert summary["primary_issue"] == "sip_call_one_way_audio"
    assert summary["codec_guesses"] == ["PCMU"]
    assert any("Call-ID: call-summary" == item for item in summary["key_evidence"])
    assert summary["recommended_action"]
    assert "rtp_packet_loss" in summary["finding_types"]
    assert "sip_call_one_way_audio" in summary["finding_types"]
    assert summary["start_time"] is not None
    assert summary["end_time"] is not None
    assert summary["duration"] >= 0
    assert summary["rtp_metrics"]["packet_count"] == 14
    assert summary["rtp_metrics"]["lost_packets"] == 1
    assert round(summary["rtp_metrics"]["loss_percent"], 2) == 6.67
    assert summary["rtp_metrics"]["ssrcs"] == [1234]


def test_call_summaries_do_not_share_rtp_between_sequential_calls_reusing_ports():
    invite = (
        b"INVITE sip:100@pbx.local SIP/2.0\r\nCall-ID: {call_id}\r\n"
        b"CSeq: 1 INVITE\r\nContent-Type: application/sdp\r\n\r\n"
        b"v=0\r\nc=IN IP4 192.168.1.10\r\nm=audio 4000 RTP/AVP 0 8\r\n"
    )
    ok = (
        b"SIP/2.0 200 OK\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\n"
        b"Content-Type: application/sdp\r\n\r\nv=0\r\n"
        b"c=IN IP4 192.168.1.20\r\nm=audio 4002 RTP/AVP 0 8\r\n"
    )
    ack = b"ACK sip:100@pbx.local SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: 1 ACK\r\n\r\n"
    bye = b"BYE sip:100@pbx.local SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: 2 BYE\r\n\r\n"
    packets = []
    for call_id, base_time, ssrc, payload_type in (
        (b"first-call", 1.0, 1111, 0),
        (b"second-call", 10.0, 2222, 8),
    ):
        packets.extend(
            [
                _timed_sip_packet(
                    "192.168.1.10",
                    "192.168.1.20",
                    invite.replace(b"{call_id}", call_id),
                    base_time,
                ),
                _timed_sip_packet(
                    "192.168.1.20",
                    "192.168.1.10",
                    ok.replace(b"{call_id}", call_id),
                    base_time + 0.1,
                ),
                _timed_sip_packet(
                    "192.168.1.10",
                    "192.168.1.20",
                    ack.replace(b"{call_id}", call_id),
                    base_time + 0.2,
                ),
            ]
        )
        rtp_a = make_rtp_packet(
            "192.168.1.10", "192.168.1.20", 4000, 4002, 100, 160, ssrc, payload_type=payload_type
        )
        rtp_b = make_rtp_packet(
            "192.168.1.10", "192.168.1.20", 4000, 4002, 101, 320, ssrc, payload_type=payload_type
        )
        rtp_a.time = base_time + 0.3
        rtp_b.time = base_time + 0.32
        packets.extend(
            [
                rtp_a,
                rtp_b,
                _timed_sip_packet(
                    "192.168.1.10",
                    "192.168.1.20",
                    bye.replace(b"{call_id}", call_id),
                    base_time + 0.5,
                ),
            ]
        )

    summaries = {summary["call_id"]: summary for summary in analyze_pcap(packets)["call_summaries"]}

    assert summaries["first-call"]["rtp_metrics"]["ssrcs"] == [1111]
    assert summaries["second-call"]["rtp_metrics"]["ssrcs"] == [2222]


def test_engine_builds_call_summary_for_failed_call():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: call-failure-summary\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 486 Busy Here\r\n"
            b"Call-ID: call-failure-summary\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        ),
    ]

    result = analyze_pcap(packets)
    summary = result["call_summaries"][0]

    assert summary["call_id"] == "call-failure-summary"
    assert summary["signaling_state"] == "failed"
    assert summary["media_state"] == "no_media"
    assert summary["has_rtp"] is False
    assert summary["severity"] == "high"
    assert summary["primary_issue"] == "sip_error_response"
    assert summary["codec_guesses"] == []
    assert any("Status: 486 Busy Here" == item for item in summary["key_evidence"])
    assert summary["recommended_action"]
    assert "sip_error_response" in summary["finding_types"]


def test_engine_uses_sdp_media_ports_to_correlate_rtp_streams():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: sdp-correlation\r\n\r\n"
            b"v=0\r\n"
            b"m=audio 4000 RTP/AVP 8\r\n"
            b"a=rtpmap:8 PCMA/8000\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: sdp-correlation\r\n\r\n"
            b"v=0\r\n"
            b"m=audio 4002 RTP/AVP 8\r\n"
            b"a=rtpmap:8 PCMA/8000\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"ACK sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: sdp-correlation\r\n\r\n"
        ),
        make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 100, 160, 1234, payload_type=8),
        make_rtp_packet("192.168.1.10", "192.168.1.20", 5000, 5002, 100, 160, 5678, payload_type=0),
    ]

    summary = analyze_pcap(packets)["call_summaries"][0]

    assert summary["rtp_stream_count"] == 1
    assert summary["rtp_metrics"]["ssrcs"] == [1234]
    assert summary["codec_guesses"] == ["PCMA"]


def test_engine_does_not_flag_expected_unidirectional_sdp_media_as_one_way_audio():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: sendonly-call\r\n\r\n"
            b"v=0\r\n"
            b"a=sendonly\r\n"
            b"m=audio 4000 RTP/AVP 0\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: sendonly-call\r\n\r\n"
            b"v=0\r\n"
            b"a=recvonly\r\n"
            b"m=audio 4002 RTP/AVP 0\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / b"ACK sip:100@pbx.local SIP/2.0\r\nCall-ID: sendonly-call\r\n\r\n",
        make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 100, 160, 1234),
        make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 101, 320, 1234),
        make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 102, 480, 1234),
    ]

    result = analyze_pcap(packets)
    summary = result["call_summaries"][0]

    assert summary["media_direction"] == "unidirectional"
    assert summary["media_state"] == "media_present"
    assert "sip_call_one_way_audio" not in summary["finding_types"]


def test_engine_does_not_flag_missing_rtp_when_sdp_disables_audio_port():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: inactive-call\r\n\r\n"
            b"v=0\r\n"
            b"m=audio 0 RTP/AVP 0\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: inactive-call\r\n\r\n"
            b"v=0\r\n"
            b"m=audio 0 RTP/AVP 0\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / b"ACK sip:100@pbx.local SIP/2.0\r\nCall-ID: inactive-call\r\n\r\n",
    ]

    result = analyze_pcap(packets)
    summary = result["call_summaries"][0]

    assert summary["media_direction"] == "inactive"
    assert summary["media_state"] == "inactive_media"
    assert "sip_call_established_without_rtp" not in summary["finding_types"]


def test_engine_uses_latest_reinvite_sdp_and_reports_directional_quality():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: reinvite-call\r\n\r\n"
            b"v=0\r\nm=audio 4000 RTP/AVP 0\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: reinvite-call\r\n\r\n"
            b"v=0\r\nm=audio 4002 RTP/AVP 0\r\n"
        ),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: reinvite-call\r\n\r\n"
            b"v=0\r\nm=audio 5000 RTP/AVP 8\r\n"
        ),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: reinvite-call\r\n\r\n"
            b"v=0\r\nm=audio 5002 RTP/AVP 8\r\n"
        ),
        make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 100, 160, 1234),
        make_rtp_packet("192.168.1.10", "192.168.1.20", 5000, 5002, 100, 160, 5678, payload_type=8),
        make_rtp_packet("192.168.1.10", "192.168.1.20", 5000, 5002, 101, 320, 5678, payload_type=8),
    ]

    summary = analyze_pcap(packets)["call_summaries"][0]

    assert summary["rtp_metrics"]["ssrcs"] == [5678]
    assert summary["rtp_metrics"]["directions"]
    assert summary["media_quality"] == "good"


def test_engine_reports_sip_signaling_timeline_and_timings():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / b"INVITE sip:100@pbx.local SIP/2.0\r\nCall-ID: timeline-call\r\nCSeq: 1 INVITE\r\n\r\n",
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / b"SIP/2.0 100 Trying\r\nCall-ID: timeline-call\r\nCSeq: 1 INVITE\r\n\r\n",
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / b"SIP/2.0 180 Ringing\r\nCall-ID: timeline-call\r\nCSeq: 1 INVITE\r\n\r\n",
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=5060)
        / b"SIP/2.0 200 OK\r\nCall-ID: timeline-call\r\nCSeq: 1 INVITE\r\n\r\n",
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / b"ACK sip:100@pbx.local SIP/2.0\r\nCall-ID: timeline-call\r\nCSeq: 1 ACK\r\n\r\n",
    ]
    for index, packet in enumerate(packets):
        packet.time = 100.0 + (index * 0.1)

    summary = analyze_pcap(packets)["call_summaries"][0]

    assert [event["event"] for event in summary["signaling_timeline"]] == [
        "INVITE",
        "100 Trying",
        "180 Ringing",
        "200 OK",
        "ACK",
    ]
    assert round(summary["signaling_timings"]["invite_to_trying"], 3) == 0.1
    assert round(summary["signaling_timings"]["invite_to_ringing"], 3) == 0.2
    assert round(summary["signaling_timings"]["invite_to_ok"], 3) == 0.3
    assert round(summary["signaling_timings"]["ok_to_ack"], 3) == 0.1
