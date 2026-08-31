from scapy.layers.inet import IP, UDP

from ciper.engine import analyze_pcap
from tests.test_rtp import make_rtp_packet


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
        make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 100, 160, 1234),
        make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 102, 480, 1234),
        make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 103, 640, 1234),
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
