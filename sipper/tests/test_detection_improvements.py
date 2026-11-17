"""Regression tests for the detection improvements in SIPPER 1.3."""

from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP

from ciper.detectors.sip import (
    detect_sip_retransmissions,
    detect_sip_sdp_private_address,
    detect_sip_slow_call_setup,
)
from ciper.detectors.tcp import detect_tcp_retransmissions
from ciper.engine import analyze_pcap, analyze_pcap_file
from ciper.flows import build_tcp_flows
from ciper.labels import evidence_label
from ciper.rtcp import build_rtcp_reports
from ciper.settings import AnalysisSettings, _validate_settings
from ciper.sip import build_sip_flows
from ciper.voip_quality import estimate_mos
from tests.test_rtp import make_rtp_packet

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
MEDIA_FINDING_PREFIXES = ("rtp_", "rtcp_", "sip_call_one_way", "sip_call_established_without_rtp")


def _sip(source, destination, payload, timestamp, sport=5060, dport=5060):
    packet = IP(src=source, dst=destination) / UDP(sport=sport, dport=dport) / payload
    packet.time = timestamp
    return packet


def _invite(call_id, sdp=b"", cseq=1, branch=b"z9hG4bK-1"):
    body = sdp
    return (
        b"INVITE sip:100@pbx.local SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP 10.0.0.1;branch=" + branch + b"\r\n"
        b"Call-ID: " + call_id + b"\r\n"
        b"CSeq: " + str(cseq).encode() + b" INVITE\r\n"
        b"Content-Type: application/sdp\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )


def _response(call_id, status, reason, sdp=b"", branch=b"z9hG4bK-1"):
    return (
        b"SIP/2.0 " + status + b" " + reason + b"\r\n"
        b"Via: SIP/2.0/UDP 10.0.0.1;branch=" + branch + b"\r\n"
        b"Call-ID: " + call_id + b"\r\n"
        b"CSeq: 1 INVITE\r\n"
        b"Content-Length: " + str(len(sdp)).encode() + b"\r\n\r\n" + sdp
    )


def _sdp(address, port, payloads=b"0 101", ptime=None):
    lines = [
        b"v=0",
        b"o=- 1 1 IN IP4 " + address,
        b"s=-",
        b"c=IN IP4 " + address,
        b"t=0 0",
        b"m=audio " + str(port).encode() + b" RTP/AVP " + payloads,
        b"a=rtpmap:0 PCMU/8000",
        b"a=rtpmap:101 telephone-event/8000",
    ]
    if ptime:
        lines.append(b"a=ptime:" + str(ptime).encode())
    return b"\r\n".join(lines) + b"\r\n"


# ------------------------------------------------------------------ samples


def test_clean_sample_call_has_no_media_findings():
    # PCMA call with comfort noise and a 3.4 s VAD pause: previously reported
    # as an interruption plus two codec changes, and rated "poor".
    result = analyze_pcap_file(str(SAMPLES / "RTP-Protocol.pcap"))

    media = [f.type for f in result["findings"] if f.type.startswith(MEDIA_FINDING_PREFIXES)]
    summary = result["call_summaries"][0]

    assert media == []
    assert summary["media_quality"] == "good"
    assert summary["media_quality_metrics"]["mos_estimate"] >= 4.0
    assert summary["rtp_metrics"]["silence_periods"] >= 1


def test_short_udp_burst_in_sample_is_not_reported_as_rtp():
    result = analyze_pcap_file(str(SAMPLES / "teste_udp.pcap"))

    assert result["rtp_streams"] == {}
    assert not any(f.type.startswith("rtp_") for f in result["findings"])


def test_rtcp_receiver_report_in_sample_is_used():
    result = analyze_pcap_file(str(SAMPLES / "teste_sip_rtp_problemas.pcap"))

    types = {f.type for f in result["findings"]}

    assert "rtcp_reported_loss" in types
    assert "rtcp_reported_jitter" in types


# ------------------------------------------------------------------ RTCP


def _rtcp_sender_report(ssrc, ntp_middle, packet_time, source="10.0.0.1", destination="10.0.0.2"):
    ntp = (ntp_middle >> 16).to_bytes(4, "big") + ((ntp_middle & 0xFFFF) << 16).to_bytes(4, "big")
    body = ssrc.to_bytes(4, "big") + ntp + b"\x00" * 12
    payload = b"\x80\xc8" + ((len(body) + 4) // 4 - 1).to_bytes(2, "big") + body
    packet = IP(src=source, dst=destination) / UDP(sport=4001, dport=4003) / payload
    packet.time = packet_time
    return packet


def _rtcp_receiver_report(reporter, source_ssrc, fraction, cumulative, jitter, lsr, dlsr, packet_time):
    block = (
        source_ssrc.to_bytes(4, "big")
        + bytes([fraction])
        + cumulative.to_bytes(3, "big")
        + (1000).to_bytes(4, "big")
        + jitter.to_bytes(4, "big")
        + lsr.to_bytes(4, "big")
        + dlsr.to_bytes(4, "big")
    )
    body = reporter.to_bytes(4, "big") + block
    payload = b"\x81\xc9" + ((len(body) + 4) // 4 - 1).to_bytes(2, "big") + body
    packet = IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=4003, dport=4001) / payload
    packet.time = packet_time
    return packet


def test_rtcp_reports_give_far_end_loss_jitter_and_rtt():
    sender = _rtcp_sender_report(1234, 0x12345678, 100.0)
    # Echoes the SR 0.9 s later after holding it for 0.5 s: RTT 0.4 s.
    receiver = _rtcp_receiver_report(9999, 1234, 26, 12, 480, 0x12345678, int(0.5 * 65536), 100.9)

    report = build_rtcp_reports([sender, receiver])[(1234, "10.0.0.2")]

    assert round(report.max_fraction_lost * 100, 1) == 10.2
    assert report.cumulative_lost == 12
    assert round(report.max_jitter, 3) == 0.060
    assert round(report.max_rtt, 2) == 0.40


def test_engine_reports_rtcp_high_rtt():
    packets = [
        _rtcp_sender_report(1234, 0x00010000, 100.0),
        _rtcp_receiver_report(9999, 1234, 0, 0, 10, 0x00010000, int(0.1 * 65536), 100.8),
    ]

    finding = next(f for f in analyze_pcap(packets)["findings"] if f.type == "rtcp_high_rtt")

    assert finding.severity == "high"


# ------------------------------------------------------------------ SIP


def test_sip_invite_retransmissions_are_reported():
    packets = [
        _sip("10.0.0.1", "10.0.0.2", _invite(b"retx"), 100.0),
        _sip("10.0.0.1", "10.0.0.2", _invite(b"retx"), 100.5),
        _sip("10.0.0.1", "10.0.0.2", _invite(b"retx"), 101.5),
        _sip("10.0.0.1", "10.0.0.2", _invite(b"retx"), 103.5),
        _sip("10.0.0.2", "10.0.0.1", _response(b"retx", b"180", b"Ringing"), 104.0),
    ]

    findings = detect_sip_retransmissions(build_sip_flows(packets))

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "Retransmissions: 3" in findings[0].evidence


def test_capture_duplicates_are_not_sip_retransmissions():
    # The same packet seen twice within microseconds (two capture interfaces).
    packets = [
        _sip("10.0.0.1", "10.0.0.2", _invite(b"dup"), 100.0),
        _sip("10.0.0.1", "10.0.0.2", _invite(b"dup"), 100.0001),
    ]

    assert detect_sip_retransmissions(build_sip_flows(packets)) == []


def test_slow_post_dial_delay_is_reported():
    packets = [
        _sip("10.0.0.1", "10.0.0.2", _invite(b"pdd"), 100.0),
        _sip("10.0.0.2", "10.0.0.1", _response(b"pdd", b"100", b"Trying"), 100.1),
        _sip("10.0.0.2", "10.0.0.1", _response(b"pdd", b"180", b"Ringing"), 107.0),
    ]

    findings = detect_sip_slow_call_setup(build_sip_flows(packets))

    assert [f.severity for f in findings] == ["medium"]
    assert "Post-dial delay: 7.00 s" in findings[0].evidence


def test_private_sdp_address_from_public_signaling_is_reported():
    packets = [_sip("200.160.2.3", "177.10.20.30", _invite(b"nat", _sdp(b"192.168.0.20", 4000)), 100.0)]

    findings = detect_sip_sdp_private_address(build_sip_flows(packets))

    assert len(findings) == 1
    assert "SDP audio endpoint: 192.168.0.20:4000" in findings[0].evidence


def test_private_sdp_address_inside_lan_is_normal():
    packets = [_sip("192.168.0.10", "192.168.0.5", _invite(b"lan", _sdp(b"192.168.0.10", 4000)), 100.0)]

    assert detect_sip_sdp_private_address(build_sip_flows(packets)) == []


# ------------------------------------------------------------------ SDP vs RTP


def _call_with_media(payload_type=0, timestamp_step=160, ptime=None):
    packets = [
        _sip("10.0.0.1", "10.0.0.2", _invite(b"media", _sdp(b"10.0.0.1", 4000, ptime=ptime)), 100.0),
        _sip("10.0.0.2", "10.0.0.1", _response(b"media", b"200", b"OK", _sdp(b"10.0.0.2", 5000, ptime=ptime)), 100.2),
    ]
    for index in range(30):
        forward = make_rtp_packet("10.0.0.1", "10.0.0.2", 4000, 5000, 10 + index, timestamp_step * (index + 1), 1, payload_type)
        forward.time = 100.3 + index * 0.02
        backward = make_rtp_packet("10.0.0.2", "10.0.0.1", 5000, 4000, 500 + index, timestamp_step * (index + 1), 2, payload_type)
        backward.time = 100.31 + index * 0.02
        packets.extend([forward, backward])
    return packets


def test_rtp_payload_not_negotiated_in_sdp_is_reported():
    types = {f.type for f in analyze_pcap(_call_with_media(payload_type=8))["findings"]}

    assert "rtp_payload_not_negotiated" in types


def test_negotiated_call_has_no_sdp_mismatch_findings():
    types = {f.type for f in analyze_pcap(_call_with_media(ptime=20))["findings"]}

    assert not types & {"rtp_payload_not_negotiated", "rtp_ptime_mismatch", "rtp_one_way_audio"}


def test_ptime_mismatch_is_reported():
    # SDP asks for 20 ms but the RTP clock advances 30 ms (240 samples) per packet.
    types = {f.type for f in analyze_pcap(_call_with_media(timestamp_step=240, ptime=20))["findings"]}

    assert "rtp_ptime_mismatch" in types


# ------------------------------------------------------------------ TCP, MOS, labels, settings


def test_tcp_retransmission_in_long_flow_is_low_severity():
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=80, flags="PA", seq=1000 + index * 10, ack=1) / (b"x" * 10)
        for index in range(300)
    ]
    packets.append(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=80, flags="PA", seq=1000, ack=1) / (b"x" * 10))

    findings = detect_tcp_retransmissions(build_tcp_flows(packets))

    assert findings[0].severity == "low"


def test_e_model_mos_accounts_for_codec_and_delay():
    clean = estimate_mos(0.0, 0.005, "PCMA")
    g729 = estimate_mos(0.0, 0.005, "G729")
    far = estimate_mos(0.0, 0.005, "PCMA", rtt_seconds=0.6)
    lossy = estimate_mos(3.0, 0.005, "PCMA")

    assert 4.3 <= clean <= 4.5
    assert g729 < clean
    assert far < clean
    assert lossy < clean


def test_evidence_lines_are_translated_for_display_only():
    assert evidence_label("Lost packets: 3") == "Pacotes perdidos: 3"
    assert evidence_label("SYN/ACK observed: no") == "SYN/ACK observed: no"
    assert evidence_label("RST observed: yes") == "RST observado: sim"
    assert evidence_label("Call-ID: abc") == "Call-ID: abc"


def test_loss_percent_setting_is_validated_and_persisted():
    assert _validate_settings({"rtp_loss_high_percent": 2.5}).rtp_loss_high_percent == 2.5
    assert _validate_settings({"rtp_loss_high_percent": 500}).rtp_loss_high_percent == AnalysisSettings().rtp_loss_high_percent
