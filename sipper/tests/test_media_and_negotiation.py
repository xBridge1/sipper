from scapy.layers.inet import IP, TCP

from ciper.engine import analyze_pcap
from ciper.settings import AnalysisSettings
from tests.test_rtp import make_rtp_packet
from tests.test_sip_header_hygiene import CALLER, PBX, SDP, _invite, _packet, _response

ANSWER_SDP = (
    b"v=0\r\no=- 2 2 IN IP4 10.0.0.20\r\ns=-\r\nc=IN IP4 10.0.0.20\r\nt=0 0\r\n"
    b"m=audio 20000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n"
)
ACK = (
    b"ACK sip:1000@10.0.0.20 SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-a\r\n"
    b"Max-Forwards: 70\r\nFrom: <sip:alice@198.51.100.10>;tag=from1\r\nTo: <sip:1000@10.0.0.20>;tag=to1\r\n"
    b"Call-ID: CALL\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
)


def _ok_with_sdp(call_id, body=ANSWER_SDP, contact=b"<sip:1000@10.0.0.20>"):
    head = _response(200, b"OK", call_id=call_id, extra=b"Contact: " + contact + b"\r\nContent-Type: application/sdp\r\n")
    head = head.replace(b"Content-Length: 0\r\n\r\n", b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
    return head + body


def _types(result):
    return {finding.type for finding in result["findings"]}


def _established(call_id, answer=ANSWER_SDP, rtp=()):
    return [
        _packet(_invite(call_id=call_id)),
        _packet(_ok_with_sdp(call_id, answer), PBX, CALLER, 1.2),
        _packet(ACK.replace(b"CALL", call_id.encode()), timestamp=1.3),
        *rtp,
    ]


def test_silent_g711_stream_is_reported_and_marks_the_call_silent():
    silence = b"\xff" * 160
    rtp = [
        make_rtp_packet(CALLER, PBX, 4000, 20000, seq, 160 * seq, 7, payload=silence) for seq in range(1, 160)
    ] + [
        make_rtp_packet(PBX, CALLER, 20000, 4000, seq, 160 * seq, 8) for seq in range(1, 160)
    ]
    for index, packet in enumerate(rtp):
        packet.time = 1.4 + (index % 159) * 0.02
    result = analyze_pcap(_established("silent", rtp=rtp))

    finding = next(item for item in result["findings"] if item.type == "rtp_silent_audio")
    assert finding.source_ip == CALLER
    summary = result["call_summaries"][0]
    assert summary["media_state"] == "silent_media"
    assert summary["verdict"]["status"] == "fail"
    assert summary["dtmf"]["silent_percent"] > 40


def test_loud_audio_is_not_silent():
    rtp = [make_rtp_packet(CALLER, PBX, 4000, 20000, seq, 160 * seq, 7) for seq in range(1, 160)]
    assert "rtp_silent_audio" not in _types(analyze_pcap(_established("loud", rtp=rtp)))


def test_rfc4733_digits_are_extracted_per_key_press():
    rtp = []
    sequence = 1
    for digit in (1, 2, 11):
        for end in (False, False, True, True, True):
            body = bytes([digit, 0x80 if end else 0x00, 0x03, 0x20])
            rtp.append(
                make_rtp_packet(CALLER, PBX, 4000, 20000, sequence, 1000 * digit, 7, payload_type=101, payload=body)
            )
            sequence += 1
    result = analyze_pcap(_established("dtmf", rtp=rtp))
    assert result["call_summaries"][0]["dtmf"]["rfc4733"] == {f"{CALLER} -> {PBX}": "12#"}


def test_answer_without_common_codec_and_without_dtmf():
    answer = ANSWER_SDP.replace(b"m=audio 20000 RTP/AVP 0 101", b"m=audio 20000 RTP/AVP 18").replace(
        b"a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n", b"a=rtpmap:18 G729/8000\r\n"
    )
    types = _types(analyze_pcap(_established("codec", answer=answer)))
    assert "sip_sdp_answer_codec_not_offered" in types
    assert "sip_sdp_dtmf_not_negotiated" in types


def test_answer_with_only_telephone_event_has_no_common_codec():
    answer = ANSWER_SDP.replace(b"RTP/AVP 0 101", b"RTP/AVP 101").replace(b"a=rtpmap:0 PCMU/8000\r\n", b"")
    assert "sip_sdp_no_common_codec" in _types(analyze_pcap(_established("nocodec", answer=answer)))


def test_invalid_answer_direction():
    offer = _invite(call_id="dir", body=SDP.replace(b"a=sendrecv", b"a=sendonly"))
    answer = ANSWER_SDP.replace(b"a=sendrecv", b"a=sendonly")
    result = analyze_pcap([_packet(offer), _packet(_ok_with_sdp("dir", answer), PBX, CALLER, 1.2)])
    assert "sip_sdp_direction_mismatch" in _types(result)


def test_private_contact_in_200_ok_explains_missing_ack():
    public_peer = "200.160.2.3"
    invite = _invite(call_id="nat")
    ok = _ok_with_sdp("nat", contact=b"<sip:1000@192.168.0.10:5060>")
    result = analyze_pcap([_packet(invite, CALLER, public_peer), _packet(ok, public_peer, CALLER, 1.2)])
    assert "sip_contact_private_address" in _types(result)
    verdict = result["call_summaries"][0]["verdict"]
    assert verdict["root_type"] == "sip_contact_private_address"
    assert verdict["culprit_ip"] == public_peer


def _register(cseq, auth=False, contact=b"<sip:200@192.168.0.5:5060>;expires=3600"):
    return (
        b"REGISTER sip:10.0.0.20 SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-r" + str(cseq).encode() + b"\r\n"
        b"Max-Forwards: 70\r\nFrom: <sip:200@10.0.0.20>;tag=r1\r\nTo: <sip:200@10.0.0.20>\r\n"
        b"Call-ID: reg-1\r\nCSeq: " + str(cseq).encode() + b" REGISTER\r\nContact: " + contact + b"\r\n"
        + (b'Authorization: Digest username="200", realm="fs", nonce="n", uri="sip:10.0.0.20", response="x"\r\n' if auth else b"")
        + b"Content-Length: 0\r\n\r\n"
    )


def _register_reply(cseq, code, reason):
    return (
        b"SIP/2.0 " + str(code).encode() + b" " + reason + b"\r\nVia: SIP/2.0/UDP 198.51.100.10:5060\r\n"
        b"From: <sip:200@10.0.0.20>;tag=r1\r\nTo: <sip:200@10.0.0.20>;tag=x\r\nCall-ID: reg-1\r\n"
        b"CSeq: " + str(cseq).encode() + b" REGISTER\r\nContent-Length: 0\r\n\r\n"
    )


def test_register_with_wrong_password_and_long_expires_behind_nat():
    endpoint = "200.160.2.3"
    result = analyze_pcap(
        [
            _packet(_register(1), endpoint, timestamp=1.0),
            _packet(_register_reply(1, 401, b"Unauthorized"), PBX, endpoint, 1.01),
            _packet(_register(2, auth=True), endpoint, timestamp=1.1),
            _packet(_register_reply(2, 401, b"Unauthorized"), PBX, endpoint, 1.11),
        ]
    )
    types = _types(result)
    assert "sip_register_auth_rejected" in types
    assert "sip_register_expires_nat" in types


def test_sip_over_tls_is_reported_as_unreadable():
    client_hello = bytes.fromhex("160301002d010000290303") + b"\x00" * 32 + bytes.fromhex("000002002f0100")
    packets = [
        IP(src=CALLER, dst=PBX) / TCP(sport=40000, dport=5061, flags="S", seq=1),
        IP(src=PBX, dst=CALLER) / TCP(sport=5061, dport=40000, flags="SA", seq=10, ack=2),
        IP(src=CALLER, dst=PBX) / TCP(sport=40000, dport=5061, flags="A", seq=2, ack=11),
        IP(src=CALLER, dst=PBX) / TCP(sport=40000, dport=5061, flags="PA", seq=2, ack=11) / client_hello,
    ]
    assert "sip_tls_signaling" in _types(analyze_pcap(packets))


def test_freeswitch_profile_predicts_codec_and_extension_rejections():
    settings = AnalysisSettings(
        target_platform="freeswitch",
        target_platform_ips=PBX,
        freeswitch_codecs="PCMA,G722",
        freeswitch_100rel=False,
    )
    invite = _invite(call_id="fsprof", extra=b"Require: 100rel\r\n")
    result = analyze_pcap([_packet(invite), _packet(_response(488, b"Not Acceptable Here", call_id="fsprof"), PBX, CALLER, 1.1)], settings)
    findings = {finding.type: finding for finding in result["findings"]}
    assert findings["freeswitch_codec_mismatch"].confirmed_by == "488 Not Acceptable Here"
    assert "freeswitch_profile_extension_disabled" in findings
    assert result["call_summaries"][0]["verdict"]["root_type"] == "freeswitch_codec_mismatch"


def test_ignored_custom_headers_and_trusted_peers():
    invite = _invite(call_id="xh", extra=b"X-Known: 1\r\n")
    settings = AnalysisSettings(target_platform="freeswitch", target_platform_ips=PBX, ignored_custom_headers="X-Known")
    assert "freeswitch_custom_header_input" not in _types(analyze_pcap([_packet(invite)], settings))
    settings = AnalysisSettings(target_platform="freeswitch", target_platform_ips=PBX, trusted_peer_ips="198.51.100.0/24")
    invite = _invite(call_id="xh2", extra=b"X-Other: 1\r\n")
    assert "freeswitch_custom_header_input" not in _types(analyze_pcap([_packet(invite)], settings))
