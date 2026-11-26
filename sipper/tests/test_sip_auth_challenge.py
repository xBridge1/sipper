"""401/407 digest challenges are part of SIP negotiation, not call failures."""

from scapy.layers.inet import IP, UDP

from ciper.engine import analyze_pcap
from ciper.sip import build_sip_flows

UA = "10.0.0.20"
PROXY = "198.51.100.10"
SDP = b"v=0\r\nc=IN IP4 10.0.0.20\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n"


def _pkt(payload, source, destination, timestamp):
    packet = IP(src=source, dst=destination) / UDP(sport=5060, dport=5060) / payload
    packet.time = timestamp
    return packet


def _request(method, cseq, branch, to_tag=None, credentials=False, body=b""):
    message = (
        f"{method} sip:5511@198.51.100.10 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 10.0.0.20:5060;branch=z9hG4bK{branch}\r\n"
        "From: <sip:1000@10.0.0.20>;tag=ua1\r\n"
        "To: <sip:5511@198.51.100.10>" + (f";tag={to_tag}" if to_tag else "") + "\r\n"
        f"Call-ID: auth-call\r\nCSeq: {cseq} {method}\r\n"
    ).encode()
    if credentials:
        message += b'Proxy-Authorization: Digest username="1000", realm="px", nonce="n", response="r"\r\n'
    if body:
        message += b"Content-Type: application/sdp\r\n"
    return message + b"Content-Length: %d\r\n\r\n" % len(body) + body


def _response(status, cseq, method, branch, to_tag, body=b""):
    message = (
        f"SIP/2.0 {status}\r\n"
        f"Via: SIP/2.0/UDP 10.0.0.20:5060;branch=z9hG4bK{branch}\r\n"
        "From: <sip:1000@10.0.0.20>;tag=ua1\r\n"
        "To: <sip:5511@198.51.100.10>" + (f";tag={to_tag}" if to_tag else "") + "\r\n"
        f"Call-ID: auth-call\r\nCSeq: {cseq} {method}\r\n"
    ).encode()
    if status.startswith("407"):
        message += b'Proxy-Authenticate: Digest realm="px", nonce="n"\r\n'
    if status.startswith("401"):
        message += b'WWW-Authenticate: Digest realm="px", nonce="n"\r\n'
    if body:
        message += b"Content-Type: application/sdp\r\n"
    return message + b"Content-Length: %d\r\n\r\n" % len(body) + body


def _challenge(status="407 Proxy Authentication Required"):
    return [
        _pkt(_request("INVITE", 1, "a", body=SDP), UA, PROXY, 0.00),
        _pkt(_response(status, 1, "INVITE", "a", "proxy-challenge"), PROXY, UA, 0.02),
        _pkt(_request("ACK", 1, "a", to_tag="proxy-challenge"), UA, PROXY, 0.03),
    ]


def _authenticated_call(status="407 Proxy Authentication Required"):
    return _challenge(status) + [
        _pkt(_request("INVITE", 2, "b", credentials=True, body=SDP), UA, PROXY, 0.05),
        _pkt(_response("200 OK", 2, "INVITE", "b", "callee", body=SDP), PROXY, UA, 1.00),
        _pkt(_request("ACK", 2, "c", to_tag="callee"), UA, PROXY, 1.01),
        _pkt(_request("BYE", 3, "d", to_tag="callee"), UA, PROXY, 5.00),
        _pkt(_response("200 OK", 3, "BYE", "d", "callee"), PROXY, UA, 5.01),
    ]


def _error_findings(result):
    return [finding for finding in result["findings"] if finding.type == "sip_error_response"]


def test_407_challenge_followed_by_authenticated_call_is_not_a_failure():
    result = analyze_pcap(_authenticated_call())

    assert _error_findings(result) == []
    assert len(result["call_summaries"]) == 1
    summary = result["call_summaries"][0]
    assert summary["signaling_state"] == "terminated"
    assert "407" not in summary["verdict"]["headline"]


def test_401_challenge_followed_by_authenticated_call_is_not_a_failure():
    result = analyze_pcap(_authenticated_call("401 Unauthorized"))

    assert _error_findings(result) == []
    assert len(result["call_summaries"]) == 1


def test_challenge_and_authenticated_retry_share_one_flow_without_reinvite():
    flows = build_sip_flows(_authenticated_call())

    assert len(flows) == 1
    flow = next(iter(flows.values()))
    assert flow.dialog_key == "auth-call|ua1|callee"
    assert flow.invites == 2
    assert flow.reinvites == 0
    assert any(message.status_code == 407 for message in flow.messages)


def test_challenge_repeated_after_credentials_is_still_a_failure():
    packets = _challenge() + [
        _pkt(_request("INVITE", 2, "b", credentials=True, body=SDP), UA, PROXY, 0.05),
        _pkt(_response("407 Proxy Authentication Required", 2, "INVITE", "b", "proxy-again"), PROXY, UA, 0.07),
        _pkt(_request("ACK", 2, "b", to_tag="proxy-again"), UA, PROXY, 0.08),
    ]

    result = analyze_pcap(packets)
    errors = _error_findings(result)

    assert len(result["call_summaries"]) == 1
    assert len(errors) == 1
    assert "407" in errors[0].description


def test_challenge_never_answered_with_credentials_is_still_a_failure():
    result = analyze_pcap(_challenge())

    assert len(_error_findings(result)) == 1
    assert result["call_summaries"][0]["signaling_state"] == "failed"


def test_491_on_reinvite_inside_established_call_is_negotiation_not_failure():
    packets = _authenticated_call()[:6] + [
        _pkt(_request("INVITE", 3, "e", to_tag="callee", body=SDP), UA, PROXY, 2.00),
        _pkt(_response("491 Request Pending", 3, "INVITE", "e", "callee"), PROXY, UA, 2.01),
        _pkt(_request("ACK", 3, "e", to_tag="callee"), UA, PROXY, 2.02),
        _pkt(_request("BYE", 4, "f", to_tag="callee"), UA, PROXY, 5.00),
        _pkt(_response("200 OK", 4, "BYE", "f", "callee"), PROXY, UA, 5.01),
    ]

    result = analyze_pcap(packets)

    assert _error_findings(result) == []
    assert result["call_summaries"][0]["signaling_state"] == "terminated"


def test_491_to_initial_invite_is_still_reported():
    packets = [
        _pkt(_request("INVITE", 1, "a", body=SDP), UA, PROXY, 0.00),
        _pkt(_response("491 Request Pending", 1, "INVITE", "a", "x"), PROXY, UA, 0.02),
    ]

    assert len(_error_findings(analyze_pcap(packets))) == 1
