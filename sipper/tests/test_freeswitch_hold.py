from scapy.layers.inet import IP, UDP

from ciper.engine import analyze_pcap
from ciper.settings import AnalysisSettings

CARRIER = "198.51.100.10"
FREESWITCH = "10.0.0.20"


def _sip(payload, source=CARRIER, destination=FREESWITCH, timestamp=1.0):
    packet = IP(src=source, dst=destination) / UDP(sport=5060, dport=5060) / payload
    packet.time = timestamp
    return packet


def _settings():
    return AnalysisSettings(target_platform="freeswitch", target_platform_ips=FREESWITCH)


def _invite(cseq, direction=None, to_tag=True, address=b"198.51.100.10"):
    sdp = b"v=0\r\nc=IN IP4 " + address + b"\r\nm=audio 4000 RTP/AVP 0 101\r\n"
    sdp += b"a=rtpmap:101 telephone-event/8000\r\n"
    if direction:
        sdp += b"a=" + direction.encode() + b"\r\n"
    return (
        b"INVITE sip:1771@10.0.0.20 SIP/2.0\r\n"
        b"Call-ID: carrier-hold\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        + (b"To: <sip:1771@10.0.0.20>;tag=fs\r\n" if to_tag else b"To: <sip:1771@10.0.0.20>\r\n")
        + b"CSeq: " + str(cseq).encode() + b" INVITE\r\n"
        b"Content-Type: application/sdp\r\n\r\n" + sdp
    )


def _reject(cseq, status=b"491 Request Pending"):
    return (
        b"SIP/2.0 " + status + b"\r\n"
        b"Call-ID: carrier-hold\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"To: <sip:1771@10.0.0.20>;tag=fs\r\n"
        b"CSeq: " + str(cseq).encode() + b" INVITE\r\n\r\n"
    )


def _ok(cseq, direction=None):
    sdp = b"v=0\r\nc=IN IP4 10.0.0.20\r\nm=audio 5000 RTP/AVP 0 101\r\n"
    sdp += b"a=rtpmap:101 telephone-event/8000\r\n"
    if direction:
        sdp += b"a=" + direction.encode() + b"\r\n"
    return (
        b"SIP/2.0 200 OK\r\n"
        b"Call-ID: carrier-hold\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"To: <sip:1771@10.0.0.20>;tag=fs\r\n"
        b"CSeq: " + str(cseq).encode() + b" INVITE\r\n"
        b"Content-Type: application/sdp\r\n\r\n" + sdp
    )


def _bye(cseq):
    return (
        b"BYE sip:1771@10.0.0.20 SIP/2.0\r\n"
        b"Call-ID: carrier-hold\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"To: <sip:1771@10.0.0.20>;tag=fs\r\n"
        b"CSeq: " + str(cseq).encode() + b" BYE\r\n\r\n"
    )


def _holds(packets):
    result = analyze_pcap(packets, _settings())
    return [f for f in result["findings"] if f.type == "freeswitch_callcenter_midcall_hold"]


def test_carrier_sendonly_reinvite_is_flagged_even_when_resumed():
    packets = [
        _sip(_invite(1, to_tag=False), timestamp=0.0),
        _sip(_ok(1), source=FREESWITCH, destination=CARRIER, timestamp=0.02),
        _sip(_invite(2, "sendonly"), timestamp=7.65),
        _sip(_ok(2, "recvonly"), source=FREESWITCH, destination=CARRIER, timestamp=7.67),
        _sip(_invite(3), timestamp=10.42),
        _sip(_ok(3), source=FREESWITCH, destination=CARRIER, timestamp=10.43),
        _sip(_bye(4), timestamp=20.89),
    ]

    holds = _holds(packets)

    assert len(holds) == 1
    finding = holds[0]
    assert finding.severity == "high"
    assert finding.source_ip == CARRIER
    assert finding.destination_ip == FREESWITCH
    assert "SDP direction: sendonly" in finding.evidence
    assert "FreeSWITCH answer direction: recvonly" in finding.evidence
    assert any(item.startswith("Hold duration: 2.77s (retomada") for item in finding.evidence)
    assert any("call-queues" in ref["url"] for ref in finding.references)


def test_hold_never_resumed_reports_until_bye():
    packets = [
        _sip(_invite(1, to_tag=False), timestamp=0.0),
        _sip(_invite(2, "inactive"), timestamp=5.0),
        _sip(_bye(3), timestamp=9.0),
    ]

    holds = _holds(packets)

    assert len(holds) == 1
    assert any(item == "Hold duration: 4.00s (nao retomado ate BYE)" for item in holds[0].evidence)
    assert "terminou ainda em espera" in holds[0].description


def test_hold_sent_by_freeswitch_itself_is_not_flagged():
    packets = [
        _sip(_invite(1, to_tag=False), timestamp=0.0),
        _sip(_invite(2, "sendonly"), source=FREESWITCH, destination=CARRIER, timestamp=5.0),
    ]

    assert _holds(packets) == []


def test_reinvite_without_hold_is_not_flagged():
    packets = [
        _sip(_invite(1, to_tag=False), timestamp=0.0),
        _sip(_invite(2, "sendrecv"), timestamp=5.0),
    ]

    assert _holds(packets) == []


def test_hold_rejected_by_freeswitch_is_not_a_hold():
    packets = [
        _sip(_invite(1, to_tag=False), timestamp=0.0),
        _sip(_invite(2, "sendonly"), timestamp=5.0),
        _sip(_reject(2), source=FREESWITCH, destination=CARRIER, timestamp=5.01),
        _sip(_bye(3), timestamp=9.0),
    ]

    result = analyze_pcap(packets, _settings())
    operations = result["call_summaries"][0]["signaling_operations"]

    assert [f for f in result["findings"] if f.type == "freeswitch_callcenter_midcall_hold"] == []
    # The rejected offer must not count as a hold either, or it would
    # explain away RTP gaps that a hold never caused.
    assert operations["holds"] == 0
    assert operations["reinvites"] == 1


def test_resume_rejected_keeps_the_hold_open_until_bye():
    packets = [
        _sip(_invite(1, to_tag=False), timestamp=0.0),
        _sip(_invite(2, "sendonly"), timestamp=5.0),
        _sip(_ok(2, "recvonly"), source=FREESWITCH, destination=CARRIER, timestamp=5.01),
        _sip(_invite(3), timestamp=6.0),
        _sip(_reject(3, b"488 Not Acceptable Here"), source=FREESWITCH, destination=CARRIER, timestamp=6.01),
        _sip(_bye(4), timestamp=9.0),
    ]

    holds = _holds(packets)

    assert len(holds) == 1
    assert "Hold duration: 4.00s (nao retomado ate BYE)" in holds[0].evidence


def test_call_that_starts_on_hold_is_left_to_the_initial_offer_rule():
    packets = [
        _sip(_invite(1, "sendonly", to_tag=False), timestamp=0.0),
        _sip(_invite(2, "sendonly"), timestamp=5.0),
        _sip(_bye(3), timestamp=9.0),
    ]

    result = analyze_pcap(packets, _settings())
    types = [finding.type for finding in result["findings"]]

    assert "freeswitch_unidirectional_initial_offer" in types
    assert "freeswitch_callcenter_midcall_hold" not in types


def test_legacy_zero_address_hold_is_described_by_its_connection_line():
    packets = [
        _sip(_invite(1, to_tag=False), timestamp=0.0),
        _sip(_invite(2, address=b"0.0.0.0"), timestamp=5.0),
        _sip(_invite(3), timestamp=7.0),
    ]

    holds = _holds(packets)

    assert len(holds) == 1
    assert "Hold type: c=0.0.0.0" in holds[0].evidence
    assert "(c=0.0.0.0)" in holds[0].description


def test_freeswitch_reinvite_with_same_cseq_number_does_not_hide_carrier_hold():
    # Each side keeps its own CSeq counter: FreeSWITCH's own CSeq 2 must not be
    # mistaken for a retransmission of the carrier's CSeq 2 hold.
    fs_refresh = _invite(2, "sendrecv", address=b"10.0.0.20")
    packets = [
        _sip(_invite(1, to_tag=False), timestamp=0.0),
        _sip(fs_refresh, source=FREESWITCH, destination=CARRIER, timestamp=3.0),
        _sip(_invite(2, "sendonly"), timestamp=5.0),
        _sip(_bye(3), timestamp=9.0),
    ]

    result = analyze_pcap(packets, _settings())
    holds = [f for f in result["findings"] if f.type == "freeswitch_callcenter_midcall_hold"]
    operations = result["call_summaries"][0]["signaling_operations"]

    assert len(holds) == 1
    assert operations["reinvites"] == 2
    assert operations["holds"] == 1
