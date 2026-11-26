from ciper.engine import analyze_pcap
from ciper.q850 import parse_q850_reason
from ciper.settings import AnalysisSettings
from tests.test_rtp import make_rtp_packet
from tests.test_sip_header_hygiene import CALLER, PBX, _invite, _packet, _response

EXTENSION = "10.0.0.30"


def _leg_b_invite(call_id="leg-b", number=b"1000"):
    return (
        _invite(call_id=call_id, start=b"INVITE sip:" + number + b"@10.0.0.30 SIP/2.0")
        .replace(b"Via: SIP/2.0/UDP 198.51.100.10:5060", b"Via: SIP/2.0/UDP 10.0.0.20:5060")
        .replace(b"Contact: <sip:alice@198.51.100.10:5060>", b"Contact: <sip:fs@10.0.0.20:5060>")
    )


def test_parse_q850_reason_header():
    cause, text = parse_q850_reason('Q.850;cause=34;text="NORMAL_CIRCUIT_CONGESTION"')
    assert cause.cause == 34
    assert cause.blame == "responder"
    assert text == "NORMAL_CIRCUIT_CONGESTION"
    assert parse_q850_reason("SIP;cause=200") == (None, None)


def test_q850_cause_overrides_sip_class_blame():
    result = analyze_pcap(
        [
            _packet(_invite(call_id="q850")),
            _packet(
                _response(503, b"Service Unavailable", call_id="q850", extra=b"Reason: Q.850;cause=17\r\n"),
                PBX,
                CALLER,
                1.2,
            ),
        ]
    )
    finding = next(item for item in result["findings"] if item.type == "sip_error_response")
    assert finding.severity == "low"
    assert "Q.850 cause: 17 - Usuario ocupado" in finding.evidence
    assert result["call_summaries"][0]["verdict"]["status"] == "user"


def test_bye_with_abnormal_q850_cause_is_a_dropped_call():
    bye = (
        b"BYE sip:alice@198.51.100.10 SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP 10.0.0.20:5060;branch=z9hG4bK-bye\r\nMax-Forwards: 70\r\n"
        b"From: <sip:1000@10.0.0.20>;tag=to1\r\nTo: <sip:alice@198.51.100.10>;tag=from1\r\n"
        b"Call-ID: dropped\r\nCSeq: 2 BYE\r\nReason: Q.850;cause=102\r\nContent-Length: 0\r\n\r\n"
    )
    result = analyze_pcap(
        [
            _packet(_invite(call_id="dropped")),
            _packet(_response(200, b"OK", call_id="dropped", extra=b"Contact: <sip:1000@10.0.0.20>\r\n"), PBX, CALLER, 1.5),
            _packet(bye, PBX, CALLER, 40.0),
        ]
    )
    finding = next(item for item in result["findings"] if item.type == "sip_abnormal_hangup")
    assert finding.culprit_ip == PBX
    hangup = result["call_summaries"][0]["hangup"]
    assert hangup["by"] == PBX
    assert hangup["q850"].startswith("102")


def test_invite_without_response_in_short_capture_is_not_called_a_timeout():
    result = analyze_pcap([_packet(_invite(call_id="short"), timestamp=1.0), _packet(_invite(call_id="x2"), PBX, CALLER, 3.0)])
    finding = next(item for item in result["findings"] if item.type == "sip_invite_no_response" and "short" in item.evidence[0])
    assert finding.severity == "medium"
    assert "Timer B" in finding.description


def test_invite_retransmitted_many_times_is_a_real_timeout_even_in_short_capture():
    invite = _invite(call_id="resent")
    packets = [_packet(invite, timestamp=1.0 + offset) for offset in (0, 0.5, 1.5, 3.5, 7.5)]
    finding = next(item for item in analyze_pcap(packets)["findings"] if item.type == "sip_invite_no_response")
    assert finding.severity == "high"


def test_capture_point_makes_one_way_audio_blame_the_silent_host():
    def call(call_id, port):
        return [
            _packet(_invite(call_id=call_id).replace(b"m=audio 4000", b"m=audio " + str(port).encode())),
            _packet(_response(200, b"OK", call_id=call_id, extra=b"Contact: <sip:1000@10.0.0.20>\r\n"), PBX, CALLER, 1.2),
            _packet(
                b"ACK sip:1000@10.0.0.20 SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-a\r\n"
                b"Max-Forwards: 70\r\nFrom: <sip:alice@198.51.100.10>;tag=from1\r\nTo: <sip:1000@10.0.0.20>;tag=to1\r\n"
                b"Call-ID: " + call_id.encode() + b"\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n",
                timestamp=1.3,
            ),
            *[
                make_rtp_packet(CALLER, PBX, port, 20000, sequence, 160 * sequence, 1000 + port)
                for sequence in range(1, 40)
            ],
        ]

    result = analyze_pcap(call("one-way-1", 4000) + call("one-way-2", 4100), AnalysisSettings(capture_point_ip=PBX))
    verdict = result["call_summaries"][0]["verdict"]
    assert result["capture_point"] == {"ip": PBX, "auto": False}
    assert verdict["culprit_ip"] == PBX
    assert "proprio host capturado" in verdict["culprit"]


def test_capture_point_is_detected_automatically():
    packets = [
        _packet(_invite(call_id=f"auto-{index}"), source=f"198.51.100.{20 + index}", timestamp=float(index))
        for index in range(3)
    ]
    assert analyze_pcap(packets)["capture_point"] == {"ip": PBX, "auto": True}
    # Every dialog between the same two hosts: both qualify, so no guess.
    same_pair = [_packet(_invite(call_id=f"pair-{index}"), timestamp=float(index)) for index in range(3)]
    assert analyze_pcap(same_pair)["capture_point"] == {"ip": None, "auto": False}


def test_leg_b_failure_is_propagated_to_leg_a():
    settings = AnalysisSettings(target_platform="freeswitch", target_platform_ips=PBX)
    result = analyze_pcap(
        [
            _packet(_invite(call_id="leg-a"), timestamp=1.0),
            _packet(_leg_b_invite(), PBX, EXTENSION, 1.1),
            _packet(_response(486, b"Busy Here", call_id="leg-b"), EXTENSION, PBX, 2.0),
            _packet(_response(486, b"Busy Here", call_id="leg-a"), PBX, CALLER, 2.05),
        ],
        settings,
    )
    summaries = {summary["call_id"]: summary for summary in result["call_summaries"]}
    leg_a, leg_b = summaries["leg-a"], summaries["leg-b"]
    assert leg_a["legs"]["role"] == "A"
    assert leg_b["legs"]["role"] == "B"
    assert leg_a["verdict"]["propagated_from"] == "leg-b"
    assert "perna B" in leg_a["verdict"]["headline"]
    assert result["diagnosis"]["calls"]["total"] == 1


def test_leg_b_server_error_blames_the_extension_not_freeswitch():
    settings = AnalysisSettings(target_platform="freeswitch", target_platform_ips=PBX)
    result = analyze_pcap(
        [
            _packet(_invite(call_id="leg-a"), timestamp=1.0),
            _packet(_leg_b_invite(), PBX, EXTENSION, 1.1),
            _packet(_response(500, b"Server Error", call_id="leg-b"), EXTENSION, PBX, 2.0),
            _packet(_response(503, b"Service Unavailable", call_id="leg-a"), PBX, CALLER, 2.05),
        ],
        settings,
    )
    leg_a = next(summary for summary in result["call_summaries"] if summary["call_id"] == "leg-a")
    assert leg_a["verdict"]["culprit_ip"] == EXTENSION
    assert result["diagnosis"]["culprit_ip"] == EXTENSION
