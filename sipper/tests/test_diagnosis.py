from ciper.engine import analyze_pcap
from ciper.settings import AnalysisSettings
from ciper.sip_status import USER_OUTCOME_CODES, sip_status_info
from tests.test_sip_header_hygiene import CALLER, PBX, _invite, _packet, _response


def _failed_call(code, reason, settings=None):
    return analyze_pcap(
        [
            _packet(_invite(call_id=f"call-{code}")),
            _packet(_response(code, reason, call_id=f"call-{code}"), PBX, CALLER, 1.2),
        ],
        settings,
    )


def test_status_table_classifies_user_outcomes():
    assert {480, 486, 487, 600, 603} <= USER_OUTCOME_CODES
    assert sip_status_info(488).blame == "negotiation"
    assert sip_status_info(503).blame == "responder"
    assert sip_status_info(400).blame == "requester"
    assert sip_status_info(499).blame == "requester"  # class default
    assert "USER_BUSY" in sip_status_info(486).freeswitch


def test_busy_call_is_a_normal_outcome_not_a_failure():
    result = _failed_call(486, b"Busy Here")

    finding = next(item for item in result["findings"] if item.type == "sip_error_response")
    assert finding.severity == "low"
    verdict = result["call_summaries"][0]["verdict"]
    assert verdict["status"] == "user"
    assert "nao e falha tecnica" in verdict["headline"]


def test_488_points_at_negotiation_between_both_sides():
    result = _failed_call(488, b"Not Acceptable Here")

    verdict = result["call_summaries"][0]["verdict"]
    assert verdict["status"] == "fail"
    assert verdict["root_type"] == "sip_error_response"
    assert "Negociacao" in verdict["culprit"]
    assert any("INCOMPATIBLE_DESTINATION" in item for item in result["findings"][0].evidence + [
        line for finding in result["findings"] for line in finding.evidence
    ])


def test_503_from_freeswitch_names_the_platform():
    settings = AnalysisSettings(target_platform="freeswitch", target_platform_ips=PBX)
    result = _failed_call(503, b"Service Unavailable", settings)

    verdict = result["call_summaries"][0]["verdict"]
    assert verdict["culprit_ip"] == PBX
    assert "FreeSWITCH" in verdict["culprit"]
    diagnosis = result["diagnosis"]
    assert diagnosis["status"] == "fail"
    assert diagnosis["headline"].startswith("1 de 1 chamada(s) com falha - causa:")
    assert diagnosis["breakdown"][0]["type"] == "sip_error_response"


def test_unconfirmed_header_risk_does_not_outrank_the_final_response():
    invite = _invite(call_id="call-503").replace(b"Max-Forwards: 70\r\n", b"")
    result = analyze_pcap(
        [
            _packet(invite),
            _packet(_response(503, b"Service Unavailable", call_id="call-503"), PBX, CALLER, 1.2),
        ]
    )

    verdict = result["call_summaries"][0]["verdict"]
    assert verdict["root_type"] == "sip_error_response"
    assert "sip_header_missing_max_forwards" in verdict["symptoms"]


def test_clean_call_verdict_is_ok():
    result = analyze_pcap(
        [
            _packet(_invite(call_id="ok-call")),
            _packet(
                _response(200, b"OK", call_id="ok-call", extra=b"Contact: <sip:1000@10.0.0.20>\r\n"),
                PBX,
                CALLER,
                1.5,
            ),
        ]
    )

    verdict = result["call_summaries"][0]["verdict"]
    # No ACK was captured, so the call is not clean: the verdict must say so.
    assert verdict["status"] == "fail"
    assert verdict["root_type"] == "sip_ok_without_ack"
