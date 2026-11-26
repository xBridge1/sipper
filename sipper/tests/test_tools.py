import json

from scapy.utils import wrpcap

from ciper.engine import analyze_pcap
from ciper.gui.flow_focus import culprit_messages, message_html
from ciper.gui.viewmodels import build_dashboard_viewmodel
from ciper.main import main
from ciper.settings import AnalysisSettings
from ciper.sip import parse_sip_message
from ciper.ticket import build_call_ticket, build_capture_ticket
from tests.test_culprit_precision import EXTENSION, _leg_b_invite
from tests.test_sip_header_hygiene import CALLER, PBX, _invite, _packet, _response


def _duplicate_capture():
    return [
        _packet(_invite(call_id="dup", extra=b"Call-ID: dup-copy\r\n"), timestamp=1.0),
        _packet(_response(400, b"Bad Request", call_id="dup"), PBX, CALLER, 1.05),
    ]


def test_unicode_digit_in_numeric_header_does_not_crash_the_parser():
    payload = _invite(call_id="u").replace(b"CSeq: 1 INVITE", b"CSeq: \xb2 INVITE")
    payload = payload.replace(b"m=audio 4000", b"m=audio \xb24000")
    message = parse_sip_message(_packet(payload))
    assert message is not None
    assert message.cseq_number is None


def test_ticket_text_contains_verdict_culprit_and_offending_lines():
    result = analyze_pcap(_duplicate_capture())
    text = build_capture_ticket(result["diagnosis"], "x.pcap", result["capture_point"])
    assert "Veredito: FALHA" in text
    assert "Provavel culpado: 198.51.100.10" in text
    assert "Call-ID: dup-copy" in text
    assert "Confirmado pela resposta: 400 Bad Request" in text
    viewmodel = build_dashboard_viewmodel({"protocols": {"SIP": 2}}, result)
    call_text = build_call_ticket(viewmodel["calls"][0])
    assert "Call-ID: dup" in call_text


def test_flow_focus_points_at_the_offending_message_and_lines():
    result = analyze_pcap(_duplicate_capture())
    viewmodel = build_dashboard_viewmodel({"protocols": {"SIP": 2}}, result)
    call = viewmodel["calls"][0]
    flow = result["sip_flows"][call["dialog_key"]]
    findings = [item for item in viewmodel["findings"] if "Call-ID: dup" in item["evidence"]]
    focus = culprit_messages(flow, findings, call["verdict"])
    root_index = min(focus, key=lambda index: focus[index]["rank"])
    assert flow.messages[root_index].method == "INVITE"
    html = message_html(flow.messages[root_index], focus[root_index], {"danger": "#f00"}, str)
    assert "<span style='background:#f00; color:#FFFFFF;'>Call-ID: dup-copy</span>" in html


def test_leg_a_relay_is_not_marked_as_root_cause():
    settings = AnalysisSettings(target_platform="freeswitch", target_platform_ips=PBX)
    result = analyze_pcap(
        [
            _packet(_invite(call_id="leg-a"), timestamp=1.0),
            _packet(_leg_b_invite(), PBX, EXTENSION, 1.1),
            _packet(_response(500, b"Server Internal Error", call_id="leg-b"), EXTENSION, PBX, 2.0),
            _packet(_response(503, b"Service Unavailable", call_id="leg-a"), PBX, CALLER, 2.05),
        ],
        settings,
    )
    viewmodel = build_dashboard_viewmodel({"protocols": {"SIP": 4}}, result)
    errors = {
        next(item for item in finding["evidence"] if item.startswith("Call-ID: ")): finding
        for finding in viewmodel["findings"]
        if finding["type"] == "sip_error_response"
    }
    assert errors["Call-ID: leg-a"]["is_root_cause"] is False
    assert "perna B" in errors["Call-ID: leg-a"]["culprit"]
    assert errors["Call-ID: leg-b"]["is_root_cause"] is True


def test_cli_json_and_fail_on_exit_code(tmp_path, capsys):
    pcap = tmp_path / "dup.pcap"
    wrpcap(str(pcap), _duplicate_capture())
    output = tmp_path / "out.json"

    code = main([str(pcap), "--json", str(output), "--fail-on", "fail", "--no-user-settings"])

    assert code == 2
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["diagnosis"]["root_type"] == "sip_header_duplicate_singleton"
    assert "Provavel culpado" in capsys.readouterr().out
    assert main([str(pcap), "--fail-on", "risk", "--no-user-settings", "--ticket"]) == 2


def test_cli_reports_missing_file(capsys):
    assert main(["nao-existe.pcap", "--no-user-settings"]) == 1
