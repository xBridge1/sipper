import re
from pathlib import Path

from scapy.layers.inet import IP, UDP

from ciper.analyzer import analyze_packets
from ciper.engine import analyze_pcap
from ciper.gui.viewmodels import build_dashboard_viewmodel
from ciper.labels import (
    FINDING_TITLES,
    display_severity,
    finding_title,
    is_actionable,
    severity_label,
    state_label,
)

SOURCE_DIR = Path(__file__).resolve().parents[1] / "ciper"


def _emitted_finding_types():
    types = set()
    for path in [SOURCE_DIR / "engine.py", *(SOURCE_DIR / "detectors").glob("*.py")]:
        types.update(re.findall(r'type="([a-z0-9_]+)"', path.read_text(encoding="utf-8")))
    icmp_source = (SOURCE_DIR / "detectors" / "icmp.py").read_text(encoding="utf-8")
    types.update(re.findall(r'"(icmp_[a-z_]+)",\n\s+"ICMP', icmp_source))
    return types


def test_every_emitted_finding_type_has_a_portuguese_title():
    missing = sorted(_emitted_finding_types() - set(FINDING_TITLES))

    assert missing == []


def test_unknown_finding_type_falls_back_to_readable_text():
    assert finding_title("custom_new_problem") == "Custom new problem"
    assert finding_title(None) == "Sem incidente"


def test_call_progress_is_informational_not_a_problem():
    assert display_severity("sip_call_established", "low") == "info"
    assert display_severity("rtp_packet_loss", "high") == "high"
    assert not is_actionable({"type": "sip_call_terminated"})
    assert is_actionable({"type": "sip_error_response"})


def test_severity_and_state_labels_are_localized():
    assert severity_label("high") == "Alta"
    assert severity_label("info") == "Info"
    assert state_label("missing_ack") == "Sem ACK"
    assert state_label("brand_new_state") == "Brand new state"


def test_viewmodel_exposes_titles_and_display_severity():
    invite = (
        "INVITE sip:200@10.0.0.2 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n"
        "From: <sip:100@10.0.0.1>;tag=a\r\n"
        "To: <sip:200@10.0.0.2>\r\n"
        "Call-ID: label-test\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n"
    )
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5060, dport=5060) / invite
    packet.time = 1.0
    result = analyze_pcap([packet])

    viewmodel = build_dashboard_viewmodel(analyze_packets([packet]), result)
    finding = next(item for item in viewmodel["findings"] if item["type"] == "sip_invite_no_response")

    assert finding["title"] == "INVITE sem resposta"
    assert finding["severity_label"] == severity_label(finding["display_severity"])
    assert viewmodel["calls"][0]["signaling_state_label"] == state_label(viewmodel["calls"][0]["signaling_state"])
