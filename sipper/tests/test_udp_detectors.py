from scapy.layers.inet import IP, UDP

from ciper.udp_flows import build_udp_flows
from ciper.detectors.udp import detect_udp_no_response


def test_detect_udp_no_response():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO"
    ]

    flows = build_udp_flows(packets)

    findings = detect_udp_no_response(flows)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.type == "udp_no_response"
    assert finding.severity == "medium"
    assert finding.source_ip == "192.168.1.10"
    assert finding.destination_ip == "192.168.1.20"

def test_udp_response_is_not_flagged():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO",

        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=50000)
        / b"OK",
    ]

    flows = build_udp_flows(packets)

    findings = detect_udp_no_response(flows)

    assert len(findings) == 0