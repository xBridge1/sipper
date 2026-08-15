from scapy.all import IP, ICMP

from ciper.flows import build_icmp_flows
from ciper.detectors.icmp import detect_icmp_no_response


def test_detect_icmp_echo_without_reply():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / ICMP(type=8)
    ]

    flows = build_icmp_flows(packets)

    findings = detect_icmp_no_response(flows)

    assert len(findings) == 1
    assert findings[0].type == "icmp_no_response"
    assert findings[0].severity == "medium"


def test_icmp_echo_with_reply_no_finding():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / ICMP(type=8),

        IP(src="192.168.1.20", dst="192.168.1.10")
        / ICMP(type=0),
    ]

    flows = build_icmp_flows(packets)

    findings = detect_icmp_no_response(flows)

    assert len(findings) == 0

def test_detect_icmp_partial_response():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / ICMP(type=8),

        IP(src="192.168.1.10", dst="192.168.1.20")
        / ICMP(type=8),

        IP(src="192.168.1.20", dst="192.168.1.10")
        / ICMP(type=0),
    ]

    flows = build_icmp_flows(packets)

    findings = detect_icmp_no_response(flows)

    assert len(findings) == 0