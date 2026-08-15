from scapy.all import IP, ICMP

from ciper.flows import build_icmp_flows
from ciper.detectors.icmp import detect_icmp_unreachable


def test_detect_icmp_destination_unreachable():
    packets = [
        IP(src="192.168.1.20", dst="192.168.1.10")
        / ICMP(type=3, code=3)
    ]

    flows = build_icmp_flows(packets)

    findings = detect_icmp_unreachable(flows)

    assert len(findings) == 1
    assert findings[0].type == "icmp_destination_unreachable"
    assert findings[0].severity == "high"