from scapy.layers.inet import IP, ICMP

from ciper.flows import build_icmp_flows
from ciper.detectors.icmp import detect_icmp_time_exceeded


def test_detect_icmp_time_exceeded():
    packets = [
        IP(src="192.168.1.1", dst="192.168.1.10")
        / ICMP(type=11, code=0)
    ]

    flows = build_icmp_flows(packets)

    findings = detect_icmp_time_exceeded(flows)

    assert len(findings) == 1
    assert findings[0].type == "icmp_time_exceeded"
    assert findings[0].severity == "high"