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


def test_time_exceeded_finding_uses_the_actual_error_packet_direction():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20") / ICMP(type=8, code=0),
        IP(src="192.168.1.20", dst="192.168.1.10") / ICMP(type=11, code=0),
    ]

    finding = detect_icmp_time_exceeded(build_icmp_flows(packets))[0]

    assert finding.source_ip == "192.168.1.20"
    assert finding.destination_ip == "192.168.1.10"
