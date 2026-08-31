from scapy.layers.inet import IP, ICMP

from ciper.engine import analyze_pcap
from ciper.flows import build_icmp_flows
from ciper.detectors.icmp import (
    detect_icmp_parameter_problem,
    detect_icmp_redirect,
    detect_icmp_unreachable,
)


def test_build_icmp_flows_tracks_redirect_and_parameter_problem():
    packets = [
        IP(src="192.168.1.1", dst="192.168.1.10") / ICMP(type=5, code=1),
        IP(src="192.168.1.2", dst="192.168.1.20") / ICMP(type=12, code=0),
    ]

    flows = build_icmp_flows(packets)

    assert len(flows) == 2

    redirect_flow = flows[("192.168.1.1", "192.168.1.10")]
    assert redirect_flow.redirect_messages == 1

    parameter_problem_flow = flows[("192.168.1.2", "192.168.1.20")]
    assert parameter_problem_flow.parameter_problem_messages == 1


def test_detect_icmp_fragmentation_needed():
    packets = [
        IP(src="192.168.1.20", dst="192.168.1.10") / ICMP(type=3, code=4),
    ]

    flows = build_icmp_flows(packets)

    findings = detect_icmp_unreachable(flows)

    assert len(findings) == 1
    assert findings[0].type == "icmp_fragmentation_needed"
    assert findings[0].severity == "high"


def test_detect_icmp_unreachable_multiple_codes_generate_multiple_findings():
    packets = [
        IP(src="192.168.1.20", dst="192.168.1.10") / ICMP(type=3, code=1),
        IP(src="192.168.1.20", dst="192.168.1.10") / ICMP(type=3, code=4),
    ]

    flows = build_icmp_flows(packets)

    findings = detect_icmp_unreachable(flows)
    finding_types = {finding.type for finding in findings}

    assert len(findings) == 2
    assert "icmp_host_unreachable" in finding_types
    assert "icmp_fragmentation_needed" in finding_types


def test_detect_icmp_redirect():
    packets = [
        IP(src="192.168.1.1", dst="192.168.1.10") / ICMP(type=5, code=1),
    ]

    flows = build_icmp_flows(packets)

    findings = detect_icmp_redirect(flows)

    assert len(findings) == 1
    assert findings[0].type == "icmp_redirect"
    assert findings[0].severity == "medium"


def test_detect_icmp_parameter_problem():
    packets = [
        IP(src="192.168.1.2", dst="192.168.1.20") / ICMP(type=12, code=0),
    ]

    flows = build_icmp_flows(packets)

    findings = detect_icmp_parameter_problem(flows)

    assert len(findings) == 1
    assert findings[0].type == "icmp_parameter_problem"
    assert findings[0].severity == "high"


def test_engine_includes_redirect_and_parameter_problem_findings():
    packets = [
        IP(src="192.168.1.1", dst="192.168.1.10") / ICMP(type=5, code=1),
        IP(src="192.168.1.2", dst="192.168.1.20") / ICMP(type=12, code=0),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "icmp_redirect" in finding_types
    assert "icmp_parameter_problem" in finding_types
