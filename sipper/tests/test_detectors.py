from scapy.layers.inet import IP, TCP

from ciper.flows import build_tcp_flows
from ciper.detectors.tcp import detect_syn_failures

from ciper.detectors.tcp import (
    detect_syn_failures,
    detect_slow_handshakes,
)


def test_detect_tcp_syn_failure():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S")
    )

    flows = build_tcp_flows([packet])

    findings = detect_syn_failures(flows)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.type == "tcp_syn_failure"
    assert finding.severity == "high"
    assert finding.source_ip == "192.168.1.10"
    assert finding.destination_ip == "192.168.1.20"
    assert "SYN observed: yes" in finding.evidence
    assert "SYN/ACK observed: no" in finding.evidence


def test_no_syn_failure_when_handshake_succeeds():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S"),

        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="SA"),

        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="A"),
    ]

    flows = build_tcp_flows(packets)

    findings = detect_syn_failures(flows)

    assert len(findings) == 0

def test_detect_slow_tcp_handshake():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S"),

        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="SA"),
    ]

    packets[0].time = 100.0
    packets[1].time = 100.8

    flows = build_tcp_flows(packets)

    findings = detect_slow_handshakes(flows)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.type == "tcp_slow_handshake"
    assert finding.severity == "high"

def test_fast_tcp_handshake_has_no_finding():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S"),

        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="SA"),
    ]

    packets[0].time = 100.0
    packets[1].time = 100.020

    flows = build_tcp_flows(packets)

    findings = detect_slow_handshakes(flows)

    assert len(findings) == 0


