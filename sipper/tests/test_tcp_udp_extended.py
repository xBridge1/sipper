from scapy.layers.inet import IP, TCP, UDP

from ciper.engine import analyze_pcap
from ciper.flows import build_tcp_flows
from ciper.udp_flows import build_udp_flows
from ciper.detectors.tcp import (
    detect_tcp_handshake_incomplete,
    detect_tcp_handshake_reset,
    detect_syn_failures,
    detect_tcp_retransmissions,
)
from ciper.detectors.udp import (
    detect_udp_burst_no_response,
    detect_udp_no_response,
)


def test_detect_tcp_handshake_incomplete():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S"),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="SA"),
    ]

    flows = build_tcp_flows(packets)

    findings = detect_tcp_handshake_incomplete(flows)

    assert len(findings) == 1
    assert findings[0].type == "tcp_handshake_incomplete"
    assert findings[0].severity == "medium"


def test_detect_tcp_handshake_reset():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S"),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="R"),
    ]

    flows = build_tcp_flows(packets)

    findings = detect_tcp_handshake_reset(flows)

    assert len(findings) == 1
    assert findings[0].type == "tcp_handshake_reset"
    assert findings[0].severity == "high"
    assert findings[0].source_ip == "192.168.1.20"
    assert findings[0].destination_ip == "192.168.1.10"


def test_tcp_syn_failure_not_reported_when_reset_is_present():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S"),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="R"),
    ]

    flows = build_tcp_flows(packets)

    findings = detect_syn_failures(flows)

    assert len(findings) == 0


def test_tcp_handshake_reset_not_reported_after_established_session():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S"),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="SA"),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="A"),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="R"),
    ]

    flows = build_tcp_flows(packets)

    findings = detect_tcp_handshake_reset(flows)

    assert len(findings) == 0


def test_udp_no_response_severity_increases_with_multiple_requests():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO1",
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO2",
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO3",
    ]

    flows = build_udp_flows(packets)

    findings = detect_udp_no_response(flows)

    assert len(findings) == 1
    assert findings[0].type == "udp_no_response"
    assert findings[0].severity == "high"


def test_build_udp_flow_tracks_timestamps_and_duration():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO",
        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=50000)
        / b"OK",
    ]

    packets[0].time = 100.0
    packets[1].time = 101.25

    flows = build_udp_flows(packets)
    flow = next(iter(flows.values()))

    assert flow.first_timestamp == 100.0
    assert flow.last_timestamp == 101.25
    assert flow.duration == 1.25


def test_engine_includes_new_tcp_finding():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S"),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="SA"),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "tcp_handshake_incomplete" in finding_types


def test_tcp_retransmission_severity_increases_with_volume():
    packets = [
        IP(src="192.168.10.10", dst="192.168.10.20")
        / TCP(sport=50000, dport=80, flags="PA", seq=1001, ack=5001)
        / b"HELLO",
        IP(src="192.168.10.10", dst="192.168.10.20")
        / TCP(sport=50000, dport=80, flags="PA", seq=1001, ack=5001)
        / b"HELLO",
        IP(src="192.168.10.10", dst="192.168.10.20")
        / TCP(sport=50000, dport=80, flags="PA", seq=1001, ack=5001)
        / b"HELLO",
    ]

    flows = build_tcp_flows(packets)

    findings = detect_tcp_retransmissions(flows)

    assert len(findings) == 1
    assert findings[0].type == "tcp_retransmission"
    assert findings[0].severity == "high"


def test_detect_udp_burst_no_response():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO1",
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO2",
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO3",
    ]

    packets[0].time = 100.0
    packets[1].time = 100.1
    packets[2].time = 100.2

    flows = build_udp_flows(packets)

    findings = detect_udp_burst_no_response(flows)

    assert len(findings) == 1
    assert findings[0].type == "udp_burst_no_response"
    assert findings[0].severity == "high"
