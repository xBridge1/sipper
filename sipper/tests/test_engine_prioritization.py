from scapy.layers.inet import IP, ICMP, TCP, UDP

from ciper.engine import analyze_pcap


def test_engine_prefers_tcp_handshake_reset_over_tcp_reset():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S"),
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="R"),
    ]

    result = analyze_pcap(packets)
    finding_types = [finding.type for finding in result["findings"]]

    assert "tcp_handshake_reset" in finding_types
    assert "tcp_reset" not in finding_types


def test_engine_prefers_udp_service_unreachable_over_udp_no_response():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO",
        IP(src="192.168.1.20", dst="192.168.1.10")
        / ICMP(type=3, code=3),
    ]

    result = analyze_pcap(packets)
    finding_types = [finding.type for finding in result["findings"]]

    assert "udp_service_unreachable" in finding_types
    assert "udp_no_response" not in finding_types


def test_engine_prefers_udp_burst_no_response_over_udp_no_response():
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

    result = analyze_pcap(packets)
    finding_types = [finding.type for finding in result["findings"]]

    assert "udp_burst_no_response" in finding_types
    assert "udp_no_response" not in finding_types
