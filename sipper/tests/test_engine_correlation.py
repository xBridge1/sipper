from scapy.layers.inet import IP, ICMP, UDP

from ciper.engine import analyze_pcap


def test_engine_correlates_udp_no_response_with_icmp_unreachable():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO",
        IP(src="192.168.1.20", dst="192.168.1.10")
        / ICMP(type=3, code=3),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "icmp_destination_unreachable" in finding_types
    assert "udp_service_unreachable" in finding_types
    assert "udp_no_response" not in finding_types
