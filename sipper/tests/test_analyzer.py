from scapy.layers.inet import IP, TCP, UDP

from ciper.analyzer import analyze_packets


def test_analyze_tcp_packet():
    packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
        sport=12345,
        dport=443,
    )

    result = analyze_packets([packet])

    assert result["protocols"]["TCP"] == 1
    assert result["source_ips"]["192.168.1.10"] == 1
    assert result["destination_ips"]["192.168.1.20"] == 1