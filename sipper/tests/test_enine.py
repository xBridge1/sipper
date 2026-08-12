from scapy.layers.inet import IP, TCP

from ciper.engine import analyze_pcap


def test_engine_detects_syn_failure():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S")
    )

    result = analyze_pcap([packet])

    assert len(result["flows"]) == 1
    assert len(result["findings"]) == 1

    finding = result["findings"][0]

    assert finding.type == "tcp_syn_failure"