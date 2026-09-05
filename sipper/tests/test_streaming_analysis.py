from scapy.layers.inet import IP, UDP
from scapy.utils import wrpcap

from ciper.engine import analyze_pcap_file
from ciper.pcap_reader import iter_pcap


def test_analyze_pcap_file_streams_packets_from_disk(tmp_path):
    file_path = tmp_path / "streaming.pcap"
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=50000, dport=5060) / b"HELLO",
        IP(src="192.168.1.20", dst="192.168.1.10") / UDP(sport=5060, dport=50000) / b"OK",
    ]
    wrpcap(str(file_path), packets)

    result = analyze_pcap_file(str(file_path))

    assert len(list(iter_pcap(str(file_path)))) == 2
    assert len(result["udp_flows"]) == 1
    assert result["findings"] == []
