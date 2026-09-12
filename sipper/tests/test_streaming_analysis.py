from scapy.layers.inet import IP, UDP
from scapy.utils import wrpcap

import ciper.engine as engine
from ciper.pcap_reader import iter_pcap


def test_analyze_pcap_file_streams_packets_from_disk(tmp_path):
    file_path = tmp_path / "streaming.pcap"
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=50000, dport=5060) / b"HELLO",
        IP(src="192.168.1.20", dst="192.168.1.10") / UDP(sport=5060, dport=50000) / b"OK",
    ]
    wrpcap(str(file_path), packets)

    result = engine.analyze_pcap_file(str(file_path))

    assert len(list(iter_pcap(str(file_path)))) == 2
    assert len(result["udp_flows"]) == 1
    assert result["findings"] == []


def test_analyze_pcap_file_reads_capture_once(monkeypatch):
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=50000, dport=5060) / b"HELLO",
        IP(src="192.168.1.20", dst="192.168.1.10") / UDP(sport=5060, dport=50000) / b"OK",
    ]
    read_count = 0

    def fake_iter_pcap(_file_path):
        nonlocal read_count
        read_count += 1
        return iter(packets)

    monkeypatch.setattr(engine, "iter_pcap", fake_iter_pcap)

    result = engine.analyze_pcap_file("capture.pcap")

    assert read_count == 1
    assert len(result["udp_flows"]) == 1
