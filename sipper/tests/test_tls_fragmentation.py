from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.packet import Raw

from ciper.engine import analyze_pcap


def _tls_record(content_type, payload, version=b"\x03\x03"):
    return bytes([content_type]) + version + len(payload).to_bytes(2, "big") + payload


def _tls_handshake(handshake_type, body=b"\x03\x03"):
    return bytes([handshake_type]) + len(body).to_bytes(3, "big") + body


def _tcp_packet(source, destination, source_port, destination_port, payload, flags="PA"):
    return (
        IP(src=source, dst=destination)
        / TCP(sport=source_port, dport=destination_port, flags=flags)
        / Raw(payload)
    )


def test_engine_detects_tls_fatal_alert():
    client_hello = _tls_record(22, _tls_handshake(1))
    fatal_alert = _tls_record(21, b"\x02\x28")
    packets = [
        _tcp_packet("192.168.1.10", "192.168.1.20", 50000, 5061, client_hello),
        _tcp_packet("192.168.1.20", "192.168.1.10", 5061, 50000, fatal_alert),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "tls_fatal_alert" in finding_types
    assert len(result["tls_flows"]) == 1


def test_engine_detects_tls_client_hello_without_server_hello():
    client_hello = _tls_record(22, _tls_handshake(1))
    packets = [
        _tcp_packet("192.168.1.10", "192.168.1.20", 50000, 443, client_hello),
        _tcp_packet("192.168.1.20", "192.168.1.10", 443, 50000, b"", flags="R"),
    ]

    result = analyze_pcap(packets)
    tls_finding = next(
        finding
        for finding in result["findings"]
        if finding.type == "tls_client_hello_no_response"
    )

    assert tls_finding.severity == "high"


def test_engine_detects_legacy_tls_version():
    tls_one_zero_client_hello = _tls_record(22, _tls_handshake(1, b"\x03\x01"), b"\x03\x01")
    packets = [
        _tcp_packet("192.168.1.10", "192.168.1.20", 50000, 443, tls_one_zero_client_hello),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "tls_legacy_version" in finding_types


def test_engine_detects_incomplete_ip_fragment_set():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20", id=17, flags="MF") / Raw(b"fragment"),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "ip_fragment_incomplete" in finding_types


def test_engine_detects_overlapping_ip_fragments():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20", id=18, flags="MF") / Raw(b"0123456789abcdef"),
        IP(src="192.168.1.10", dst="192.168.1.20", id=18, frag=1) / Raw(b"overlap"),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "ip_fragment_overlap" in finding_types


def test_engine_reports_complete_ip_fragmentation_as_low_risk():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20", id=19, flags="MF") / Raw(b"0123456789abcdef"),
        IP(src="192.168.1.10", dst="192.168.1.20", id=19, frag=2) / Raw(b"lastpart"),
    ]

    result = analyze_pcap(packets)
    fragmentation_finding = next(
        finding for finding in result["findings"] if finding.type == "ip_fragmentation"
    )

    assert fragmentation_finding.severity == "low"


def test_engine_detects_incomplete_ipv6_fragment_set():
    packets = [
        IPv6(src="2001:db8::10", dst="2001:db8::20")
        / IPv6ExtHdrFragment(id=20, m=1)
        / Raw(b"fragment"),
    ]

    result = analyze_pcap(packets)
    finding_types = {finding.type for finding in result["findings"]}

    assert "ip_fragment_incomplete" in finding_types
