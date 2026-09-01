from scapy.layers.inet import IP, TCP, UDP

from ciper.analyzer import analyze_packets
from tests.test_rtp import make_rtp_packet


def test_analyze_tcp_packet():
    packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
        sport=12345,
        dport=443,
    )

    result = analyze_packets([packet])

    assert result["protocols"]["TCP"] == 1
    assert result["source_ips"]["192.168.1.10"] == 1
    assert result["destination_ips"]["192.168.1.20"] == 1


def test_analyze_packets_classifies_sip_and_rtp_before_udp():
    sip_packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: analyzer-call\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        )
    )
    rtp_packet = make_rtp_packet(
        "192.168.1.10", "192.168.1.20", 4000, 4002, 100, 160, 1234
    )
    udp_packet = IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=1, dport=2) / b"data"

    result = analyze_packets([sip_packet, rtp_packet, udp_packet])

    assert result["protocols"] == {"SIP": 1, "RTP": 1, "UDP": 1}
