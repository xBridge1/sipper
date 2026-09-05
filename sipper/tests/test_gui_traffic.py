from scapy.layers.inet import IP, UDP

from ciper.gui.app import _build_traffic_counts
from tests.test_rtp import make_rtp_packet


def test_build_traffic_counts_classifies_sip_rtp_and_udp():
    sip_packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:100@pbx.local SIP/2.0\r\n"
            b"Call-ID: traffic-call\r\n\r\n"
        )
    )
    rtp_packet = make_rtp_packet("192.168.1.10", "192.168.1.20", 4000, 4002, 100, 160, 1234)
    udp_packet = IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=1000, dport=1001) / b"data"
    for index, packet in enumerate([sip_packet, rtp_packet, udp_packet]):
        packet.time = 100.0 + index

    counters, labels, duration = _build_traffic_counts([sip_packet, rtp_packet, udp_packet])

    assert labels == ["00:00", "00:01", "00:02"]
    assert counters["SIP"] == [1, 0, 0]
    assert counters["RTP"] == [0, 1, 0]
    assert counters["UDP"] == [0, 0, 1]
    assert duration == 2.0


def test_build_traffic_counts_bounds_sparse_capture_series():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=1000, dport=1001) / b"first",
        IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=1000, dport=1001) / b"last",
    ]
    packets[0].time = 100.0
    packets[1].time = 100000.0

    counters, labels, duration = _build_traffic_counts(packets, max_bucket_count=60)

    assert len(labels) <= 60
    assert sum(counters["UDP"]) == 2
    assert duration == 99900.0
