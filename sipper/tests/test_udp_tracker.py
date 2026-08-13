from scapy.layers.inet import IP, UDP

from ciper.udp_flows import build_udp_flows
from ciper.udp_tracker import track_udp_packets


def test_udp_tracker_detects_directions():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060)
        / b"HELLO",

        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=50000)
        / b"OK",
    ]

    flows = build_udp_flows(packets)

    flow = next(iter(flows.values()))

    events = track_udp_packets(packets, flow)

    assert len(events) == 2

    assert events[0].direction == "forward"
    assert events[0].payload_length == 5

    assert events[1].direction == "reverse"
    assert events[1].payload_length == 2