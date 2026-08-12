from scapy.layers.inet import IP, TCP

from ciper.flows import build_tcp_flows
from ciper.tcp_tracker import track_tcp_packets


def test_tcp_tracker_detects_retransmission():
    packets = [
        IP(src="192.168.10.10", dst="192.168.10.20")
        / TCP(
            sport=50000,
            dport=80,
            flags="PA",
            seq=1001,
            ack=5001,
        )
        / b"HELLO",

        IP(src="192.168.10.10", dst="192.168.10.20")
        / TCP(
            sport=50000,
            dport=80,
            flags="PA",
            seq=1001,
            ack=5001,
        )
        / b"HELLO",
    ]

    flows = build_tcp_flows(packets)

    flow = next(iter(flows.values()))

    events = track_tcp_packets(packets, flow)

    assert len(events) == 2

    assert events[0].event_type == "new"
    assert events[1].event_type == "retransmission"

    assert events[0].payload_length == 5
    assert events[1].payload_length == 5


def test_tcp_tracker_does_not_flag_ack_as_retransmission():
    packets = [
        IP(src="192.168.10.10", dst="192.168.10.20")
        / TCP(
            sport=50000,
            dport=80,
            flags="A",
            seq=1001,
            ack=5001,
        ),

        IP(src="192.168.10.10", dst="192.168.10.20")
        / TCP(
            sport=50000,
            dport=80,
            flags="A",
            seq=1001,
            ack=5001,
        ),
    ]

    flows = build_tcp_flows(packets)

    flow = next(iter(flows.values()))

    events = track_tcp_packets(packets, flow)

    assert len(events) == 2

    assert events[0].event_type == "new"
    assert events[1].event_type == "new"

    assert events[0].payload_length == 0
    assert events[1].payload_length == 0