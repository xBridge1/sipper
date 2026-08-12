from scapy.layers.inet import IP, TCP

from ciper.flows import build_tcp_flows


def test_bidirectional_tcp_packets_belong_to_same_flow():
    packet_1 = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S")
    )

    packet_2 = (
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="SA")
    )

    flows = build_tcp_flows([packet_1, packet_2])

    assert len(flows) == 1

    flow = next(iter(flows.values()))

    assert flow.packet_count == 2


def test_tcp_handshake_is_detected():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S"),

        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="SA"),

        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="A"),
    ]

    flows = build_tcp_flows(packets)

    assert len(flows) == 1

    flow = next(iter(flows.values()))

    assert flow.syn is True
    assert flow.syn_ack is True
    assert flow.ack is True
    assert flow.established is True


def test_tcp_flow_ignores_port_zero():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=0, dport=0, flags="S")
    )

    flows = build_tcp_flows([packet])

    assert len(flows) == 0

def test_tcp_flow_tracks_packets_and_bytes():
    packet_1 = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S")
    )

    packet_2 = (
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="SA")
    )

    packet_1.time = 100.0
    packet_2.time = 101.5

    flows = build_tcp_flows([packet_1, packet_2])

    flow = next(iter(flows.values()))

    assert flow.packet_count == 2
    assert flow.byte_count == len(packet_1) + len(packet_2)

    assert flow.packets_forward == 1
    assert flow.packets_reverse == 1

    assert flow.first_timestamp == 100.0
    assert flow.last_timestamp == 101.5

    assert flow.duration == 1.5

def test_tcp_handshake_time():
    packet_1 = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S")
    )

    packet_2 = (
        IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=443, dport=50000, flags="SA")
    )

    packet_1.time = 100.0
    packet_2.time = 100.250

    flows = build_tcp_flows([packet_1, packet_2])

    flow = next(iter(flows.values()))

    assert flow.syn_timestamp == 100.0
    assert flow.syn_ack_timestamp == 100.250
    assert flow.handshake_time == 0.250