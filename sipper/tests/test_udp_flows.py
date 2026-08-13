from scapy.layers.inet import IP, UDP

from ciper.udp_flows import build_udp_flows


def test_build_udp_flow():
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=50000, dport=5060),

        IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=5060, dport=50000),
    ]

    flows = build_udp_flows(packets)

    assert len(flows) == 1

    flow = next(iter(flows.values()))

    assert flow.packet_count == 2
    assert flow.packets_forward == 1
    assert flow.packets_reverse == 1