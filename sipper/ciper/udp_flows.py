from collections import defaultdict

from scapy.layers.inet import IP, UDP

from ciper.models import UDPFlow


def build_udp_flows(packets):
    packet_groups = defaultdict(list)

    for packet in packets:
        if IP not in packet or UDP not in packet:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

        if source_port == 0 or destination_port == 0:
            continue

        endpoint_a = (source_ip, source_port)
        endpoint_b = (destination_ip, destination_port)

        flow_key = tuple(sorted([endpoint_a, endpoint_b]))

        packet_groups[flow_key].append(packet)

    flows = {}

    for flow_key, flow_packets in packet_groups.items():
        first_packet = flow_packets[0]

        flow = UDPFlow(
            source_ip=first_packet[IP].src,
            source_port=first_packet[UDP].sport,
            destination_ip=first_packet[IP].dst,
            destination_port=first_packet[UDP].dport,
        )

        for packet in flow_packets:
            flow.packets.append(packet)
            flow.packet_count += 1

            if UDP in packet:
                flow.byte_count += len(bytes(packet[UDP]))

            if (
                packet[IP].src == flow.source_ip
                and packet[UDP].sport == flow.source_port
            ):
                flow.packets_forward += 1
            else:
                flow.packets_reverse += 1

        flows[flow_key] = flow

    return flows