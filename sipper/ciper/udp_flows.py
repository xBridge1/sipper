from collections import defaultdict

from scapy.layers.inet import UDP

from ciper.models import UDPFlow
from ciper.network import get_ip_addresses, get_network_layer


def build_udp_flows(packets):
    packet_groups = defaultdict(list)

    for packet in packets:
        if get_network_layer(packet) is None or UDP not in packet:
            continue

        source_ip, destination_ip = get_ip_addresses(packet)
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
            source_ip=get_ip_addresses(first_packet)[0],
            source_port=first_packet[UDP].sport,
            destination_ip=get_ip_addresses(first_packet)[1],
            destination_port=first_packet[UDP].dport,
        )

        for packet in flow_packets:
            flow.packets.append(packet)
            flow.packet_count += 1

            timestamp = float(packet.time)

            if flow.first_timestamp is None:
                flow.first_timestamp = timestamp

            flow.last_timestamp = timestamp

            if UDP in packet:
                flow.byte_count += len(bytes(packet[UDP]))

            if (
                get_ip_addresses(packet)[0] == flow.source_ip
                and packet[UDP].sport == flow.source_port
            ):
                flow.packets_forward += 1
            else:
                flow.packets_reverse += 1

        flows[flow_key] = flow

    return flows
