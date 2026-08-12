from collections import defaultdict

from scapy.layers.inet import IP, TCP

from ciper.models import TCPFlow


def build_tcp_flows(packets):
    packet_groups = defaultdict(list)

    # Primeiro agrupamos os pacotes por conexão
    for packet in packets:
        if IP not in packet or TCP not in packet:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        # Porta 0 não representa uma conexão TCP válida
        if source_port == 0 or destination_port == 0:
            continue

        endpoint_a = (source_ip, source_port)
        endpoint_b = (destination_ip, destination_port)

        flow_key = tuple(sorted([endpoint_a, endpoint_b]))

        packet_groups[flow_key].append(packet)

    # Depois transformamos cada grupo em um TCPFlow
    flows = {}

    for flow_key, flow_packets in packet_groups.items():
        first_packet = flow_packets[0]

        flow = TCPFlow(
            source_ip=first_packet[IP].src,
            source_port=first_packet[TCP].sport,
            destination_ip=first_packet[IP].dst,
            destination_port=first_packet[TCP].dport,
        )

        for packet in flow_packets:
            flow.packets.append(packet)
            flags = packet[TCP].flags

            flow.packet_count += 1
            flow.byte_count += len(packet)

            timestamp = float(packet.time)

            if flow.first_timestamp is None:
                flow.first_timestamp = timestamp

            flow.last_timestamp = timestamp

            if (
                packet[IP].src == flow.source_ip
                and packet[TCP].sport == flow.source_port
            ):
                flow.packets_forward += 1
            else:
                flow.packets_reverse += 1

            if "S" in flags and "A" not in flags:
                flow.syn = True

                if flow.syn_timestamp is None:
                    flow.syn_timestamp = timestamp

            if "S" in flags and "A" in flags:
                flow.syn_ack = True

                if flow.syn_ack_timestamp is None:
                    flow.syn_ack_timestamp = timestamp

            if "A" in flags and "S" not in flags:
                flow.ack = True

            if "F" in flags:
                flow.fin = True

            if "R" in flags:
                flow.rst = True

        flows[flow_key] = flow

    return flows