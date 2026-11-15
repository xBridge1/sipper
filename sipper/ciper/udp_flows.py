from ciper.models import UDPFlow
from ciper.packets import ensure_decoded


def build_udp_flows(packets):
    flows = {}

    for packet in packets:
        packet = ensure_decoded(packet)
        if not packet.ip_version or packet.transport != "UDP":
            continue

        source_port = packet.sport
        destination_port = packet.dport
        if source_port == 0 or destination_port == 0:
            continue

        endpoint_a = (packet.src, source_port)
        endpoint_b = (packet.dst, destination_port)
        flow_key = (endpoint_a, endpoint_b) if endpoint_a <= endpoint_b else (endpoint_b, endpoint_a)

        flow = flows.get(flow_key)
        if flow is None:
            flow = UDPFlow(
                source_ip=packet.src,
                source_port=source_port,
                destination_ip=packet.dst,
                destination_port=destination_port,
            )
            flows[flow_key] = flow

        flow.packets.append(packet)
        flow.packet_count += 1

        timestamp = packet.time
        if flow.first_timestamp is None:
            flow.first_timestamp = timestamp
        flow.last_timestamp = timestamp

        flow.byte_count += 8 + len(packet.payload)

        if packet.src == flow.source_ip and source_port == flow.source_port:
            flow.packets_forward += 1
        else:
            flow.packets_reverse += 1

    return flows
