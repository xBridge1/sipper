from dataclasses import dataclass, field

from ciper.models import TCPFlow
from ciper.packets import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, ensure_decoded


def build_tcp_flows(packets):
    flows = {}

    for packet in packets:
        packet = ensure_decoded(packet)
        if not packet.ip_version or packet.transport != "TCP":
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
            flow = TCPFlow(
                source_ip=packet.src,
                source_port=source_port,
                destination_ip=packet.dst,
                destination_port=destination_port,
            )
            flows[flow_key] = flow

        flow.packets.append(packet)
        flags = packet.tcp_flags

        flow.packet_count += 1
        flow.byte_count += packet.length

        timestamp = packet.time
        if flow.first_timestamp is None:
            flow.first_timestamp = timestamp
        flow.last_timestamp = timestamp

        if packet.src == flow.source_ip and source_port == flow.source_port:
            flow.packets_forward += 1
        else:
            flow.packets_reverse += 1

        syn = flags & TCP_SYN
        ack = flags & TCP_ACK

        if syn and not ack:
            flow.syn = True
            if flow.syn_timestamp is None:
                flow.syn_timestamp = timestamp

        if syn and ack:
            flow.syn_ack = True
            if flow.syn_ack_timestamp is None:
                flow.syn_ack_timestamp = timestamp

        if ack and not syn:
            flow.ack = True

        if flags & TCP_FIN:
            flow.fin = True

        if flags & TCP_RST:
            flow.rst = True

    return flows


@dataclass
class ICMPFlow:
    source_ip: str
    destination_ip: str
    echo_requests: int = 0
    echo_replies: int = 0
    unreachable_messages: int = 0
    time_exceeded_messages: int = 0
    redirect_messages: int = 0
    parameter_problem_messages: int = 0
    unreachable_codes: list[int] = field(default_factory=list)
    packets: list = field(default_factory=list)


def build_icmp_flows(packets):
    flows = {}

    for packet in packets:
        packet = ensure_decoded(packet)
        if packet.ip_version != 4 or packet.transport != "ICMP":
            continue

        icmp_type = packet.icmp_type

        if icmp_type not in (0, 3, 5, 8, 11, 12):
            continue

        source_ip = packet.src
        destination_ip = packet.dst

        if icmp_type == 0:
            key = (destination_ip, source_ip)
            reverse_key = (source_ip, destination_ip)
        else:
            key = (source_ip, destination_ip)
            reverse_key = (destination_ip, source_ip)

        if key in flows:
            flow = flows[key]
        elif reverse_key in flows:
            flow = flows[reverse_key]
        else:
            flow = ICMPFlow(
                source_ip=source_ip,
                destination_ip=destination_ip,
            )
            flows[key] = flow

        flow.packets.append(packet)

        if icmp_type == 8:
            flow.echo_requests += 1
        elif icmp_type == 0:
            flow.echo_replies += 1
        elif icmp_type == 3:
            flow.unreachable_messages += 1
            flow.unreachable_codes.append(packet.icmp_code)
        elif icmp_type == 5:
            flow.redirect_messages += 1
        elif icmp_type == 11:
            flow.time_exceeded_messages += 1
        elif icmp_type == 12:
            flow.parameter_problem_messages += 1

    return flows
