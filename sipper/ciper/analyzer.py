from collections import Counter

from scapy.layers.inet import IP, TCP, UDP, ICMP

from ciper.rtp import parse_rtp_packet
from ciper.sip import parse_sip_message


def analyze_packets(packets):
    protocols = Counter()
    source_ips = Counter()
    destination_ips = Counter()
    tcp_connections = Counter()

    for packet in packets:
        if IP not in packet:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        source_ips[source_ip] += 1
        destination_ips[destination_ip] += 1

        if parse_sip_message(packet) is not None:
            protocols["SIP"] += 1

        elif parse_rtp_packet(packet) is not None:
            protocols["RTP"] += 1

        elif TCP in packet:
            protocols["TCP"] += 1

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            connection = (
                source_ip,
                source_port,
                destination_ip,
                destination_port,
            )

            tcp_connections[connection] += 1

        elif UDP in packet:
            protocols["UDP"] += 1

        elif ICMP in packet:
            protocols["ICMP"] += 1

        else:
            protocols["Other"] += 1

    return {
        "protocols": protocols,
        "source_ips": source_ips,
        "destination_ips": destination_ips,
        "tcp_connections": tcp_connections,
    }
