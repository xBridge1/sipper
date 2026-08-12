from collections import Counter

from scapy.layers.inet import IP, TCP, UDP, ICMP


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

        if TCP in packet:
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