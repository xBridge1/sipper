from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6


def get_network_layer(packet):
    if IP in packet:
        return packet[IP]
    if IPv6 in packet:
        return packet[IPv6]
    return None


def get_ip_addresses(packet):
    network_layer = get_network_layer(packet)
    if network_layer is None:
        return "", ""
    return network_layer.src, network_layer.dst
