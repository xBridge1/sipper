from ciper.packets import ensure_decoded


def get_network_layer(packet):
    """Return the decoded packet when it carries IPv4/IPv6, otherwise None."""
    packet = ensure_decoded(packet)
    return packet if packet.ip_version else None


def get_ip_addresses(packet):
    packet = ensure_decoded(packet)
    if not packet.ip_version:
        return "", ""
    return packet.src, packet.dst
