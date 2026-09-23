from dataclasses import dataclass, field

from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP
from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment


@dataclass
class IPFragmentGroup:
    source_ip: str
    destination_ip: str
    protocol: int
    identification: int
    fragments: list[tuple[int, int]] = field(default_factory=list)
    has_initial_fragment: bool = False
    has_final_fragment: bool = False
    source_port: int | None = None
    destination_port: int | None = None
    source_port: int | None = None
    destination_port: int | None = None

    @property
    def fragment_count(self):
        return len(self.fragments)

    @property
    def has_overlap(self):
        previous_end = None
        for start, end in sorted(self.fragments):
            if previous_end is not None and start < previous_end:
                return True
            previous_end = end if previous_end is None else max(previous_end, end)
        return False

    @property
    def has_gap(self):
        if not self.has_initial_fragment or not self.has_final_fragment:
            return False

        previous_end = 0
        for start, end in sorted(self.fragments):
            if start > previous_end:
                return True
            previous_end = max(previous_end, end)
        return False

    @property
    def is_incomplete(self):
        return not self.has_initial_fragment or not self.has_final_fragment or self.has_gap


def build_ip_fragment_groups(packets):
    groups = {}

    for packet in packets:
        fragment = _extract_fragment(packet)
        if fragment is None:
            continue

        source_ip, destination_ip, protocol, identification, start, is_final, payload = fragment
        key = (source_ip, destination_ip, protocol, identification)
        group = groups.setdefault(
            key,
            IPFragmentGroup(
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                identification=identification,
            ),
        )
        end = start + len(payload)
        group.fragments.append((start, end))
        group.has_initial_fragment = group.has_initial_fragment or start == 0
        group.has_final_fragment = group.has_final_fragment or is_final
        if start == 0:
            source_port, destination_port = _extract_ports(packet)
            if source_port is not None:
                group.source_port = source_port
                group.destination_port = destination_port
        if start == 0:
            source_port, destination_port = _extract_ports(packet)
            if source_port is not None:
                group.source_port = source_port
                group.destination_port = destination_port

    return groups


def _extract_ports(packet):
    if TCP in packet:
        return int(packet[TCP].sport), int(packet[TCP].dport)
    if UDP in packet:
        return int(packet[UDP].sport), int(packet[UDP].dport)
    return None, None


def _extract_ports(packet):
    if TCP in packet:
        return int(packet[TCP].sport), int(packet[TCP].dport)
    if UDP in packet:
        return int(packet[UDP].sport), int(packet[UDP].dport)
    return None, None


def _extract_fragment(packet):
    if IP in packet:
        ip_packet = packet[IP]
        if not (ip_packet.flags.MF or ip_packet.frag > 0):
            return None
        return (
            ip_packet.src,
            ip_packet.dst,
            int(ip_packet.proto),
            int(ip_packet.id),
            int(ip_packet.frag) * 8,
            not bool(ip_packet.flags.MF),
            bytes(ip_packet.payload),
        )

    if IPv6 in packet and IPv6ExtHdrFragment in packet:
        ipv6_packet = packet[IPv6]
        fragment_header = packet[IPv6ExtHdrFragment]
        return (
            ipv6_packet.src,
            ipv6_packet.dst,
            int(fragment_header.nh),
            int(fragment_header.id),
            int(fragment_header.offset) * 8,
            not bool(fragment_header.m),
            bytes(fragment_header.payload),
        )

    return None
