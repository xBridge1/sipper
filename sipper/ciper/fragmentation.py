from dataclasses import dataclass, field

from ciper.packets import ensure_decoded


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
    duplicate_fragments: int = 0
    fragment_payloads: dict[tuple[int, int, bool], bytes] = field(default_factory=dict, repr=False)

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
        packet = ensure_decoded(packet)
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
        fragment_range = (start, end, is_final)
        if (
            fragment_range in group.fragment_payloads
            and group.fragment_payloads[fragment_range] == payload
        ):
            group.duplicate_fragments += 1
            continue
        group.fragment_payloads.setdefault(fragment_range, payload)
        group.fragments.append((start, end))
        group.has_initial_fragment = group.has_initial_fragment or start == 0
        group.has_final_fragment = group.has_final_fragment or is_final
        if start == 0:
            source_port, destination_port = _extract_ports(packet)
            if source_port is not None:
                group.source_port = source_port
                group.destination_port = destination_port

    return groups


def _extract_ports(packet):
    if packet.transport in {"TCP", "UDP"}:
        return packet.sport, packet.dport
    return None, None


def _extract_fragment(packet):
    if not packet.fragmented or not packet.ip_version:
        return None
    return (
        packet.src,
        packet.dst,
        int(packet.proto or 0),
        packet.ip_id,
        packet.fragment_offset,
        not packet.more_fragments,
        packet.fragment_payload,
    )
