"""Lightweight packet decoding.

Every analysis stage works on ``DecodedPacket`` records instead of scapy
objects. A record is decoded once, straight from the captured bytes, and holds
only the fields the analysis needs (addresses, ports, TCP state, fragment
information and the transport payload). This is an order of magnitude faster
than scapy dissection and uses far less memory.

Scapy packets are still accepted everywhere: ``ensure_decoded`` converts them by
decoding ``bytes(packet)``, so tests and external callers can keep building
packets with scapy.
"""

import socket
from struct import Struct

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_PPP = 9
LINKTYPE_RAW = 101
LINKTYPE_RAW_ALT = 12
LINKTYPE_RAW_OPENBSD = 14
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

_U16 = Struct("!H")
_IPV4 = Struct("!BBHHHBB2x4s4s")
_IPV6 = Struct("!IHBB16s16s")
_PORTS = Struct("!HH")
_TCP = Struct("!HHIIBB")
_UDP = Struct("!HHH")

_IPV6_EXTENSION_HEADERS = {0, 43, 60}
_IPV6_FRAGMENT = 44
_IPV6_AH = 51

_inet_ntoa = socket.inet_ntoa
_inet_ntop = socket.inet_ntop
_AF_INET6 = socket.AF_INET6

_UNSET = object()


class DecodedPacket:
    __slots__ = (
        "time",
        "length",
        "ip_version",
        "src",
        "dst",
        "proto",
        "ip_id",
        "more_fragments",
        "fragment_offset",
        "fragmented",
        "fragment_payload",
        "transport",
        "sport",
        "dport",
        "tcp_seq",
        "tcp_ack",
        "tcp_flags",
        "icmp_type",
        "icmp_code",
        "payload",
        "_kind",
        "_sip",
        "_rtp",
    )

    def __init__(self, time=0.0, length=0):
        self.time = time
        self.length = length
        self.ip_version = 0
        self.src = ""
        self.dst = ""
        self.proto = None
        self.ip_id = 0
        self.more_fragments = False
        self.fragment_offset = 0
        self.fragmented = False
        self.fragment_payload = b""
        self.transport = ""
        self.sport = 0
        self.dport = 0
        self.tcp_seq = 0
        self.tcp_ack = 0
        self.tcp_flags = 0
        self.icmp_type = None
        self.icmp_code = None
        self.payload = b""
        self._kind = _UNSET
        self._sip = _UNSET
        self._rtp = _UNSET

    def __len__(self):
        return self.length

    def __repr__(self):
        if self.transport in {"TCP", "UDP"}:
            endpoints = f"{self.src}:{self.sport} -> {self.dst}:{self.dport}"
        else:
            endpoints = f"{self.src} -> {self.dst}"
        return f"<DecodedPacket {self.transport or self.proto} {endpoints} t={self.time:.6f}>"

    @property
    def has_ip(self):
        return self.ip_version != 0

    @property
    def is_tcp(self):
        return self.transport == "TCP"

    @property
    def is_udp(self):
        return self.transport == "UDP"

    @property
    def is_icmp(self):
        return self.transport == "ICMP"


def decode_frame(linktype, data, timestamp=0.0):
    """Decode one captured frame into a ``DecodedPacket``.

    Unknown link types or non-IP frames produce a record without network
    information (``ip_version == 0``) so they are still counted.
    """
    packet = DecodedPacket(timestamp, len(data))
    offset = _network_offset(linktype, data)
    if offset is not None:
        _decode_ip(packet, data, offset)
    return packet


def ensure_decoded(packet):
    if type(packet) is DecodedPacket:
        return packet
    return from_scapy(packet)


def decode_all(packets):
    return [ensure_decoded(packet) for packet in packets]


def from_scapy(packet):
    """Convert a scapy packet (or any object exposing ``bytes()``/``time``)."""
    data = bytes(packet)
    timestamp = float(getattr(packet, "time", 0.0) or 0.0)
    return decode_frame(_scapy_linktype(packet, data), data, timestamp)


def _scapy_linktype(packet, data):
    name = type(packet).__name__
    if name in {"IP", "IPv6"}:
        return LINKTYPE_RAW
    if name == "Ether":
        return LINKTYPE_ETHERNET
    if name == "CookedLinux":
        return LINKTYPE_LINUX_SLL
    if name == "CookedLinuxV2":
        return LINKTYPE_LINUX_SLL2
    if name == "Loopback":
        return LINKTYPE_NULL
    if data and data[0] >> 4 in (4, 6):
        return LINKTYPE_RAW
    return LINKTYPE_ETHERNET


def _network_offset(linktype, data):
    size = len(data)
    if linktype == LINKTYPE_ETHERNET:
        if size < 14:
            return None
        ethertype = (data[12] << 8) | data[13]
        offset = 14
        return _resolve_ethertype(data, ethertype, offset)

    if linktype in (LINKTYPE_RAW, LINKTYPE_RAW_ALT, LINKTYPE_RAW_OPENBSD, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return 0 if size else None

    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        if size < 5:
            return None
        return 4 if data[4] >> 4 in (4, 6) else None

    if linktype == LINKTYPE_LINUX_SLL:
        if size < 16:
            return None
        return _resolve_ethertype(data, (data[14] << 8) | data[15], 16)

    if linktype == LINKTYPE_LINUX_SLL2:
        if size < 20:
            return None
        return _resolve_ethertype(data, (data[0] << 8) | data[1], 20)

    if linktype == LINKTYPE_PPP:
        offset = 2 if size >= 2 and data[0] == 0xFF and data[1] == 0x03 else 0
        if size < offset + 2:
            return None
        protocol = (data[offset] << 8) | data[offset + 1]
        if protocol == 0x0021 or protocol == 0x0057:
            return offset + 2
        return None

    return None


def _resolve_ethertype(data, ethertype, offset):
    size = len(data)
    # 802.1Q, 802.1ad and legacy QinQ tags.
    while ethertype in (0x8100, 0x88A8, 0x9100):
        if size < offset + 4:
            return None
        ethertype = (data[offset + 2] << 8) | data[offset + 3]
        offset += 4

    if ethertype == 0x0800 or ethertype == 0x86DD:
        return offset

    if ethertype == 0x8864:  # PPPoE session
        if size < offset + 8:
            return None
        protocol = (data[offset + 6] << 8) | data[offset + 7]
        if protocol == 0x0021 or protocol == 0x0057:
            return offset + 8
        return None

    if ethertype in (0x8847, 0x8848):  # MPLS label stack
        while size >= offset + 4:
            bottom_of_stack = data[offset + 2] & 0x01
            offset += 4
            if bottom_of_stack:
                if size > offset and data[offset] >> 4 in (4, 6):
                    return offset
                return None
        return None

    return None


def _decode_ip(packet, data, offset):
    size = len(data)
    if size <= offset:
        return

    version = data[offset] >> 4
    if version == 4:
        if size < offset + 20:
            return
        version_ihl, _tos, total_length, ip_id, flags_fragment, _ttl, proto, src, dst = _IPV4.unpack_from(data, offset)
        header_length = (version_ihl & 0x0F) * 4
        if header_length < 20:
            return
        packet.ip_version = 4
        packet.src = _inet_ntoa(src)
        packet.dst = _inet_ntoa(dst)
        packet.proto = proto
        packet.ip_id = ip_id
        more_fragments = bool(flags_fragment & 0x2000)
        fragment_offset = (flags_fragment & 0x1FFF) * 8
        packet.more_fragments = more_fragments
        packet.fragment_offset = fragment_offset

        end = offset + total_length if total_length >= header_length else size
        if end > size:
            end = size
        payload_start = offset + header_length
        if payload_start > end:
            return

        if more_fragments or fragment_offset:
            packet.fragmented = True
            packet.fragment_payload = data[payload_start:end]
            if fragment_offset:
                packet.payload = packet.fragment_payload
                return

        _decode_transport(packet, data, proto, payload_start, end, allow_icmp=True)
        return

    if version == 6:
        if size < offset + 40:
            return
        _vtc, payload_length, next_header, _hop_limit, src, dst = _IPV6.unpack_from(data, offset)
        packet.ip_version = 6
        packet.src = _inet_ntop(_AF_INET6, src)
        packet.dst = _inet_ntop(_AF_INET6, dst)
        end = offset + 40 + payload_length if payload_length else size
        if end > size:
            end = size
        cursor = offset + 40

        while True:
            if next_header in _IPV6_EXTENSION_HEADERS:
                if end < cursor + 2:
                    break
                following = data[cursor]
                cursor += (data[cursor + 1] + 1) * 8
                next_header = following
                continue
            if next_header == _IPV6_AH:
                if end < cursor + 2:
                    break
                following = data[cursor]
                cursor += (data[cursor + 1] + 2) * 4
                next_header = following
                continue
            if next_header == _IPV6_FRAGMENT:
                if end < cursor + 8:
                    break
                following = data[cursor]
                offset_flags = (data[cursor + 2] << 8) | data[cursor + 3]
                packet.ip_id = int.from_bytes(data[cursor + 4:cursor + 8], "big")
                packet.fragment_offset = (offset_flags >> 3) * 8
                packet.more_fragments = bool(offset_flags & 0x01)
                packet.fragmented = True
                cursor += 8
                next_header = following
                packet.proto = next_header
                packet.fragment_payload = data[cursor:end]
                if packet.fragment_offset:
                    packet.payload = packet.fragment_payload
                    return
                continue
            break

        packet.proto = next_header
        if cursor <= end:
            _decode_transport(packet, data, next_header, cursor, end, allow_icmp=False)


def _decode_transport(packet, data, proto, start, end, allow_icmp):
    available = end - start
    if proto == 6:
        if available < 20:
            return
        sport, dport, seq, ack, data_offset, flags = _TCP.unpack_from(data, start)
        header_length = (data_offset >> 4) * 4
        if header_length < 20:
            header_length = 20
        packet.transport = "TCP"
        packet.sport = sport
        packet.dport = dport
        packet.tcp_seq = seq
        packet.tcp_ack = ack
        packet.tcp_flags = flags
        payload_start = start + header_length
        if payload_start < end:
            packet.payload = data[payload_start:end]
        return

    if proto == 17:
        if available < 8:
            return
        sport, dport, udp_length = _UDP.unpack_from(data, start)
        packet.transport = "UDP"
        packet.sport = sport
        packet.dport = dport
        payload_end = end
        if udp_length >= 8 and start + udp_length < end:
            payload_end = start + udp_length
        if start + 8 < payload_end:
            packet.payload = data[start + 8:payload_end]
        return

    if proto == 1 and allow_icmp:
        if available < 4:
            return
        packet.transport = "ICMP"
        packet.icmp_type = data[start]
        packet.icmp_code = data[start + 1]
        if start + 8 < end:
            packet.payload = data[start + 8:end]
