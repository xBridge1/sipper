import struct

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.l2 import CookedLinux, Dot1Q, Ether
from scapy.utils import PcapNgWriter, wrpcap

from ciper.analyzer import classify_packet
from ciper.engine import analyze_pcap_file
from ciper.packets import (
    LINKTYPE_ETHERNET,
    LINKTYPE_RAW,
    TCP_ACK,
    TCP_SYN,
    decode_frame,
    ensure_decoded,
)
from ciper.pcap_reader import iter_pcap

MACS = {"src": "00:11:22:33:44:55", "dst": "66:77:88:99:aa:bb"}


def _sip_invite(call_id="abc@host"):
    return (
        "INVITE sip:200@10.0.0.2 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n"
        "From: <sip:100@10.0.0.1>;tag=1\r\n"
        "To: <sip:200@10.0.0.2>\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode()


def test_decodes_ethernet_udp_and_strips_padding():
    frame = bytes(Ether(**MACS) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1000, dport=2000) / b"hi")
    packet = decode_frame(LINKTYPE_ETHERNET, frame + b"\x00" * 10, 12.5)

    assert packet.ip_version == 4
    assert (packet.src, packet.dst, packet.sport, packet.dport) == ("10.0.0.1", "10.0.0.2", 1000, 2000)
    assert packet.transport == "UDP"
    assert packet.payload == b"hi"
    assert packet.time == 12.5
    assert len(packet) == len(frame) + 10


def test_tcp_payload_excludes_ethernet_padding():
    frame = bytes(Ether(**MACS) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5, dport=6, flags="A"))
    packet = decode_frame(LINKTYPE_ETHERNET, frame + b"\x00" * 6)

    assert packet.transport == "TCP"
    assert packet.tcp_flags == TCP_ACK
    assert packet.payload == b""


def test_decodes_vlan_tagged_tcp():
    frame = bytes(
        Ether(**MACS) / Dot1Q(vlan=10) / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=40000, dport=443, flags="S", seq=99)
    )
    packet = decode_frame(LINKTYPE_ETHERNET, frame)

    assert packet.transport == "TCP"
    assert packet.tcp_flags == TCP_SYN
    assert packet.tcp_seq == 99
    assert packet.dport == 443


def test_decodes_ipv4_fragments_like_scapy():
    first = ensure_decoded(IP(src="1.1.1.1", dst="2.2.2.2", id=7, flags="MF") / UDP(sport=5060, dport=5060) / (b"x" * 32))
    later = ensure_decoded(IP(src="1.1.1.1", dst="2.2.2.2", id=7, frag=5, proto=17) / (b"y" * 16))

    assert first.fragmented and first.more_fragments and first.fragment_offset == 0
    assert first.transport == "UDP"
    assert later.fragmented and later.fragment_offset == 40
    assert later.transport == ""
    assert later.payload == b"y" * 16
    assert later.ip_id == 7


def test_decodes_ipv6_fragment_header():
    packet = ensure_decoded(
        IPv6(src="2001:db8::1", dst="2001:db8::2")
        / IPv6ExtHdrFragment(id=0x1234, m=1, offset=0)
        / UDP(sport=5060, dport=5060)
        / (b"z" * 24)
    )

    assert packet.ip_version == 6
    assert packet.src == "2001:db8::1"
    assert packet.fragmented and packet.more_fragments
    assert packet.ip_id == 0x1234
    assert packet.transport == "UDP"


def test_icmp_error_is_not_counted_as_udp():
    packet = ensure_decoded(
        IP(src="2.2.2.2", dst="1.1.1.1")
        / ICMP(type=3, code=3)
        / IP(src="1.1.1.1", dst="2.2.2.2")
        / UDP(sport=5060, dport=5060)
    )

    assert packet.transport == "ICMP"
    assert (packet.icmp_type, packet.icmp_code) == (3, 3)
    assert classify_packet(packet) == "ICMP"


def test_non_ip_frame_is_kept_without_network_layer():
    packet = decode_frame(LINKTYPE_ETHERNET, b"\xff" * 12 + b"\x08\x06" + b"\x00" * 28)

    assert packet.ip_version == 0
    assert classify_packet(packet) is None


def test_truncated_frames_do_not_raise():
    full = bytes(IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=2))
    for size in range(len(full)):
        decode_frame(LINKTYPE_RAW, full[:size])


def test_classification_is_cached_and_shared_with_sip_parser():
    packet = ensure_decoded(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5060, dport=5060) / _sip_invite())

    assert classify_packet(packet) == "SIP"
    assert packet._sip is not None
    assert packet._sip.call_id == "abc@host"


def test_reads_nanosecond_pcap(tmp_path):
    path = tmp_path / "nano.pcap"
    frame = bytes(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2) / b"x")
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, LINKTYPE_RAW))
        handle.write(struct.pack("<IIII", 100, 250_000_000, len(frame), len(frame)))
        handle.write(frame)

    packets = list(iter_pcap(path))

    assert len(packets) == 1
    assert abs(packets[0].time - 100.25) < 1e-9
    assert packets[0].transport == "UDP"


def test_reads_big_endian_pcap(tmp_path):
    path = tmp_path / "big.pcap"
    frame = bytes(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2) / b"x")
    with open(path, "wb") as handle:
        handle.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_RAW))
        handle.write(struct.pack(">IIII", 7, 500_000, len(frame), len(frame)))
        handle.write(frame)

    packets = list(iter_pcap(path))

    assert packets[0].time == 7.5
    assert packets[0].src == "10.0.0.1"


def test_reads_pcapng_capture(tmp_path):
    path = tmp_path / "capture.pcapng"
    packets = [
        Ether(**MACS) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5060, dport=5060) / _sip_invite(),
        Ether(**MACS) / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=5060, dport=5060) / b"SIP/2.0 100 Trying\r\n\r\n",
    ]
    packets[0].time = 1000.125
    packets[1].time = 1000.5
    writer = PcapNgWriter(str(path))
    for packet in packets:
        writer.write(packet)
    writer.close()

    decoded = list(iter_pcap(path))

    assert len(decoded) == 2
    assert abs(decoded[0].time - 1000.125) < 1e-6
    assert decoded[0].transport == "UDP"
    assert classify_packet(decoded[0]) == "SIP"


def test_reads_linux_cooked_capture(tmp_path):
    path = tmp_path / "sll.pcap"
    wrpcap(str(path), [CookedLinux(proto=0x0800) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags="S")])

    packets = list(iter_pcap(path))

    assert packets[0].transport == "TCP"
    assert packets[0].tcp_flags == TCP_SYN


def test_truncated_capture_yields_complete_packets(tmp_path):
    path = tmp_path / "cut.pcap"
    wrpcap(str(path), [IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2) / (b"x" * 50)] * 3)
    data = path.read_bytes()
    path.write_bytes(data[:-20])

    assert len(list(iter_pcap(path))) == 2


def test_iter_pcap_reports_progress(tmp_path):
    path = tmp_path / "progress.pcap"
    wrpcap(str(path), [IP() / UDP(sport=1, dport=2)] * 10)
    calls = []

    list(iter_pcap(path, progress=lambda done, total: calls.append((done, total))))

    assert calls[-1][0] == calls[-1][1] == path.stat().st_size


def test_analyze_pcap_file_reports_monotonic_progress(tmp_path):
    path = tmp_path / "stages.pcap"
    wrpcap(str(path), [IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5060, dport=5060) / _sip_invite()])
    fractions = []

    analyze_pcap_file(str(path), progress=lambda stage, fraction: fractions.append(fraction))

    assert fractions == sorted(fractions)
    assert fractions[-1] == 1.0
