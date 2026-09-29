from pathlib import Path

from scapy.all import IP, Raw, TCP, UDP, wrpcap


OUTPUT_DIR = Path(__file__).parent


def build_tcp_retransmission_pcap():
    packets = []

    syn = (
        IP(src="192.168.10.10", dst="192.168.10.20")
        / TCP(sport=50000, dport=80, flags="S", seq=1000)
    )
    syn.time = 100.000
    packets.append(syn)

    syn_ack = (
        IP(src="192.168.10.20", dst="192.168.10.10")
        / TCP(sport=80, dport=50000, flags="SA", seq=5000, ack=1001)
    )
    syn_ack.time = 100.020
    packets.append(syn_ack)

    ack = (
        IP(src="192.168.10.10", dst="192.168.10.20")
        / TCP(sport=50000, dport=80, flags="A", seq=1001, ack=5001)
    )
    ack.time = 100.030
    packets.append(ack)

    data_1 = (
        IP(src="192.168.10.10", dst="192.168.10.20")
        / TCP(
            sport=50000,
            dport=80,
            flags="PA",
            seq=1001,
            ack=5001,
        )
        / b"HELLO"
    )
    data_1.time = 100.040
    packets.append(data_1)

    retransmission = (
        IP(src="192.168.10.10", dst="192.168.10.20")
        / TCP(
            sport=50000,
            dport=80,
            flags="PA",
            seq=1001,
            ack=5001,
        )
        / b"HELLO"
    )
    retransmission.time = 100.150
    packets.append(retransmission)

    return packets


def build_voip_quality_pcap():
    packets = [
        IP(src="192.168.60.10", dst="192.168.60.20")
        / UDP(sport=5060, dport=5060)
        / Raw(
            b"INVITE sip:200@pbx.test SIP/2.0\r\n"
            b"Call-ID: regression-quality\r\nCSeq: 1 INVITE\r\n\r\n"
            b"v=0\r\nc=IN IP4 192.168.60.10\r\nm=audio 4000 RTP/AVP 8\r\n"
        ),
        IP(src="192.168.60.20", dst="192.168.60.10")
        / UDP(sport=5060, dport=5060)
        / Raw(
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: regression-quality\r\nCSeq: 1 INVITE\r\n\r\n"
            b"v=0\r\nc=IN IP4 192.168.60.20\r\nm=audio 4002 RTP/AVP 8\r\n"
        ),
        IP(src="192.168.60.10", dst="192.168.60.20")
        / UDP(sport=5060, dport=5060)
        / Raw(b"ACK sip:200@pbx.test SIP/2.0\r\nCall-ID: regression-quality\r\nCSeq: 1 ACK\r\n\r\n"),
    ]
    packets.extend(
        [
            _rtp_packet("192.168.60.10", "192.168.60.20", 4000, 4002, 100, 160, 101),
            _rtp_packet("192.168.60.10", "192.168.60.20", 4000, 4002, 102, 480, 101),
            _rtp_packet("192.168.60.20", "192.168.60.10", 4002, 4000, 100, 160, 202),
        ]
    )
    for index, packet in enumerate(packets):
        packet.time = 200.0 + (index * 0.02)
    packets[-2].time = 200.24
    return packets


def build_tls_weak_cipher_pcap():
    hello = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x04\x00\x05\x13\x01"
        + b"\x01\x00"
        + b"\x00\x00"
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
    packet = IP(src="192.168.70.10", dst="192.168.70.20") / TCP(sport=50000, dport=443, seq=1) / Raw(record)
    packet.time = 300.0
    return [packet]


def _rtp_packet(source, destination, source_port, destination_port, sequence, timestamp, ssrc):
    header = bytes(
        [
            0x80,
            8,
            (sequence >> 8) & 0xFF,
            sequence & 0xFF,
            (timestamp >> 24) & 0xFF,
            (timestamp >> 16) & 0xFF,
            (timestamp >> 8) & 0xFF,
            timestamp & 0xFF,
            (ssrc >> 24) & 0xFF,
            (ssrc >> 16) & 0xFF,
            (ssrc >> 8) & 0xFF,
            ssrc & 0xFF,
        ]
    )
    return IP(src=source, dst=destination) / UDP(sport=source_port, dport=destination_port) / Raw(header + b"\x00" * 160)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    captures = {
        "tcp_retransmission.pcap": build_tcp_retransmission_pcap(),
        "voip_quality.pcap": build_voip_quality_pcap(),
        "tls_weak_cipher.pcap": build_tls_weak_cipher_pcap(),
    }

    for name, packets in captures.items():
        output_file = OUTPUT_DIR / name
        wrpcap(str(output_file), packets)
        print(f"Created: {output_file}")
        print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()
