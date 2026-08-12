from pathlib import Path

from scapy.all import IP, TCP, wrpcap


OUTPUT_DIR = Path(__file__).parent / "pcaps"


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


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    output_file = OUTPUT_DIR / "tcp_retransmission.pcap"

    packets = build_tcp_retransmission_pcap()

    wrpcap(str(output_file), packets)

    print(f"Created: {output_file}")
    print(f"Packets: {len(packets)}")


if __name__ == "__main__":
    main()