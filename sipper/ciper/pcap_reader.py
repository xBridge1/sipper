from scapy.all import rdpcap


def read_pcap(file_path):
    packets = rdpcap(file_path)

    return {
        "packet_count": len(packets),
        "packets": packets,
    }