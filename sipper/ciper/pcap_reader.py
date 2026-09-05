from scapy.all import rdpcap
from scapy.utils import PcapReader


def read_pcap(file_path):
    packets = rdpcap(file_path)

    return {
        "packet_count": len(packets),
        "packets": packets,
    }


def iter_pcap(file_path):
    reader = PcapReader(file_path)

    try:
        for packet in reader:
            yield packet
    finally:
        reader.close()
