from scapy.utils import PcapReader
from scapy.error import Scapy_Exception
from pathlib import Path
from struct import error as StructError


def read_pcap(file_path):
    packets = list(iter_pcap(file_path))

    return {
        "packet_count": len(packets),
        "packets": packets,
    }


def iter_pcap(file_path):
    path = validate_capture_file(file_path)

    try:
        reader = PcapReader(str(path))
    except (OSError, EOFError, Scapy_Exception, StructError) as error:
        raise PcapInputError(f"Falha ao abrir o arquivo PCAP: {path.name}") from error

    try:
        for packet in reader:
            yield packet
    except (OSError, EOFError, Scapy_Exception, StructError) as error:
        raise PcapInputError(f"Falha ao ler o arquivo PCAP: {path.name}") from error
    finally:
        reader.close()


def validate_capture_file(file_path):
    path = Path(file_path)

    if not path.is_file():
        raise PcapInputError("Arquivo PCAP nao encontrado")
    if path.suffix.lower() not in {".pcap", ".pcapng"}:
        raise PcapInputError("Selecione um arquivo .pcap ou .pcapng")
    if path.stat().st_size == 0:
        raise PcapInputError("Arquivo PCAP vazio")

    return path


class PcapInputError(ValueError):
    pass
