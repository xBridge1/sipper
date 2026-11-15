"""Fast native reader for pcap and pcapng captures.

Frames are decoded directly into ``DecodedPacket`` records (see
``ciper.packets``) without building scapy objects. Both classic pcap
(microsecond and nanosecond, either byte order) and pcapng (multiple
interfaces, per-interface timestamp resolution) are supported. A capture that
ends with a truncated record, which is common when a capture is interrupted,
yields every complete packet and stops cleanly.
"""

from pathlib import Path
from struct import Struct, error as StructError

from ciper.packets import decode_frame

PCAP_MAGIC_USEC = 0xA1B2C3D4
PCAP_MAGIC_NSEC = 0xA1B23C4D
PCAP_MAGIC_MODIFIED = 0xA1B2CD34
PCAPNG_SECTION_HEADER = 0x0A0D0D0A
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D

READ_BUFFER_BYTES = 1024 * 1024
PROGRESS_INTERVAL_PACKETS = 4096


class PcapInputError(ValueError):
    pass


def read_pcap(file_path):
    packets = list(iter_pcap(file_path))

    return {
        "packet_count": len(packets),
        "packets": packets,
    }


def iter_pcap(file_path, progress=None):
    """Yield ``DecodedPacket`` records from a pcap or pcapng file.

    ``progress``, when given, is called as ``progress(bytes_read, total_bytes)``
    periodically and once more when the file has been fully read.
    """
    path = validate_capture_file(file_path)
    total_bytes = path.stat().st_size

    try:
        handle = open(path, "rb", buffering=READ_BUFFER_BYTES)
    except OSError as error:
        raise PcapInputError(f"Falha ao abrir o arquivo PCAP: {path.name}") from error

    try:
        magic_bytes = handle.read(4)
        if len(magic_bytes) < 4:
            raise PcapInputError(f"Falha ao abrir o arquivo PCAP: {path.name}")

        if int.from_bytes(magic_bytes, "little") == PCAPNG_SECTION_HEADER:
            records = _iter_pcapng(handle, magic_bytes, path)
        else:
            records = _iter_pcap(handle, magic_bytes, path)

        count = 0
        for packet in records:
            yield packet
            count += 1
            if progress is not None and count % PROGRESS_INTERVAL_PACKETS == 0:
                progress(handle.tell(), total_bytes)
        if progress is not None:
            progress(total_bytes, total_bytes)
    except (OSError, StructError) as error:
        raise PcapInputError(f"Falha ao ler o arquivo PCAP: {path.name}") from error
    finally:
        handle.close()


def _iter_pcap(handle, magic_bytes, path):
    magic_le = int.from_bytes(magic_bytes, "little")
    magic_be = int.from_bytes(magic_bytes, "big")
    if magic_le in (PCAP_MAGIC_USEC, PCAP_MAGIC_NSEC, PCAP_MAGIC_MODIFIED):
        endian, magic = "<", magic_le
    elif magic_be in (PCAP_MAGIC_USEC, PCAP_MAGIC_NSEC, PCAP_MAGIC_MODIFIED):
        endian, magic = ">", magic_be
    else:
        raise PcapInputError(f"Falha ao abrir o arquivo PCAP: {path.name}")

    header = handle.read(20)
    if len(header) < 20:
        raise PcapInputError(f"Falha ao abrir o arquivo PCAP: {path.name}")
    _major, _minor, _zone, _sigfigs, _snaplen, linktype = Struct(endian + "HHiIII").unpack(header)
    linktype &= 0xFFFF

    divisor = 1_000_000_000 if magic == PCAP_MAGIC_NSEC else 1_000_000
    record_size = 24 if magic == PCAP_MAGIC_MODIFIED else 16
    record_header = Struct(endian + "IIII")
    read = handle.read
    unpack = record_header.unpack_from

    while True:
        header = read(record_size)
        if len(header) < record_size:
            return
        seconds, fraction, captured_length, _original_length = unpack(header)
        data = read(captured_length)
        if len(data) < captured_length:
            return
        yield decode_frame(linktype, data, seconds + fraction / divisor)


def _iter_pcapng(handle, first_bytes, path):
    read = handle.read
    endian = "<"
    interfaces = []
    previous_time = 0.0
    pending = first_bytes

    while True:
        head = pending + read(8 - len(pending))
        pending = b""
        if len(head) < 8:
            return

        block_type_le = int.from_bytes(head[:4], "little")
        if block_type_le == PCAPNG_SECTION_HEADER:
            magic = read(4)
            if len(magic) < 4:
                return
            if int.from_bytes(magic, "little") == PCAPNG_BYTE_ORDER_MAGIC:
                endian = "<"
            elif int.from_bytes(magic, "big") == PCAPNG_BYTE_ORDER_MAGIC:
                endian = ">"
            else:
                raise PcapInputError(f"Falha ao abrir o arquivo PCAP: {path.name}")
            block_length = int.from_bytes(head[4:8], "little" if endian == "<" else "big")
            if block_length < 28:
                raise PcapInputError(f"Falha ao ler o arquivo PCAP: {path.name}")
            rest = read(block_length - 12)
            if len(rest) < block_length - 12:
                return
            interfaces = []
            continue

        order = "little" if endian == "<" else "big"
        block_type = int.from_bytes(head[:4], order)
        block_length = int.from_bytes(head[4:8], order)
        if block_length < 12 or block_length % 4:
            raise PcapInputError(f"Falha ao ler o arquivo PCAP: {path.name}")
        body = read(block_length - 8)
        if len(body) < block_length - 8:
            return
        body = body[:-4]

        if block_type == 1:  # Interface Description Block
            linktype = int.from_bytes(body[0:2], order)
            interfaces.append(_parse_interface_options(body, order, linktype))
            continue

        if block_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                continue
            interface_id = int.from_bytes(body[0:4], order)
            timestamp_raw = (int.from_bytes(body[4:8], order) << 32) | int.from_bytes(body[8:12], order)
            captured_length = int.from_bytes(body[12:16], order)
            data = body[20:20 + captured_length]
            linktype, resolution, time_offset = _interface(interfaces, interface_id)
            previous_time = timestamp_raw / resolution + time_offset
            yield decode_frame(linktype, data, previous_time)
            continue

        if block_type == 3:  # Simple Packet Block
            if len(body) < 4:
                continue
            original_length = int.from_bytes(body[0:4], order)
            data = body[4:4 + original_length]
            linktype, _resolution, _offset = _interface(interfaces, 0)
            yield decode_frame(linktype, data, previous_time)
            continue

        if block_type == 2:  # Obsolete Packet Block
            if len(body) < 20:
                continue
            interface_id = int.from_bytes(body[0:2], order)
            timestamp_raw = (int.from_bytes(body[4:8], order) << 32) | int.from_bytes(body[8:12], order)
            captured_length = int.from_bytes(body[12:16], order)
            data = body[20:20 + captured_length]
            linktype, resolution, time_offset = _interface(interfaces, interface_id)
            previous_time = timestamp_raw / resolution + time_offset
            yield decode_frame(linktype, data, previous_time)


def _interface(interfaces, interface_id):
    if 0 <= interface_id < len(interfaces):
        return interfaces[interface_id]
    return (1, 1_000_000, 0)


def _parse_interface_options(body, order, linktype):
    resolution = 1_000_000
    time_offset = 0
    offset = 8
    while offset + 4 <= len(body):
        code = int.from_bytes(body[offset:offset + 2], order)
        length = int.from_bytes(body[offset + 2:offset + 4], order)
        value = body[offset + 4:offset + 4 + length]
        if code == 0:
            break
        if code == 9 and value:
            exponent = value[0]
            resolution = 2 ** (exponent & 0x7F) if exponent & 0x80 else 10 ** exponent
        elif code == 14 and len(value) == 8:
            time_offset = int.from_bytes(value, order, signed=True)
        offset += 4 + length + ((4 - length % 4) % 4)
    return (linktype, resolution, time_offset)


def validate_capture_file(file_path):
    path = Path(file_path)

    if not path.is_file():
        raise PcapInputError("Arquivo PCAP nao encontrado")
    if path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise PcapInputError("Selecione um arquivo .pcap ou .pcapng")
    if path.stat().st_size == 0:
        raise PcapInputError("Arquivo PCAP vazio")

    return path
