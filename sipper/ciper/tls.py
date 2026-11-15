from dataclasses import dataclass, field

from ciper.tcp_reassembly import reassemble_tcp_payloads


TLS_CONTENT_TYPES = {20, 21, 22, 23, 24}
TLS_COMMON_PORTS = {443, 465, 636, 993, 995, 5061, 8443}
TLS_VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}
TLS_ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    90: "user_canceled",
    109: "missing_extension",
    112: "unrecognized_name",
    120: "no_application_protocol",
}
TLS_CIPHER_SUITE_NAMES = {
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}
TLS_WEAK_CIPHER_SUITES = {0x0004, 0x0005, 0x000A}


@dataclass
class TLSFlow:
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    client_hello_count: int = 0
    server_hello_count: int = 0
    fatal_alerts: list[tuple[str, str]] = field(default_factory=list)
    legacy_versions: set[str] = field(default_factory=set)
    malformed_records: int = 0
    reset: bool = False
    server_names: set[str] = field(default_factory=set)
    offered_versions: set[str] = field(default_factory=set)
    offered_cipher_suites: set[int] = field(default_factory=set)
    negotiated_version: str | None = None
    negotiated_cipher_suite: int | None = None
    certificate_count: int = 0


def build_tls_flows(tcp_flows, tcp_blocks=None):
    """Detect TLS sessions in TCP flows.

    ``tcp_blocks`` may contain blocks already produced by
    ``reassemble_tcp_payloads`` for all TCP traffic, so streams are not
    reassembled a second time.
    """
    tls_flows = {}
    blocks_by_flow = _group_blocks_by_flow(tcp_blocks) if tcp_blocks is not None else None

    for key, tcp_flow in tcp_flows.items():
        tls_flow = TLSFlow(
            source_ip=tcp_flow.source_ip,
            source_port=tcp_flow.source_port,
            destination_ip=tcp_flow.destination_ip,
            destination_port=tcp_flow.destination_port,
            reset=tcp_flow.rst,
        )
        handshake_buffers = {"forward": b"", "reverse": b""}
        detected = False

        if blocks_by_flow is not None:
            flow_blocks = blocks_by_flow.get(_flow_key(
                tcp_flow.source_ip,
                tcp_flow.source_port,
                tcp_flow.destination_ip,
                tcp_flow.destination_port,
            ), [])
        else:
            flow_blocks = reassemble_tcp_payloads(tcp_flow.packets)

        for block in flow_blocks:
            direction = _block_direction(block, tcp_flow)
            records, _remainder, malformed = _consume_tls_records(block.payload)
            tls_flow.malformed_records += malformed
            detected = detected or bool(records) or (
                malformed > 0 and _is_likely_tls_block(block)
            )

            for content_type, _record_version, payload in records:
                _record_tls_content(tls_flow, handshake_buffers, direction, content_type, payload)

        if detected:
            tls_flows[key] = tls_flow

    return tls_flows


def _flow_key(source_ip, source_port, destination_ip, destination_port):
    endpoint_a = (source_ip, source_port)
    endpoint_b = (destination_ip, destination_port)
    return (endpoint_a, endpoint_b) if endpoint_a <= endpoint_b else (endpoint_b, endpoint_a)


def _group_blocks_by_flow(blocks):
    grouped = {}
    for block in blocks:
        key = _flow_key(block.source_ip, block.source_port, block.destination_ip, block.destination_port)
        grouped.setdefault(key, []).append(block)
    return grouped


def _block_direction(block, tcp_flow):
    if (
        block.source_ip == tcp_flow.source_ip
        and block.source_port == tcp_flow.source_port
    ):
        return "forward"
    return "reverse"


def _is_likely_tls_block(block):
    if block.source_port in TLS_COMMON_PORTS or block.destination_port in TLS_COMMON_PORTS:
        return True

    return len(block.payload) >= 3 and block.payload[1:3] in {
        version.to_bytes(2, "big") for version in TLS_VERSION_NAMES
    }


def _consume_tls_records(buffer):
    records = []
    malformed = 0
    offset = 0
    size = len(buffer)

    while size - offset >= 5:
        content_type = buffer[offset]
        version = (buffer[offset + 1] << 8) | buffer[offset + 2]
        record_length = (buffer[offset + 3] << 8) | buffer[offset + 4]

        if content_type not in TLS_CONTENT_TYPES or version not in TLS_VERSION_NAMES or record_length > 18432:
            return records, b"", malformed + 1

        record_end = offset + 5 + record_length
        if size < record_end:
            break

        # Application data is never inspected, so its bytes are not copied.
        payload = buffer[offset + 5:record_end] if content_type != 23 else b""
        records.append((content_type, version, payload))
        offset = record_end

    return records, buffer[offset:], malformed


def _record_tls_content(tls_flow, handshake_buffers, direction, content_type, payload):
    if content_type == 21 and len(payload) >= 2 and payload[0] == 2:
        description = TLS_ALERT_DESCRIPTIONS.get(payload[1], f"alert_{payload[1]}")
        tls_flow.fatal_alerts.append((direction, description))
        return

    if content_type != 22:
        return

    handshake_buffer = handshake_buffers[direction] + payload
    offset = 0
    while offset + 4 <= len(handshake_buffer):
        handshake_type = handshake_buffer[offset]
        handshake_length = int.from_bytes(handshake_buffer[offset + 1:offset + 4], "big")
        message_end = offset + 4 + handshake_length
        if message_end > len(handshake_buffer):
            break

        body = handshake_buffer[offset + 4:message_end]
        if handshake_type == 1:
            tls_flow.client_hello_count += 1
            _record_legacy_version(tls_flow, body)
            _parse_client_hello(tls_flow, body)
        elif handshake_type == 2:
            tls_flow.server_hello_count += 1
            _record_legacy_version(tls_flow, body)
            _parse_server_hello(tls_flow, body)
        elif handshake_type == 11:
            tls_flow.certificate_count += 1
        offset = message_end

    handshake_buffers[direction] = handshake_buffer[offset:]


def _record_legacy_version(tls_flow, body):
    if len(body) < 2:
        return
    version = (body[0] << 8) | body[1]
    if version in {0x0300, 0x0301, 0x0302}:
        tls_flow.legacy_versions.add(TLS_VERSION_NAMES[version])


def _parse_client_hello(tls_flow, body):
    if len(body) < 35:
        return

    _record_version(tls_flow.offered_versions, int.from_bytes(body[:2], "big"))
    offset = 34
    session_id_length = body[offset]
    offset += 1 + session_id_length
    if offset + 2 > len(body):
        return

    cipher_length = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    if cipher_length % 2 or offset + cipher_length > len(body):
        return

    for cipher_offset in range(offset, offset + cipher_length, 2):
        tls_flow.offered_cipher_suites.add(int.from_bytes(body[cipher_offset:cipher_offset + 2], "big"))
    offset += cipher_length

    if offset >= len(body):
        return
    compression_length = body[offset]
    offset += 1 + compression_length
    _parse_tls_extensions(tls_flow, body, offset, client_hello=True)


def _parse_server_hello(tls_flow, body):
    if len(body) < 38:
        return

    selected_version = int.from_bytes(body[:2], "big")
    _record_version(tls_flow.offered_versions, selected_version)
    offset = 34
    session_id_length = body[offset]
    offset += 1 + session_id_length
    if offset + 3 > len(body):
        return

    tls_flow.negotiated_cipher_suite = int.from_bytes(body[offset:offset + 2], "big")
    offset += 3
    tls_flow.negotiated_version = TLS_VERSION_NAMES.get(selected_version, f"0x{selected_version:04X}")
    _parse_tls_extensions(tls_flow, body, offset, client_hello=False)


def _parse_tls_extensions(tls_flow, body, offset, client_hello):
    if offset + 2 > len(body):
        return

    extensions_end = offset + 2 + int.from_bytes(body[offset:offset + 2], "big")
    if extensions_end > len(body):
        return
    offset += 2

    while offset + 4 <= extensions_end:
        extension_type = int.from_bytes(body[offset:offset + 2], "big")
        extension_length = int.from_bytes(body[offset + 2:offset + 4], "big")
        offset += 4
        extension_end = offset + extension_length
        if extension_end > extensions_end:
            return
        extension = body[offset:extension_end]

        if extension_type == 0 and client_hello:
            _parse_server_names(tls_flow, extension)
        elif extension_type == 43:
            _parse_supported_versions(tls_flow, extension, client_hello)

        offset = extension_end


def _parse_server_names(tls_flow, extension):
    if len(extension) < 5:
        return

    names_end = 2 + int.from_bytes(extension[:2], "big")
    offset = 2
    while offset + 3 <= names_end and names_end <= len(extension):
        name_type = extension[offset]
        name_length = int.from_bytes(extension[offset + 1:offset + 3], "big")
        offset += 3
        if offset + name_length > names_end:
            return
        if name_type == 0:
            server_name = extension[offset:offset + name_length].decode("ascii", errors="ignore").strip().lower()
            if server_name:
                tls_flow.server_names.add(server_name)
        offset += name_length


def _parse_supported_versions(tls_flow, extension, client_hello):
    if client_hello:
        if not extension:
            return
        versions = extension[1:1 + extension[0]]
    else:
        versions = extension[:2]

    for offset in range(0, len(versions) - 1, 2):
        version = int.from_bytes(versions[offset:offset + 2], "big")
        _record_version(tls_flow.offered_versions, version)
        if not client_hello:
            tls_flow.negotiated_version = TLS_VERSION_NAMES.get(version, f"0x{version:04X}")


def _record_version(versions, version):
    if version in TLS_VERSION_NAMES:
        versions.add(TLS_VERSION_NAMES[version])
