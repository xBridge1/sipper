from dataclasses import dataclass, field

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


TLS_CONTENT_TYPES = {20, 21, 22, 23}
TLS_VERSION_NAMES = {
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
    80: "user_canceled",
    90: "user_canceled",
    109: "missing_extension",
    112: "unrecognized_name",
    120: "no_application_protocol",
}


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


def build_tls_flows(tcp_flows):
    tls_flows = {}

    for key, tcp_flow in tcp_flows.items():
        tls_flow = TLSFlow(
            source_ip=tcp_flow.source_ip,
            source_port=tcp_flow.source_port,
            destination_ip=tcp_flow.destination_ip,
            destination_port=tcp_flow.destination_port,
            reset=tcp_flow.rst,
        )
        buffers = {"forward": b"", "reverse": b""}
        detected = False

        for packet in tcp_flow.packets:
            if IP not in packet or TCP not in packet or Raw not in packet:
                continue

            direction = _packet_direction(packet, tcp_flow)
            buffers[direction] += bytes(packet[Raw].load)
            records, buffers[direction], malformed = _consume_tls_records(buffers[direction])
            tls_flow.malformed_records += malformed

            for content_type, _record_version, payload in records:
                detected = True
                _record_tls_content(tls_flow, direction, content_type, payload)

        if detected:
            tls_flows[key] = tls_flow

    return tls_flows


def _packet_direction(packet, tcp_flow):
    if (
        packet[IP].src == tcp_flow.source_ip
        and packet[TCP].sport == tcp_flow.source_port
    ):
        return "forward"
    return "reverse"


def _consume_tls_records(buffer):
    records = []
    malformed = 0

    while len(buffer) >= 5:
        content_type = buffer[0]
        version = (buffer[1] << 8) | buffer[2]
        record_length = (buffer[3] << 8) | buffer[4]

        if content_type not in TLS_CONTENT_TYPES or version not in TLS_VERSION_NAMES or record_length > 18432:
            return records, b"", malformed + 1

        record_end = 5 + record_length
        if len(buffer) < record_end:
            break

        records.append((content_type, version, buffer[5:record_end]))
        buffer = buffer[record_end:]

    return records, buffer, malformed


def _record_tls_content(tls_flow, direction, content_type, payload):
    if content_type == 21 and len(payload) >= 2 and payload[0] == 2:
        description = TLS_ALERT_DESCRIPTIONS.get(payload[1], f"alert_{payload[1]}")
        tls_flow.fatal_alerts.append((direction, description))
        return

    if content_type != 22:
        return

    offset = 0
    while offset + 4 <= len(payload):
        handshake_type = payload[offset]
        handshake_length = int.from_bytes(payload[offset + 1:offset + 4], "big")
        message_end = offset + 4 + handshake_length
        if message_end > len(payload):
            return

        body = payload[offset + 4:message_end]
        if handshake_type == 1:
            tls_flow.client_hello_count += 1
            _record_legacy_version(tls_flow, body)
        elif handshake_type == 2:
            tls_flow.server_hello_count += 1
            _record_legacy_version(tls_flow, body)
        offset = message_end


def _record_legacy_version(tls_flow, body):
    if len(body) < 2:
        return
    version = (body[0] << 8) | body[1]
    if version in {0x0301, 0x0302}:
        tls_flow.legacy_versions.add(TLS_VERSION_NAMES[version])
