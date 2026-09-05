from dataclasses import dataclass, field

from scapy.packet import Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


@dataclass
class SIPMessage:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    is_request: bool
    method: str | None
    status_code: int | None
    reason_phrase: str | None
    call_id: str
    start_line: str
    header_count: int
    max_header_length: int
    is_fragmented: bool
    packet_time: float
    sdp_media: list["SDPMediaDescription"] = field(default_factory=list)
    cseq_method: str | None = None
    from_tag: str | None = None
    to_tag: str | None = None
    contact: str | None = None
    via_branch: str | None = None


@dataclass
class SDPMediaDescription:
    media_type: str
    port: int
    protocol: str
    payload_types: list[int] = field(default_factory=list)
    connection_address: str | None = None
    codecs: dict[int, str] = field(default_factory=dict)
    direction: str = "sendrecv"
    rtcp_port: int | None = None
    media_id: str | None = None
    rtcp_mux: bool = False


@dataclass
class SIPFlow:
    call_id: str
    source_ip: str
    destination_ip: str
    messages: list[SIPMessage] = field(default_factory=list)
    invites: int = 0
    acknowledgements: int = 0
    byes: int = 0
    cancels: int = 0
    responses: int = 0
    provisional_responses: int = 0
    success_responses: int = 0
    error_responses: int = 0
    large_header_messages: int = 0
    fragmented_messages: int = 0
    registers: int = 0


def parse_sip_message(packet):
    payload = _extract_payload(packet)

    if not payload:
        return None

    source_ip, destination_ip, source_port, destination_port = _extract_endpoints(packet)
    is_fragmented = bool(IP in packet and (packet[IP].flags.MF or packet[IP].frag > 0))

    return _parse_sip_payload(
        payload,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        is_fragmented,
        float(packet.time),
    )


def _parse_sip_payload(
    payload,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    is_fragmented,
    packet_time,
):

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None

    lines = text.splitlines()

    if not lines:
        return None

    start_line = lines[0].strip()

    if not start_line:
        return None

    headers = {}
    header_count = 0
    max_header_length = 0

    previous_header = None

    for raw_line in lines[1:]:
        if raw_line.startswith((" ", "\t")) and previous_header is not None:
            headers[previous_header] = f"{headers[previous_header]} {raw_line.strip()}"
            continue

        line = raw_line.strip()

        if not line or ":" not in line:
            continue

        name, value = line.split(":", 1)
        header_name = _normalize_header_name(name)
        headers[header_name] = value.strip()
        previous_header = header_name
        header_count += 1
        max_header_length = max(max_header_length, len(line.encode("utf-8")))

    call_id = headers.get("call-id")

    if not call_id:
        return None

    sdp_media = _parse_sdp_media(text)
    cseq_method = _extract_cseq_method(headers.get("cseq"))
    from_tag = _extract_parameter(headers.get("from"), "tag")
    to_tag = _extract_parameter(headers.get("to"), "tag")
    via_branch = _extract_parameter(headers.get("via"), "branch")

    if start_line.startswith("SIP/2.0 "):
        parts = start_line.split(" ", 2)

        if len(parts) < 3:
            return None

        return SIPMessage(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            is_request=False,
            method=None,
            status_code=int(parts[1]),
            reason_phrase=parts[2],
            call_id=call_id,
            start_line=start_line,
            header_count=header_count,
            max_header_length=max_header_length,
            is_fragmented=is_fragmented,
            packet_time=packet_time,
            sdp_media=sdp_media,
            cseq_method=cseq_method,
            from_tag=from_tag,
            to_tag=to_tag,
            contact=headers.get("contact"),
            via_branch=via_branch,
        )

    parts = start_line.split(" ", 2)

    if len(parts) < 3 or not parts[2].startswith("SIP/2.0"):
        return None

    return SIPMessage(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        is_request=True,
        method=parts[0],
        status_code=None,
        reason_phrase=None,
        call_id=call_id,
        start_line=start_line,
        header_count=header_count,
        max_header_length=max_header_length,
        is_fragmented=is_fragmented,
        packet_time=packet_time,
        sdp_media=sdp_media,
        cseq_method=cseq_method,
        from_tag=from_tag,
        to_tag=to_tag,
        contact=headers.get("contact"),
        via_branch=via_branch,
    )


def build_sip_flows(packets):
    flows = {}
    tcp_buffers = {}

    for packet in packets:
        if TCP in packet:
            messages = _extract_tcp_sip_messages(packet, tcp_buffers)
        else:
            message = parse_sip_message(packet)
            messages = [message] if message is not None else []

        for message in messages:
            _add_message_to_flow(flows, message)

    return flows


def _extract_tcp_sip_messages(packet, tcp_buffers):
    payload = _extract_payload(packet)

    if not payload or (IP not in packet and IPv6 not in packet):
        return []

    source_ip, destination_ip, source_port, destination_port = _extract_endpoints(packet)
    key = (source_ip, destination_ip, source_port, destination_port)
    state = tcp_buffers.setdefault(key, {"payload": b"", "packet_time": None, "fragmented": False})

    if not state["payload"]:
        state["packet_time"] = float(packet.time)
        state["fragmented"] = bool(IP in packet and (packet[IP].flags.MF or packet[IP].frag > 0))

    state["payload"] += payload
    state["fragmented"] = state["fragmented"] or bool(IP in packet and (packet[IP].flags.MF or packet[IP].frag > 0))
    messages = []

    while True:
        message_payload = _pop_complete_sip_message(state)

        if message_payload is None:
            break

        message = _parse_sip_payload(
            message_payload,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            state["fragmented"],
            state["packet_time"],
        )

        if message is not None:
            messages.append(message)

        if state["payload"]:
            state["packet_time"] = float(packet.time)
            state["fragmented"] = bool(IP in packet and (packet[IP].flags.MF or packet[IP].frag > 0))

    return messages


def _pop_complete_sip_message(state):
    payload = state["payload"]
    header_marker = b"\r\n\r\n"
    header_end = payload.find(header_marker)

    if header_end < 0:
        header_marker = b"\n\n"
        header_end = payload.find(header_marker)

    if header_end < 0:
        return None

    header_length = header_end + len(header_marker)
    header_text = payload[:header_end].decode("utf-8", errors="ignore")
    content_length = 0

    for line in header_text.splitlines()[1:]:
        name, separator, value = line.partition(":")
        if separator and _normalize_header_name(name) == "content-length" and value.strip().isdigit():
            content_length = int(value.strip())
            break

    message_length = header_length + content_length

    if len(payload) < message_length:
        return None

    state["payload"] = payload[message_length:]
    return payload[:message_length]


def _add_message_to_flow(flows, message):
    if message is None:
        return

    if message.call_id not in flows:
        flows[message.call_id] = SIPFlow(
            call_id=message.call_id,
            source_ip=message.source_ip,
            destination_ip=message.destination_ip,
        )

    flow = flows[message.call_id]
    flow.messages.append(message)

    if message.is_request and message.method == "INVITE":
        flow.invites += 1

    if message.is_request and message.method == "ACK":
        flow.acknowledgements += 1

    if message.is_request and message.method == "BYE":
        flow.byes += 1

    if message.is_request and message.method == "CANCEL":
        flow.cancels += 1

    if message.is_request and message.method == "REGISTER":
        flow.registers += 1

    if not message.is_request:
        flow.responses += 1

        if 100 <= message.status_code < 200:
            flow.provisional_responses += 1
        elif 200 <= message.status_code < 300:
            flow.success_responses += 1
        elif 400 <= message.status_code < 700:
            flow.error_responses += 1

    if message.max_header_length > 1024:
        flow.large_header_messages += 1

    if message.is_fragmented:
        flow.fragmented_messages += 1


def _extract_payload(packet):
    if Raw in packet:
        return bytes(packet[Raw].load)

    return b""


def _parse_sdp_media(text):
    if "\r\n\r\n" in text:
        _headers, body = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        _headers, body = text.split("\n\n", 1)
    else:
        return []

    media_descriptions = []
    session_connection_address = None
    session_direction = "sendrecv"
    current_media = None

    for raw_line in body.splitlines():
        line = raw_line.strip()

        if line.startswith("c="):
            parts = line.split()
            if len(parts) >= 3:
                if current_media is None:
                    session_connection_address = parts[2]
                else:
                    current_media.connection_address = parts[2]
            continue

        if line.startswith("m="):
            parts = line[2:].split()
            port_value = parts[1].split("/", 1)[0]
            if len(parts) < 3 or not port_value.isdigit():
                current_media = None
                continue

            payload_types = [int(value) for value in parts[3:] if value.isdigit()]
            current_media = SDPMediaDescription(
                media_type=parts[0],
                port=int(port_value),
                protocol=parts[2],
                payload_types=payload_types,
            )
            media_descriptions.append(current_media)
            continue

        if line in {"a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive"}:
            direction = line[2:]
            if current_media is None:
                session_direction = direction
            else:
                current_media.direction = direction
            continue

        if line.startswith("a=rtpmap:") and current_media is not None:
            value = line[len("a=rtpmap:"):]
            parts = value.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                codec = parts[1].split("/", 1)[0]
                current_media.codecs[int(parts[0])] = codec
            continue

        if line.startswith("a=rtcp:") and current_media is not None:
            value = line[len("a=rtcp:"):].split(None, 1)[0]
            if value.isdigit():
                current_media.rtcp_port = int(value)
            continue

        if line.startswith("a=mid:") and current_media is not None:
            current_media.media_id = line[len("a=mid:"):].strip() or None
            continue

        if line == "a=rtcp-mux" and current_media is not None:
            current_media.rtcp_mux = True

    for media in media_descriptions:
        if media.connection_address is None:
            media.connection_address = session_connection_address
        if media.direction == "sendrecv":
            media.direction = session_direction

    return media_descriptions


def _extract_endpoints(packet):
    network_layer = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
    source_ip = network_layer.src if network_layer is not None else ""
    destination_ip = network_layer.dst if network_layer is not None else ""

    if UDP in packet:
        return source_ip, destination_ip, packet[UDP].sport, packet[UDP].dport

    if TCP in packet:
        return source_ip, destination_ip, packet[TCP].sport, packet[TCP].dport

    return source_ip, destination_ip, 0, 0


def _normalize_header_name(name):
    compact_names = {
        "i": "call-id",
        "f": "from",
        "t": "to",
        "v": "via",
        "m": "contact",
        "l": "content-length",
        "c": "content-type",
    }
    normalized = name.strip().lower()
    return compact_names.get(normalized, normalized)


def _extract_parameter(value, parameter_name):
    if not value:
        return None

    for parameter in value.split(";")[1:]:
        name, separator, parameter_value = parameter.strip().partition("=")
        if separator and name.lower() == parameter_name:
            return parameter_value.strip()

    return None


def _extract_cseq_method(value):
    if not value:
        return None

    parts = value.split()
    return parts[1].upper() if len(parts) >= 2 else None
