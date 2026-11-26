from ciper.text import is_ascii_digits
from dataclasses import dataclass, field

from ciper.packets import _UNSET, ensure_decoded
from ciper.tcp_reassembly import reassemble_tcp_payloads


SIP_LARGE_HEADER_LINE_BYTES = 1024
SIP_FRAGMENTATION_RISK_HEADER_BYTES = 1200
SIP_UDP_FRAGMENTATION_RISK_BYTES = 1200


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
    header_size: int = 0
    header_text: str = ""
    message_size: int = 0
    transport: str = ""
    tcp_segmented: bool = False
    invalid_header_count: int = 0
    content_length_mismatch: bool = False
    sdp_media: list["SDPMediaDescription"] = field(default_factory=list)
    cseq_method: str | None = None
    cseq_number: int | None = None
    from_tag: str | None = None
    to_tag: str | None = None
    contact: str | None = None
    via_branch: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    request_uri: str | None = None
    # Every value of every header, in order (Via, Record-Route and duplicated
    # singleton headers keep all occurrences here; ``headers`` keeps the last).
    header_values: dict[str, list[str]] = field(default_factory=dict)
    # Byte-level facts that are lost once the message is decoded.
    invalid_utf8_headers: list[str] = field(default_factory=list)
    non_ascii_headers: list[str] = field(default_factory=list)
    control_char_headers: list[str] = field(default_factory=list)
    invalid_header_names: list[str] = field(default_factory=list)
    invalid_header_lines: list[str] = field(default_factory=list)
    bare_lf_lines: int = 0
    folded_lines: int = 0
    body_text: str = ""
    sip_version: str = "SIP/2.0"


@dataclass
class SDPMediaDescription:
    media_type: str
    port: int
    protocol: str
    payload_types: list[int] = field(default_factory=list)
    connection_address: str | None = None
    codecs: dict[int, str] = field(default_factory=dict)
    clock_rates: dict[int, int] = field(default_factory=dict)
    direction: str = "sendrecv"
    rtcp_port: int | None = None
    media_id: str | None = None
    rtcp_mux: bool = False
    ptime: int | None = None


@dataclass
class SIPFlow:
    call_id: str
    source_ip: str
    destination_ip: str
    dialog_key: str = ""
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
    header_fragmentation_risk_messages: int = 0
    invalid_header_messages: int = 0
    content_length_mismatches: int = 0
    fragmented_messages: int = 0
    udp_fragmentation_risk_messages: int = 0
    tcp_segmented_messages: int = 0
    registers: int = 0
    options: int = 0
    refers: int = 0
    reinvites: int = 0
    hold_events: int = 0
    resume_events: int = 0
    media_on_hold: bool = False
    invite_transaction_keys: set[tuple] = field(default_factory=set)
    # Media state before each INVITE offer, so a rejected offer can be undone.
    media_offer_undo: dict[tuple, tuple] = field(default_factory=dict)

    def __post_init__(self):
        if not self.dialog_key:
            self.dialog_key = self.call_id


def parse_sip_message(packet):
    packet = ensure_decoded(packet)
    cached = packet._sip
    if cached is not _UNSET:
        return cached

    message = None
    payload = packet.payload
    if payload and _looks_like_sip(payload):
        transport = packet.transport if packet.transport in {"UDP", "TCP"} else ""
        message = _parse_sip_payload(
            payload,
            packet.src,
            packet.dst,
            packet.sport if transport else 0,
            packet.dport if transport else 0,
            packet.fragmented,
            packet.time,
            transport,
        )

    packet._sip = message
    return message


def _looks_like_sip(payload):
    # Requests start with a method token and responses with "SIP/2.0"; both
    # contain "SIP/2.0" in the start line. RTP, RTCP, TLS and most binary
    # payloads fail the first-byte check without any decoding.
    first = payload[0]
    if not (65 <= first <= 90 or 97 <= first <= 122):
        return False
    line_end = payload.find(b"\n", 0, 4096)
    start_line = payload[:line_end] if line_end >= 0 else payload[:4096]
    return b"SIP/2.0" in start_line


def _parse_sip_payload(
    payload,
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    is_fragmented,
    packet_time,
    transport="",
    tcp_segmented=False,
):

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        # Legacy PBXs often send Latin-1 display names. Keep the message (it
        # is exactly the kind of input that breaks downstream systems) and
        # record which headers carry the invalid bytes.
        text = payload.decode("latin-1")

    header_bytes, body_bytes = _split_sip_payload(payload)
    raw_lines = header_bytes.split(b"\n")
    lines = [_decode_header_line(line) for line in raw_lines]

    if not lines:
        return None

    start_line = lines[0].strip()

    if not start_line:
        return None

    header_text = "\n".join(line.rstrip("\r") for line in lines)
    headers = {}
    header_values = {}
    header_count = 0
    max_header_length = 0
    invalid_header_count = 0
    declared_content_length = None
    invalid_utf8_headers = []
    non_ascii_headers = []
    control_char_headers = []
    invalid_header_names = []
    invalid_header_lines = []
    # The final line has no terminator of its own (the blank line was split off).
    bare_lf_lines = sum(1 for line in raw_lines[:-1] if not line.endswith(b"\r"))
    if len(raw_lines) == 1:
        bare_lf_lines = 0
    folded_lines = 0

    previous_header = None

    for raw_bytes, raw_line in zip(raw_lines[1:], lines[1:]):
        raw_line = raw_line.rstrip("\r")
        if raw_line.startswith((" ", "\t")) and previous_header is not None:
            folded_lines += 1
            headers[previous_header] = f"{headers[previous_header]} {raw_line.strip()}"
            header_values[previous_header][-1] = headers[previous_header]
            _record_byte_issues(
                raw_bytes,
                previous_header,
                invalid_utf8_headers,
                non_ascii_headers,
                control_char_headers,
            )
            continue

        line = raw_line.strip()

        if not line:
            continue

        if ":" not in line:
            invalid_header_count += 1
            invalid_header_lines.append(line[:120])
            previous_header = None
            continue

        name, value = line.split(":", 1)
        header_name = _normalize_header_name(name)
        if not header_name:
            invalid_header_count += 1
            invalid_header_lines.append(line[:120])
            previous_header = None
            continue
        if not _is_token(name.strip()):
            invalid_header_names.append(name.strip()[:60])
        headers[header_name] = value.strip()
        header_values.setdefault(header_name, []).append(value.strip())
        _record_byte_issues(
            raw_bytes,
            header_name,
            invalid_utf8_headers,
            non_ascii_headers,
            control_char_headers,
        )
        previous_header = header_name
        header_count += 1
        max_header_length = max(max_header_length, len(raw_bytes.rstrip(b"\r")))
        if header_name == "content-length":
            if is_ascii_digits(value.strip()):
                declared_content_length = int(value.strip())
            else:
                invalid_header_count += 1

    content_length_mismatch = (
        declared_content_length is not None and declared_content_length != len(body_bytes)
    )

    # With a (malformed) duplicated Call-ID, the first copy is what most
    # stacks match on; keep it so the message stays in its dialog.
    call_id = (header_values.get("call-id") or [None])[0]

    if not call_id:
        return None

    sdp_media = _parse_sdp_media(text)
    cseq_method = _extract_cseq_method(headers.get("cseq"))
    cseq_number = _extract_cseq_number(headers.get("cseq"))
    from_tag = _extract_parameter(headers.get("from"), "tag")
    to_tag = _extract_parameter(headers.get("to"), "tag")
    top_via = (header_values.get("via") or [""])[0].split(",", 1)[0]
    via_branch = _extract_parameter(top_via, "branch")

    common = dict(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        call_id=call_id,
        start_line=start_line,
        header_count=header_count,
        max_header_length=max_header_length,
        is_fragmented=is_fragmented,
        packet_time=packet_time,
        header_size=len(header_bytes),
        header_text=header_text,
        message_size=len(payload),
        transport=transport,
        tcp_segmented=tcp_segmented,
        invalid_header_count=invalid_header_count,
        content_length_mismatch=content_length_mismatch,
        sdp_media=sdp_media,
        cseq_method=cseq_method,
        cseq_number=cseq_number,
        from_tag=from_tag,
        to_tag=to_tag,
        contact=headers.get("contact"),
        via_branch=via_branch,
        headers=dict(headers),
        header_values=header_values,
        invalid_utf8_headers=invalid_utf8_headers,
        non_ascii_headers=non_ascii_headers,
        control_char_headers=control_char_headers,
        invalid_header_names=invalid_header_names,
        invalid_header_lines=invalid_header_lines,
        bare_lf_lines=bare_lf_lines,
        folded_lines=folded_lines,
        body_text=body_bytes[:8192].decode("utf-8", errors="replace") if body_bytes else "",
    )

    if start_line.upper().startswith("SIP/"):
        parts = start_line.split(None, 2)

        if len(parts) < 2 or not is_ascii_digits(parts[1]):
            return None

        return SIPMessage(
            is_request=False,
            method=None,
            status_code=int(parts[1]),
            reason_phrase=parts[2] if len(parts) > 2 else "",
            sip_version=parts[0],
            **common,
        )

    # Method SP Request-URI SP SIP-Version. A Request-URI with embedded
    # whitespace is invalid, but the message is still kept so it can be
    # reported instead of silently disappearing from the analysis.
    parts = start_line.split()

    if len(parts) < 3 or not parts[-1].upper().startswith("SIP/"):
        return None

    return SIPMessage(
        is_request=True,
        method=parts[0],
        status_code=None,
        reason_phrase=None,
        request_uri=" ".join(parts[1:-1]),
        sip_version=parts[-1],
        **common,
    )


def build_sip_flows(packets, tcp_blocks=None):
    """Build SIP dialogs from UDP packets and reassembled TCP streams.

    ``tcp_blocks`` lets the caller pass blocks already produced by
    ``reassemble_tcp_payloads`` so TCP streams are reassembled only once per
    analysis; TCP packets in ``packets`` are then ignored.
    """
    flows = {}
    initial_messages = {}
    challenge_tags = {}
    messages = []
    tcp_packets = []

    for packet in packets:
        packet = ensure_decoded(packet)
        if packet.transport == "TCP":
            if tcp_blocks is None:
                tcp_packets.append(packet)
        else:
            message = parse_sip_message(packet)
            if message is not None:
                messages.append(message)

    if tcp_blocks is None:
        tcp_blocks = reassemble_tcp_payloads(tcp_packets)

    for block in tcp_blocks:
        if b"SIP/2.0" in block.payload:
            messages.extend(_extract_tcp_sip_messages(block))

    for message in sorted(messages, key=lambda item: item.packet_time):
        _add_message_to_flow(flows, initial_messages, message, challenge_tags)

    return flows


def _extract_tcp_sip_messages(block):
    state = {
        "payload": block.payload,
        "packet_time": block.first_timestamp,
        "fragmented": block.fragmented,
        "segmented": block.segmented,
    }
    messages = []

    while True:
        message_payload = _pop_complete_sip_message(state)

        if message_payload is None:
            break

        message = _parse_sip_payload(
            message_payload,
            block.source_ip,
            block.destination_ip,
            block.source_port,
            block.destination_port,
            state["fragmented"],
            state["packet_time"],
            "TCP",
            state["segmented"],
        )

        if message is not None:
            messages.append(message)

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
        if separator and _normalize_header_name(name) == "content-length" and is_ascii_digits(value.strip()):
            content_length = int(value.strip())
            break

    message_length = header_length + content_length

    if len(payload) < message_length:
        return None

    state["payload"] = payload[message_length:]
    return payload[:message_length]


def _add_message_to_flow(flows, initial_messages, message, challenge_tags=None):
    if message is None:
        return

    base_key = message.call_id
    if challenge_tags is None:
        challenge_tags = {}
    if _is_auth_challenge(message):
        challenge_tags.setdefault(base_key, set()).add(message.to_tag)
    challenge = bool(message.to_tag) and message.to_tag in challenge_tags.get(base_key, ())

    if challenge:
        # A 401/407 challenge (and the ACK for it) is a final non-2xx
        # response: it never creates a dialog (RFC 3261 12.1). Keep it with
        # the INVITE/REGISTER it answers so the authenticated retry lands in
        # the same flow and the challenge is seen as superseded.
        dialog_key = _pre_dialog_flow_key(flows, base_key)
    else:
        dialog_key = _resolve_dialog_key(
            message,
            flows,
            initial_messages.get(base_key, []),
        )

    if dialog_key not in flows:
        if dialog_key != base_key and base_key in flows:
            flow = flows.pop(base_key)
            flow.dialog_key = dialog_key
            flow.source_ip, flow.destination_ip = _get_dialog_endpoints(
                message,
                initial_messages.get(base_key, []),
            )
            flows[dialog_key] = flow
        else:
            source_ip, destination_ip = _get_dialog_endpoints(
                message,
                initial_messages.get(base_key, []),
            )
            flow = SIPFlow(
                call_id=message.call_id,
                source_ip=source_ip,
                destination_ip=destination_ip,
                dialog_key=dialog_key,
            )
            flows[dialog_key] = flow
            if dialog_key != base_key:
                for initial_message in initial_messages.get(base_key, []):
                    _record_flow_message(flow, initial_message)
    else:
        flow = flows[dialog_key]

    _record_flow_message(flow, message)

    if message.to_tag is None or challenge:
        initial_messages.setdefault(base_key, []).append(message)


def is_auth_retry(flow, message):
    """An INVITE outside the dialog (no To tag) sent after a 401/407 challenge.

    It repeats the original request with credentials; it is not a re-INVITE."""
    if message.to_tag:
        return False
    return any(
        not earlier.is_request
        and earlier.status_code in {401, 407}
        and earlier.cseq_method == message.method
        and earlier.packet_time <= message.packet_time
        for earlier in flow.messages
    )


def _is_auth_challenge(message):
    return (
        not message.is_request
        and message.status_code in {401, 407}
        and bool(message.to_tag)
    )


def _pre_dialog_flow_key(flows, base_key):
    """Flow holding the requests of a Call-ID before any dialog was formed."""
    if base_key in flows:
        return base_key
    candidates = [key for key, flow in flows.items() if flow.call_id == base_key]
    return candidates[-1] if candidates else base_key


def _get_dialog_key(message):
    if not message.from_tag or not message.to_tag:
        return message.call_id
    return f"{message.call_id}|{message.from_tag}|{message.to_tag}"


def _resolve_dialog_key(message, flows, initial_messages):
    dialog_key = _get_dialog_key(message)
    if not message.from_tag or not message.to_tag:
        return dialog_key

    reverse_key = f"{message.call_id}|{message.to_tag}|{message.from_tag}"
    if dialog_key not in flows and reverse_key in flows:
        return reverse_key

    initial_request = next(
        (
            initial
            for initial in initial_messages
            if initial.is_request and initial.method == "INVITE"
        ),
        None,
    )
    if initial_request and initial_request.from_tag == message.to_tag:
        return reverse_key
    return dialog_key


def _get_dialog_endpoints(message, initial_messages):
    initial_request = next(
        (
            initial
            for initial in initial_messages
            if initial.is_request and initial.method == "INVITE"
        ),
        None,
    )
    if initial_request is None:
        return message.source_ip, message.destination_ip

    if message.is_request and message.source_ip == initial_request.source_ip:
        destination_ip = message.destination_ip
    else:
        destination_ip = message.source_ip
    return initial_request.source_ip, destination_ip


def _record_flow_message(flow, message):
    flow.messages.append(message)

    if message.is_request and message.method == "INVITE":
        transaction_key = _invite_transaction_key(message)
        if transaction_key not in flow.invite_transaction_keys:
            if flow.invites > 0 and not is_auth_retry(flow, message):
                flow.reinvites += 1
            flow.invite_transaction_keys.add(transaction_key)
            flow.invites += 1
            flow.media_offer_undo[(message.source_ip, message.cseq_number)] = (
                flow.media_on_hold,
                flow.hold_events,
                flow.resume_events,
            )
            _track_media_operation(flow, message)

    if not message.is_request and message.cseq_method == "INVITE" and message.status_code >= 200:
        _settle_media_offer(flow, message)

    if message.is_request and message.method == "ACK":
        flow.acknowledgements += 1

    if message.is_request and message.method == "BYE":
        flow.byes += 1

    if message.is_request and message.method == "CANCEL":
        flow.cancels += 1

    if message.is_request and message.method == "REGISTER":
        flow.registers += 1

    if message.is_request and message.method == "OPTIONS":
        flow.options += 1

    if message.is_request and message.method == "REFER":
        flow.refers += 1

    if not message.is_request:
        flow.responses += 1

        if 100 <= message.status_code < 200:
            flow.provisional_responses += 1
        elif 200 <= message.status_code < 300:
            flow.success_responses += 1
        elif 400 <= message.status_code < 700:
            flow.error_responses += 1

    if (
        message.max_header_length > SIP_LARGE_HEADER_LINE_BYTES
        or message.header_size > SIP_FRAGMENTATION_RISK_HEADER_BYTES
    ):
        flow.large_header_messages += 1

    if message.header_size > SIP_FRAGMENTATION_RISK_HEADER_BYTES:
        flow.header_fragmentation_risk_messages += 1

    if message.invalid_header_count > 0:
        flow.invalid_header_messages += 1

    if message.content_length_mismatch:
        flow.content_length_mismatches += 1

    if message.is_fragmented:
        flow.fragmented_messages += 1

    if message.transport == "UDP" and message.message_size > SIP_UDP_FRAGMENTATION_RISK_BYTES:
        flow.udp_fragmentation_risk_messages += 1

    if message.tcp_segmented:
        flow.tcp_segmented_messages += 1


def _settle_media_offer(flow, response):
    """Undo the hold/resume an INVITE offer applied when it was rejected.

    The media state is applied when the offer is seen, so captures missing
    the answer still count it; a final non-2xx means it never took effect."""
    key = (response.destination_ip, response.cseq_number)
    if key not in flow.media_offer_undo:
        return
    latest = next(reversed(flow.media_offer_undo))
    undo = flow.media_offer_undo.pop(key)
    if response.status_code >= 300 and key == latest:
        flow.media_on_hold, flow.hold_events, flow.resume_events = undo


def _track_media_operation(flow, message):
    active_media = [media for media in message.sdp_media if media.media_type == "audio"]
    if not active_media:
        return

    on_hold = any(
        media.port == 0
        or media.direction in {"sendonly", "recvonly", "inactive"}
        or media.connection_address in {"0.0.0.0", "::"}
        for media in active_media
    )

    if on_hold and not flow.media_on_hold:
        flow.hold_events += 1
        flow.media_on_hold = True
    elif not on_hold and flow.media_on_hold:
        flow.resume_events += 1
        flow.media_on_hold = False


def _split_sip_payload(payload):
    marker = b"\r\n\r\n"
    marker_index = payload.find(marker)
    if marker_index >= 0:
        return payload[:marker_index], payload[marker_index + len(marker):]

    marker = b"\n\n"
    marker_index = payload.find(marker)
    if marker_index >= 0:
        return payload[:marker_index], payload[marker_index + len(marker):]

    return payload, b""


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
            if len(parts) < 3:
                current_media = None
                continue

            port_value = parts[1].split("/", 1)[0]
            if not is_ascii_digits(port_value) or not 0 <= int(port_value) <= 65535:
                current_media = None
                continue

            payload_types = [int(value) for value in parts[3:] if is_ascii_digits(value)]
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
            if len(parts) == 2 and is_ascii_digits(parts[0]):
                payload_type = int(parts[0])
                encoding_parts = parts[1].split("/")
                current_media.codecs[payload_type] = encoding_parts[0]
                if len(encoding_parts) >= 2 and is_ascii_digits(encoding_parts[1]):
                    current_media.clock_rates[payload_type] = int(encoding_parts[1])
            continue

        if line.startswith("a=rtcp:") and current_media is not None:
            value = line[len("a=rtcp:"):].split(None, 1)[0]
            if is_ascii_digits(value):
                current_media.rtcp_port = int(value)
            continue

        if line.startswith("a=mid:") and current_media is not None:
            current_media.media_id = line[len("a=mid:"):].strip() or None
            continue

        if line.startswith("a=ptime:") and current_media is not None:
            value = line[len("a=ptime:"):].strip()
            if is_ascii_digits(value) and 0 < int(value) <= 1000:
                current_media.ptime = int(value)
            continue

        if line == "a=rtcp-mux" and current_media is not None:
            current_media.rtcp_mux = True

    for media in media_descriptions:
        if media.connection_address is None:
            media.connection_address = session_connection_address
        if media.direction == "sendrecv":
            media.direction = session_direction

    return media_descriptions


_TOKEN_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.!%*_+`'~"
)


def _is_token(value):
    """RFC 3261 token: header names may only use these characters."""
    return bool(value) and all(character in _TOKEN_CHARACTERS for character in value)


def _decode_header_line(raw_line):
    try:
        return raw_line.decode("utf-8")
    except UnicodeDecodeError:
        return raw_line.decode("latin-1")


def _record_byte_issues(raw_line, header_name, invalid_utf8, non_ascii, control_chars):
    line = raw_line.rstrip(b"\r")
    if any(byte < 0x20 and byte != 0x09 or byte == 0x7F for byte in line):
        if header_name not in control_chars:
            control_chars.append(header_name)
    if not line.isascii():
        try:
            line.decode("utf-8")
        except UnicodeDecodeError:
            if header_name not in invalid_utf8:
                invalid_utf8.append(header_name)
        else:
            if header_name not in non_ascii:
                non_ascii.append(header_name)


def _normalize_header_name(name):
    compact_names = {
        "i": "call-id",
        "f": "from",
        "t": "to",
        "v": "via",
        "m": "contact",
        "l": "content-length",
        "c": "content-type",
        "e": "content-encoding",
        "k": "supported",
        "s": "subject",
        "r": "refer-to",
        "b": "referred-by",
        "o": "event",
        "u": "allow-events",
        "x": "session-expires",
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


def _extract_cseq_number(value):
    if not value:
        return None

    number = value.split(None, 1)[0]
    return int(number) if is_ascii_digits(number) else None


def _invite_transaction_key(message):
    if message.cseq_number is not None:
        # Each side of a dialog has its own CSeq space.
        return ("cseq", message.source_ip, message.cseq_number)
    if message.via_branch:
        return ("branch", message.via_branch)

    media_signature = tuple(
        (
            media.media_type,
            media.port,
            media.connection_address,
            media.direction,
            tuple(media.payload_types),
        )
        for media in message.sdp_media
    )
    return ("content", message.start_line, message.header_text, media_signature)


def get_sip_method_responses(flow, method, allow_unspecified=False):
    return [
        message
        for message in flow.messages
        if (
            not message.is_request
            and message.status_code is not None
            and (
                message.cseq_method == method
                or (allow_unspecified and message.cseq_method is None)
            )
        )
    ]


def get_terminal_sip_method_errors(flow, method, allow_unspecified=False):
    responses = get_sip_method_responses(flow, method, allow_unspecified)
    return [
        response
        for response in responses
        if 400 <= response.status_code < 700
        and not _is_superseded_auth_challenge(responses, response)
        and not _is_in_dialog_glare(flow, response)
    ]


def _is_in_dialog_glare(flow, response):
    """491 Request Pending inside an established dialog.

    Both sides sent a re-INVITE/UPDATE at the same time; RFC 3261 14.1 has
    the UAC retry after a random delay. It is negotiation, not a failure."""
    if response.status_code != 491:
        return False
    return any(
        not message.is_request
        and message.cseq_method == "INVITE"
        and message.status_code is not None
        and 200 <= message.status_code < 300
        and message.packet_time < response.packet_time
        for message in flow.messages
    )


def get_successful_invite_responses(flow):
    return [
        response
        for response in get_sip_method_responses(flow, "INVITE", allow_unspecified=True)
        if 200 <= response.status_code < 300
    ]


def has_matching_sip_ack(flow, response):
    for message in flow.messages:
        if not message.is_request or message.method != "ACK":
            continue
        if response.cseq_number is not None and message.cseq_number != response.cseq_number:
            continue
        if response.to_tag and message.to_tag and response.to_tag != message.to_tag:
            continue
        return True
    return False


def _is_superseded_auth_challenge(responses, response):
    if response.status_code not in {401, 407}:
        return False

    response_index = responses.index(response)
    for later in responses[response_index + 1:]:
        if response.cseq_number is None or later.cseq_number is None:
            return True
        if later.cseq_number != response.cseq_number:
            return True
    return False
