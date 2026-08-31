from dataclasses import dataclass, field

from scapy.packet import Raw
from scapy.layers.inet import IP, TCP, UDP


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


def parse_sip_message(packet):
    payload = _extract_payload(packet)

    if not payload:
        return None

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

    for line in lines[1:]:
        line = line.strip()

        if not line or ":" not in line:
            continue

        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
        header_count += 1
        max_header_length = max(max_header_length, len(line.encode("utf-8")))

    call_id = headers.get("call-id")

    if not call_id:
        return None

    source_ip, destination_ip, source_port, destination_port = _extract_endpoints(packet)
    is_fragmented = bool(IP in packet and (packet[IP].flags.MF or packet[IP].frag > 0))
    packet_time = float(packet.time)

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
    )


def build_sip_flows(packets):
    flows = {}

    for packet in packets:
        message = parse_sip_message(packet)

        if message is None:
            continue

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

    return flows


def _extract_payload(packet):
    if Raw in packet:
        return bytes(packet[Raw].load)

    return b""


def _extract_endpoints(packet):
    source_ip = packet[IP].src if IP in packet else ""
    destination_ip = packet[IP].dst if IP in packet else ""

    if UDP in packet:
        return source_ip, destination_ip, packet[UDP].sport, packet[UDP].dport

    if TCP in packet:
        return source_ip, destination_ip, packet[TCP].sport, packet[TCP].dport

    return source_ip, destination_ip, 0, 0
