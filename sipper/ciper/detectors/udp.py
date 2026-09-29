from ciper.findings import Finding
from ciper.udp_tracker import track_udp_packets
from scapy.packet import Raw

UDP_REQUEST_RESPONSE_PORTS = {
    53,      # DNS
    123,     # NTP
    161,     # SNMP
    500,     # IKE
    4500,    # IPsec NAT-T
    5060,    # SIP
    5061,    # SIP TLS
}


def detect_udp_no_response(flows):
    findings = []

    for flow in flows.values():
        events = track_udp_packets(flow.packets, flow)

        if not events:
            continue

        forward_events = [
            event
            for event in events
            if event.direction == "forward"
        ]

        reverse_events = [
            event
            for event in events
            if event.direction == "reverse"
        ]

        if not forward_events:
            continue

        if not _expects_response(flow) or reverse_events:
            continue

        request_count = len(forward_events)
        recognized_request = _contains_recognized_sip_request(flow)

        if request_count >= 3:
            severity = "high"
            confidence = 0.90
        elif request_count == 2:
            severity = "medium"
            confidence = 0.85
        else:
            severity = "medium"
            confidence = 0.80

        if flow.destination_port in {5060, 5061} and not recognized_request:
            confidence -= 0.15

        findings.append(
            Finding(
                type="udp_no_response",
                severity=severity,
                confidence=confidence,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="UDP traffic was observed without a response.",
                recommendation=(
                    "Check whether the destination service is available, "
                    "whether UDP traffic is being blocked by a firewall, "
                    "or whether the application is expected to respond."
                ),
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Packets sent: {request_count}",
                    "Response packets: 0",
                    "SIP request recognized: yes" if recognized_request else "Application request not identified",
                ],
            )
        )

    return findings


def detect_udp_burst_no_response(flows):
    findings = []

    for flow in flows.values():
        if not _expects_response(flow) or flow.packets_reverse != 0:
            continue

        if flow.packets_forward < 3:
            continue

        if flow.duration > 1.0:
            continue

        findings.append(
            Finding(
                type="udp_burst_no_response",
                severity="high",
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="Multiple UDP requests were sent in a short burst without any response.",
                recommendation=(
                    "Check whether the destination service is unavailable, "
                    "rate-limited, or whether the traffic is being dropped "
                    "before reaching the endpoint."
                ),
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Packets sent: {flow.packets_forward}",
                    f"Burst duration: {flow.duration:.3f}s",
                    "Response packets: 0",
                ],
            )
        )

    return findings


def _expects_response(flow):
    if flow.destination_port not in UDP_REQUEST_RESPONSE_PORTS:
        return False

    if flow.destination_port not in {5060, 5061}:
        return True

    return not any(_is_sip_response_or_ack(packet) for packet in flow.packets)


def _contains_recognized_sip_request(flow):
    return any(_is_sip_request(packet) for packet in flow.packets)


def _is_sip_response_or_ack(packet):
    line = _sip_start_line(packet)
    return line.startswith("SIP/2.0") or line.startswith("ACK ")


def _is_sip_request(packet):
    line = _sip_start_line(packet)
    if not line or line.startswith("SIP/2.0"):
        return False
    parts = line.split()
    return len(parts) >= 3 and parts[2].upper() == "SIP/2.0" and parts[0].isalpha()


def _sip_start_line(packet):
    if Raw not in packet:
        return ""

    payload = bytes(packet[Raw].load)
    if not payload:
        return ""
    lines = payload.decode("utf-8", errors="ignore").splitlines()
    return lines[0].strip().upper() if lines else ""
