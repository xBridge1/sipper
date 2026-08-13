from ciper.findings import Finding

from scapy.layers.inet import IP, TCP


def detect_syn_failures(flows):
    findings = []

    for flow in flows.values():
        if flow.syn and not flow.syn_ack and not flow.established:
            finding = Finding(
                type="tcp_syn_failure",
                severity="high",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                recommendation=(
                    "Check whether the destination host is reachable, "
                    "the destination port is listening, or a firewall is "
                    "blocking the connection."
                ),
                description=(
                    "TCP SYN was detected, but no SYN/ACK response "
                    "was observed."
                ),
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    "SYN observed: yes",
                    "SYN/ACK observed: no",
                    f"Packets in flow: {flow.packet_count}",
                ],
            )

            findings.append(finding)

    return findings

def detect_slow_handshakes(flows):
    findings = []

    for flow in flows.values():
        handshake_time = flow.handshake_time

        if handshake_time is None:
            continue

        if handshake_time > 0.5:
            severity = "high"
        elif handshake_time > 0.1:
            severity = "medium"
        else:
            continue

        findings.append(
            Finding(
                type="tcp_slow_handshake",
                severity=severity,
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description=(
                    "TCP handshake response time was unusually high."
                ),
                recommendation=(
                    "Check network latency, server response time, "
                    "firewalls, proxies, or overloaded endpoints."
                ),
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Handshake time: {handshake_time:.3f}s",
                    "SYN observed: yes",
                    "SYN/ACK observed: yes",
                ],
            )
        )

    return findings

from ciper.tcp_tracker import track_tcp_packets


def detect_tcp_retransmissions(flows):
    findings = []

    for flow in flows.values():
        events = track_tcp_packets(flow.packets, flow)

        retransmissions = [
            event
            for event in events
            if event.event_type == "retransmission"
        ]

        if not retransmissions:
            continue

        first = retransmissions[0]

        findings.append(
            Finding(
                type="tcp_retransmission",
                severity="medium",
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="TCP retransmission detected.",
                recommendation=(
                    "Check for packet loss, network congestion, "
                    "unstable links, or problems between the endpoints."
                ),
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Sequence: {first.sequence}",
                    f"Payload: {first.payload_length} bytes",
                    f"Direction: {first.direction}",
                    f"Retransmissions: {len(retransmissions)}",
                ],
            )
        )

    return findings

def detect_tcp_resets(flows):
    findings = []

    for flow in flows.values():
        if not flow.rst:
            continue

        reset_packet = None

        for packet in flow.packets:
            if TCP in packet and packet[TCP].flags & 0x04:
                reset_packet = packet
                break

        if reset_packet is None:
            continue

        findings.append(
            Finding(
                type="tcp_reset",
                severity="high",
                confidence=0.95,
                source_ip=reset_packet[IP].src,
                destination_ip=reset_packet[IP].dst,
                description="TCP connection was reset unexpectedly.",
                evidence=[
                    f"Source: {reset_packet[IP].src}:{reset_packet[TCP].sport}",
                    f"Destination: {reset_packet[IP].dst}:{reset_packet[TCP].dport}",
                    "RST observed: yes",
                ],
                recommendation=(
                    "Check whether the application rejected the connection, "
                    "a firewall terminated the session, or the service "
                    "crashed."
                ),
            )
        )

    return findings