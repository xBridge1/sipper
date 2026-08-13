from ciper.findings import Finding
from ciper.udp_tracker import track_udp_packets

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

        if flow.destination_port not in UDP_REQUEST_RESPONSE_PORTS:
            continue

        if reverse_events:
            continue

        findings.append(
            Finding(
                type="udp_no_response",
                severity="medium",
                confidence=0.80,
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
                    f"Packets sent: {len(forward_events)}",
                    "Response packets: 0",
                ],
            )
        )

    return findings