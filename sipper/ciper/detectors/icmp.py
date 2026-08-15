from ciper.findings import Finding


def detect_icmp_no_response(flows):
    findings = []

    for flow in flows.values():
        if flow.echo_requests == 0:
            continue

        if flow.echo_replies != 0:
            continue

        findings.append(
            Finding(
                type="icmp_no_response",
                severity="medium",
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="ICMP Echo Request was observed without a response.",
                evidence=[
                    f"Source: {flow.source_ip}",
                    f"Destination: {flow.destination_ip}",
                    f"Echo requests: {flow.echo_requests}",
                    f"Echo replies: {flow.echo_replies}",
                ],
                recommendation=(
                    "Check whether the destination host is reachable, "
                    "whether ICMP is being blocked by a firewall, or "
                    "whether the destination is configured to ignore ping requests."
                ),
            )
        )

    return findings

def detect_icmp_unreachable(flows):
    findings = []

    for flow in flows.values():
        if flow.unreachable_messages == 0:
            continue

        findings.append(
            Finding(
                type="icmp_destination_unreachable",
                severity="high",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="ICMP Destination Unreachable was observed.",
                evidence=[
                    f"Source: {flow.source_ip}",
                    f"Destination: {flow.destination_ip}",
                    f"Unreachable messages: {flow.unreachable_messages}",
                ],
                recommendation=(
                    "Check whether the destination host, network, or "
                    "service is reachable and whether a firewall is "
                    "blocking the traffic."
                ),
            )
        )

    return findings