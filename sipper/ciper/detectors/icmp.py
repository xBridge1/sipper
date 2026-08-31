from ciper.findings import Finding


UNREACHABLE_CODE_DETAILS = {
    0: (
        "icmp_network_unreachable",
        "ICMP Network Unreachable was observed.",
        "Check whether the destination network is reachable and whether routing is configured correctly.",
    ),
    1: (
        "icmp_host_unreachable",
        "ICMP Host Unreachable was observed.",
        "Check whether the destination host is online and whether there is a valid route to reach it.",
    ),
    3: (
        "icmp_destination_unreachable",
        "ICMP Port Unreachable was observed.",
        "Check whether the destination service is listening on the target port and whether filtering is blocking the traffic.",
    ),
    4: (
        "icmp_fragmentation_needed",
        "ICMP Fragmentation Needed was observed.",
        "Check path MTU discovery, MTU settings, and any devices dropping fragmented traffic.",
    ),
    13: (
        "icmp_admin_prohibited",
        "ICMP Communication Administratively Prohibited was observed.",
        "Check firewall and security policy rules blocking the traffic path.",
    ),
}


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

        codes = sorted(set(flow.unreachable_codes)) or [None]

        for code in codes:
            if code is not None:
                finding_type, description, recommendation = UNREACHABLE_CODE_DETAILS.get(
                    code,
                    (
                        "icmp_destination_unreachable",
                        "ICMP Destination Unreachable was observed.",
                        "Check whether the destination host, network, or service is reachable and whether a firewall is blocking the traffic.",
                    ),
                )
            else:
                finding_type = "icmp_destination_unreachable"
                description = "ICMP Destination Unreachable was observed."
                recommendation = (
                    "Check whether the destination host, network, or "
                    "service is reachable and whether a firewall is "
                    "blocking the traffic."
                )

            evidence = [
                f"Source: {flow.source_ip}",
                f"Destination: {flow.destination_ip}",
                f"Unreachable messages: {flow.unreachable_messages}",
            ]

            if code is not None:
                evidence.append(f"ICMP code: {code}")

            findings.append(
                Finding(
                    type=finding_type,
                    severity="high",
                    confidence=0.95,
                    source_ip=flow.source_ip,
                    destination_ip=flow.destination_ip,
                    description=description,
                    evidence=evidence,
                    recommendation=recommendation,
                )
            )

    return findings


def detect_icmp_time_exceeded(flows):
    findings = []

    for flow in flows.values():
        if flow.time_exceeded_messages == 0:
            continue

        findings.append(
            Finding(
                type="icmp_time_exceeded",
                severity="high",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="ICMP Time Exceeded was observed.",
                evidence=[
                    f"Source: {flow.source_ip}",
                    f"Destination: {flow.destination_ip}",
                    f"Time Exceeded messages: {flow.time_exceeded_messages}",
                ],
                recommendation=(
                    "Check network routing, TTL configuration, or "
                    "possible routing loops between the endpoints."
                ),
            )
        )

    return findings


def detect_icmp_redirect(flows):
    findings = []

    for flow in flows.values():
        if flow.redirect_messages == 0:
            continue

        findings.append(
            Finding(
                type="icmp_redirect",
                severity="medium",
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="ICMP Redirect was observed.",
                evidence=[
                    f"Source: {flow.source_ip}",
                    f"Destination: {flow.destination_ip}",
                    f"Redirect messages: {flow.redirect_messages}",
                ],
                recommendation=(
                    "Check routing design, gateway selection, and whether hosts are using the expected next-hop device."
                ),
            )
        )

    return findings


def detect_icmp_parameter_problem(flows):
    findings = []

    for flow in flows.values():
        if flow.parameter_problem_messages == 0:
            continue

        findings.append(
            Finding(
                type="icmp_parameter_problem",
                severity="high",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="ICMP Parameter Problem was observed.",
                evidence=[
                    f"Source: {flow.source_ip}",
                    f"Destination: {flow.destination_ip}",
                    f"Parameter problem messages: {flow.parameter_problem_messages}",
                ],
                recommendation=(
                    "Check for malformed packets, protocol implementation issues, or devices modifying headers incorrectly."
                ),
            )
        )

    return findings
