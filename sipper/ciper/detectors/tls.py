from ciper.findings import Finding


def detect_tls_fatal_alerts(flows):
    findings = []

    for flow in flows.values():
        if not flow.fatal_alerts:
            continue

        direction, alert = flow.fatal_alerts[0]
        source_ip = flow.source_ip if direction == "forward" else flow.destination_ip
        destination_ip = flow.destination_ip if direction == "forward" else flow.source_ip
        findings.append(
            Finding(
                type="tls_fatal_alert",
                severity="high",
                confidence=0.98,
                source_ip=source_ip,
                destination_ip=destination_ip,
                description="TLS negotiation ended with a fatal alert.",
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Alert direction: {direction}",
                    f"Fatal alert: {alert}",
                ],
                recommendation=(
                    "Check certificate trust, supported TLS versions and cipher suites, "
                    "server name configuration, and TLS inspection devices."
                ),
            )
        )

    return findings


def detect_tls_client_hello_no_response(flows):
    findings = []

    for flow in flows.values():
        if flow.client_hello_count == 0 or flow.server_hello_count > 0:
            continue

        findings.append(
            Finding(
                type="tls_client_hello_no_response",
                severity="high" if flow.reset else "medium",
                confidence=0.90 if flow.reset else 0.75,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="TLS ClientHello was observed without a ServerHello response.",
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"ClientHello messages: {flow.client_hello_count}",
                    f"ServerHello messages: {flow.server_hello_count}",
                    f"TCP reset observed: {'yes' if flow.reset else 'no'}",
                ],
                recommendation=(
                    "Check whether the TLS service is reachable, whether a firewall or proxy "
                    "blocks the handshake, and whether the server accepts the requested SNI and TLS version."
                ),
            )
        )

    return findings


def detect_tls_legacy_versions(flows):
    findings = []

    for flow in flows.values():
        if not flow.legacy_versions:
            continue

        findings.append(
            Finding(
                type="tls_legacy_version",
                severity="medium",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="A deprecated TLS version was proposed during the handshake.",
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Versions: {', '.join(sorted(flow.legacy_versions))}",
                ],
                recommendation=(
                    "Disable TLS 1.0 and TLS 1.1 where possible, and configure both endpoints "
                    "to negotiate TLS 1.2 or TLS 1.3."
                ),
            )
        )

    return findings


def detect_tls_malformed_records(flows):
    findings = []

    for flow in flows.values():
        if flow.malformed_records == 0:
            continue

        findings.append(
            Finding(
                type="tls_malformed_record",
                severity="medium",
                confidence=0.80,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="TLS records with an invalid header or length were observed.",
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Malformed records: {flow.malformed_records}",
                ],
                recommendation=(
                    "Check for packet corruption, protocol mismatches, TLS inspection issues, "
                    "or a service speaking a different protocol on this port."
                ),
            )
        )

    return findings
