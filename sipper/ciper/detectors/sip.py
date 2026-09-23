from ciper.findings import Finding


def detect_sip_invite_no_response(flows):
    findings = []

    for flow in flows.values():
        if flow.invites == 0:
            continue

        if flow.responses != 0:
            continue

        findings.append(
            Finding(
                type="sip_invite_no_response",
                severity="high",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="SIP INVITE was observed without any SIP response.",
                evidence=[
                    f"Call-ID: {flow.call_id}",
                    f"Source: {flow.source_ip}",
                    f"Destination: {flow.destination_ip}",
                    f"INVITEs: {flow.invites}",
                    f"Responses: {flow.responses}",
                ],
                recommendation=(
                    "Check whether the SIP server or peer is reachable, "
                    "whether SIP signaling is being blocked, or whether the "
                    "destination is not processing the call setup."
                ),
            )
        )

    return findings


def detect_sip_error_responses(flows):
    findings = []

    for flow in flows.values():
        if flow.error_responses == 0:
            continue

        error_messages = [
            message
            for message in flow.messages
            if not message.is_request
            and message.status_code is not None
            and 400 <= message.status_code < 700
        ]

        if not error_messages:
            continue

        first_error = error_messages[0]

        findings.append(
            Finding(
                type="sip_error_response",
                severity="high",
                confidence=0.95,
                source_ip=first_error.source_ip,
                destination_ip=first_error.destination_ip,
                description="SIP call setup received an error response.",
                evidence=[
                    f"Call-ID: {flow.call_id}",
                    f"Status: {first_error.status_code} {first_error.reason_phrase}",
                    f"INVITEs: {flow.invites}",
                    f"Error responses: {flow.error_responses}",
                ],
                recommendation=(
                    "Check SIP routing, authentication, dial plan, or the "
                    "destination endpoint availability based on the returned status code."
                ),
            )
        )

    return findings


def detect_sip_ok_without_ack(flows):
    findings = []

    for flow in flows.values():
        if flow.success_responses == 0:
            continue

        if flow.acknowledgements != 0:
            continue

        findings.append(
            Finding(
                type="sip_ok_without_ack",
                severity="high",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="SIP 200 OK was observed without a matching ACK.",
                evidence=[
                    f"Call-ID: {flow.call_id}",
                    f"INVITEs: {flow.invites}",
                    f"200 OK responses: {flow.success_responses}",
                    f"ACKs: {flow.acknowledgements}",
                ],
                recommendation=(
                    "Check whether the caller sent the ACK, whether signaling "
                    "packets were lost, or whether NAT/firewall handling is breaking the dialog."
                ),
            )
        )

    return findings


def detect_sip_call_established(flows):
    findings = []

    for flow in flows.values():
        if flow.invites == 0:
            continue

        if flow.success_responses == 0:
            continue

        if flow.acknowledgements == 0:
            continue

        findings.append(
            Finding(
                type="sip_call_established",
                severity="low",
                confidence=0.98,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="SIP call setup completed successfully.",
                evidence=[
                    f"Call-ID: {flow.call_id}",
                    f"INVITEs: {flow.invites}",
                    f"Provisional responses: {flow.provisional_responses}",
                    f"200 OK responses: {flow.success_responses}",
                    f"ACKs: {flow.acknowledgements}",
                ],
                recommendation=(
                    "Call signaling appears complete. If there is still a voice issue, "
                    "the next step is to inspect RTP media quality and direction."
                ),
            )
        )

    return findings


def detect_sip_call_cancelled(flows):
    findings = []

    for flow in flows.values():
        if flow.cancels == 0:
            continue

        findings.append(
            Finding(
                type="sip_call_cancelled",
                severity="medium",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="SIP call attempt was cancelled before completion.",
                evidence=[
                    f"Call-ID: {flow.call_id}",
                    f"INVITEs: {flow.invites}",
                    f"CANCELs: {flow.cancels}",
                ],
                recommendation=(
                    "Check whether the caller aborted the setup intentionally or "
                    "whether delays in call setup caused the cancellation."
                ),
            )
        )

    return findings


def detect_sip_call_terminated(flows):
    findings = []

    for flow in flows.values():
        if flow.byes == 0:
            continue

        if flow.success_responses == 0 or flow.acknowledgements == 0:
            continue

        findings.append(
            Finding(
                type="sip_call_terminated",
                severity="low",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="SIP call was established and later terminated with BYE.",
                evidence=[
                    f"Call-ID: {flow.call_id}",
                    f"200 OK responses: {flow.success_responses}",
                    f"ACKs: {flow.acknowledgements}",
                    f"BYEs: {flow.byes}",
                ],
                recommendation=(
                    "Call signaling shows a normal call teardown. If users reported "
                    "an unexpected drop, correlate this with RTP timing and endpoint behavior."
                ),
            )
        )

    return findings


def detect_sip_large_headers(flows):
    findings = []

    for flow in flows.values():
        if flow.large_header_messages == 0:
            continue

        findings.append(
            Finding(
                type="sip_large_header",
                severity="medium",
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="SIP message contains unusually large headers.",
                evidence=[
                    f"Call-ID: {flow.call_id}",
                    f"Messages with large headers: {flow.large_header_messages}",
                    f"Header fragmentation risks: {flow.header_fragmentation_risk_messages}",
                ],
                recommendation=(
                    "Check whether SIP headers are oversized due to excessive routing, "
                    "identity, or contact information that could stress MTU limits."
                ),
            )
        )

    return findings


def detect_sip_header_validation_errors(flows):
    findings = []

    for flow in flows.values():
        if flow.invalid_header_messages > 0:
            findings.append(
                Finding(
                    type="sip_invalid_header",
                    severity="medium",
                    confidence=0.95,
                    source_ip=flow.source_ip,
                    destination_ip=flow.destination_ip,
                    description="SIP messages contain malformed header lines.",
                    evidence=[
                        f"Call-ID: {flow.call_id}",
                        f"Messages with invalid headers: {flow.invalid_header_messages}",
                    ],
                    recommendation=(
                        "Check SIP message generation and any SBC, proxy, or inspection device "
                        "that may be rewriting headers."
                    ),
                )
            )

        if flow.content_length_mismatches > 0:
            findings.append(
                Finding(
                    type="sip_content_length_mismatch",
                    severity="high",
                    confidence=0.95,
                    source_ip=flow.source_ip,
                    destination_ip=flow.destination_ip,
                    description="SIP Content-Length does not match the message body size.",
                    evidence=[
                        f"Call-ID: {flow.call_id}",
                        f"Content-Length mismatches: {flow.content_length_mismatches}",
                    ],
                    recommendation=(
                        "Correct the SIP message generator or intermediary rewriting the body. "
                        "A mismatched Content-Length can break parsing and TCP stream reassembly."
                    ),
                )
            )

    return findings


def detect_sip_header_fragmentation_risk(flows):
    findings = []

    for flow in flows.values():
        if flow.header_fragmentation_risk_messages == 0:
            continue

        findings.append(
            Finding(
                type="sip_header_fragmentation_risk",
                severity="high",
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="SIP header block size creates a high risk of IP fragmentation.",
                evidence=[
                    f"Call-ID: {flow.call_id}",
                    f"Oversized header blocks: {flow.header_fragmentation_risk_messages}",
                    "Header threshold: 1200 bytes",
                ],
                recommendation=(
                    "Reduce oversized Via, Route, Record-Route, Contact, and identity headers, "
                    "or use TCP/TLS transport where appropriate."
                ),
            )
        )

    return findings


def detect_sip_udp_fragmentation_risk(flows):
    findings = []

    for flow in flows.values():
        if flow.udp_fragmentation_risk_messages == 0:
            continue

        findings.append(
            Finding(
                type="sip_udp_fragmentation_risk",
                severity="medium",
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="SIP messages over UDP exceed the safe 1200-byte MTU budget.",
                evidence=[
                    f"Call-ID: {flow.call_id}",
                    f"Oversized SIP/UDP messages: {flow.udp_fragmentation_risk_messages}",
                    "Safe message threshold: 1200 bytes",
                ],
                recommendation=(
                    "Reduce SIP message size or use TCP/TLS where supported. UDP packets above "
                    "the path MTU can be fragmented or silently dropped."
                ),
            )
        )

    return findings


def detect_sip_signaling_fragmentation(flows, fragment_groups=None):
    findings = []
    fragment_groups = fragment_groups or {}

    for flow in flows.values():
        related_groups = _find_related_fragment_groups(flow, fragment_groups)

        if flow.fragmented_messages == 0 and not related_groups:
            continue

        findings.append(
            Finding(
                type="sip_signaling_fragmentation",
                severity="high",
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="Fragmented IP packets were observed carrying SIP signaling.",
                evidence=[
                    f"Call-ID: {flow.call_id}",
                    f"Fragmented SIP messages: {flow.fragmented_messages}",
                    f"Related IP fragment sets: {len(related_groups)}",
                    f"TCP-segmented SIP messages: {flow.tcp_segmented_messages}",
                ],
                recommendation=(
                    "Check MTU, transport choice, and SIP message size. Fragmented "
                    "signaling can be dropped by network devices and break call setup."
                ),
            )
        )

    return findings


def _find_related_fragment_groups(flow, fragment_groups):
    return [
        group
        for group in fragment_groups.values()
        if any(_fragment_group_matches_message(group, message) for message in flow.messages)
    ]


def _fragment_group_matches_message(group, message):
    protocol = 17 if message.transport == "UDP" else 6 if message.transport == "TCP" else None

    if protocol is None or group.protocol != protocol:
        return False

    if (group.source_ip, group.destination_ip) != (message.source_ip, message.destination_ip):
        return False

    if group.source_port is None:
        return message.is_fragmented

    return (group.source_port, group.destination_port) == (
        message.source_port,
        message.destination_port,
    )
