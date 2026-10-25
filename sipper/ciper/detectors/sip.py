from ciper.findings import Finding
from ciper.sip import (
    SIP_FRAGMENTATION_RISK_HEADER_BYTES,
    SIP_LARGE_HEADER_LINE_BYTES,
    SIP_UDP_FRAGMENTATION_RISK_BYTES,
    get_sip_method_responses,
    get_successful_invite_responses,
    get_terminal_sip_method_errors,
    has_matching_sip_ack,
)


def detect_sip_invite_no_response(flows):
    findings = []

    for flow in flows.values():
        if flow.invites == 0:
            continue

        invite_responses = get_sip_method_responses(flow, "INVITE", allow_unspecified=True)
        if invite_responses:
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
                    *_flow_evidence(flow),
                    f"Source: {flow.source_ip}",
                    f"Destination: {flow.destination_ip}",
                    f"INVITEs: {flow.invites}",
                    "INVITE responses: 0",
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
        if flow.invites == 0:
            continue

        error_messages = get_terminal_sip_method_errors(flow, "INVITE", allow_unspecified=True)

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
                    *_flow_evidence(flow),
                    f"Status: {first_error.status_code} {first_error.reason_phrase}",
                    f"INVITEs: {flow.invites}",
                    f"INVITE error responses: {len(error_messages)}",
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
        if flow.invites == 0:
            continue

        success_responses = get_successful_invite_responses(flow)
        if not success_responses:
            continue

        missing_ack = next(
            (response for response in success_responses if not has_matching_sip_ack(flow, response)),
            None,
        )
        if missing_ack is None:
            continue

        findings.append(
            Finding(
                type="sip_ok_without_ack",
                severity="high",
                confidence=0.95,
                source_ip=missing_ack.source_ip,
                destination_ip=missing_ack.destination_ip,
                description="SIP 200 OK was observed without a matching ACK.",
                evidence=[
                    *_flow_evidence(flow),
                    f"INVITEs: {flow.invites}",
                    f"INVITE 2xx responses: {len(success_responses)}",
                    f"ACKs: {flow.acknowledgements}",
                    f"Unacknowledged CSeq: {missing_ack.cseq_number or 'unknown'}",
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

        success_responses = get_successful_invite_responses(flow)
        if not any(has_matching_sip_ack(flow, response) for response in success_responses):
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
                    *_flow_evidence(flow),
                    f"INVITEs: {flow.invites}",
                    f"Provisional responses: {flow.provisional_responses}",
                    f"INVITE 2xx responses: {len(success_responses)}",
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
                    *_flow_evidence(flow),
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

        success_responses = get_successful_invite_responses(flow)
        if not any(has_matching_sip_ack(flow, response) for response in success_responses):
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
                    *_flow_evidence(flow),
                    f"INVITE 2xx responses: {len(success_responses)}",
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

        message = _first_affected_message(
            flow,
            lambda item: item.max_header_length > SIP_LARGE_HEADER_LINE_BYTES
            or item.header_size > SIP_FRAGMENTATION_RISK_HEADER_BYTES,
        )

        findings.append(
            Finding(
                type="sip_large_header",
                severity="medium",
                confidence=0.90,
                source_ip=message.source_ip if message else flow.source_ip,
                destination_ip=message.destination_ip if message else flow.destination_ip,
                description="SIP message contains unusually large headers.",
                evidence=[
                    *_flow_evidence(flow),
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
            message = _first_affected_message(
                flow,
                lambda item: item.invalid_header_count > 0,
            )
            findings.append(
                Finding(
                    type="sip_invalid_header",
                    severity="medium",
                    confidence=0.95,
                    source_ip=message.source_ip if message else flow.source_ip,
                    destination_ip=message.destination_ip if message else flow.destination_ip,
                    description="SIP messages contain malformed header lines.",
                    evidence=[
                        *_flow_evidence(flow),
                        f"Messages with invalid headers: {flow.invalid_header_messages}",
                    ],
                    recommendation=(
                        "Check SIP message generation and any SBC, proxy, or inspection device "
                        "that may be rewriting headers."
                    ),
                )
            )

        if flow.content_length_mismatches > 0:
            message = _first_affected_message(
                flow,
                lambda item: item.content_length_mismatch,
            )
            findings.append(
                Finding(
                    type="sip_content_length_mismatch",
                    severity="high",
                    confidence=0.95,
                    source_ip=message.source_ip if message else flow.source_ip,
                    destination_ip=message.destination_ip if message else flow.destination_ip,
                    description="SIP Content-Length does not match the message body size.",
                    evidence=[
                        *_flow_evidence(flow),
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

        message = _first_affected_message(
            flow,
            lambda item: item.header_size > SIP_FRAGMENTATION_RISK_HEADER_BYTES,
        )

        findings.append(
            Finding(
                type="sip_header_fragmentation_risk",
                severity="high",
                confidence=0.90,
                source_ip=message.source_ip if message else flow.source_ip,
                destination_ip=message.destination_ip if message else flow.destination_ip,
                description="SIP header block size creates a high risk of IP fragmentation.",
                evidence=[
                    *_flow_evidence(flow),
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

        message = _first_affected_message(
            flow,
            lambda item: item.transport == "UDP"
            and item.message_size > SIP_UDP_FRAGMENTATION_RISK_BYTES,
        )

        findings.append(
            Finding(
                type="sip_udp_fragmentation_risk",
                severity="medium",
                confidence=0.90,
                source_ip=message.source_ip if message else flow.source_ip,
                destination_ip=message.destination_ip if message else flow.destination_ip,
                description="SIP messages over UDP exceed the safe 1200-byte MTU budget.",
                evidence=[
                    *_flow_evidence(flow),
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
                    *_flow_evidence(flow),
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


def detect_sip_register_failures(flows):
    return _detect_method_failures(
        flows,
        "REGISTER",
        "sip_register_failure",
        "SIP registration was rejected by the registrar.",
        "Check credentials, realm configuration, registration policy, and reachability of the registrar.",
    )


def detect_sip_transfer_failures(flows):
    return _detect_method_failures(
        flows,
        "REFER",
        "sip_transfer_failure",
        "SIP call transfer request was rejected.",
        "Check transfer permissions, Refer-To routing, dial plan, and the target endpoint availability.",
    )


def detect_sip_options_no_response(flows):
    findings = []

    for flow in flows.values():
        options_requests = [
            message
            for message in flow.messages
            if message.is_request and message.method == "OPTIONS"
        ]
        options_responses = [
            message
            for message in flow.messages
            if not message.is_request and message.cseq_method == "OPTIONS"
        ]
        if not options_requests or options_responses:
            continue

        request = options_requests[0]
        findings.append(
            Finding(
                type="sip_options_no_response",
                severity="medium",
                confidence=0.85,
                source_ip=request.source_ip,
                destination_ip=request.destination_ip,
                description="SIP OPTIONS capability probe received no response.",
                evidence=[
                    *_flow_evidence(flow),
                    f"OPTIONS requests: {len(options_requests)}",
                    "OPTIONS responses: 0",
                ],
                recommendation=(
                    "Check SIP reachability, OPTIONS keepalive configuration, firewall rules, and the destination SIP service."
                ),
            )
        )

    return findings


def _detect_method_failures(flows, method, finding_type, description, recommendation):
    findings = []

    for flow in flows.values():
        errors = get_terminal_sip_method_errors(flow, method)
        if not errors:
            continue

        response = errors[0]
        findings.append(
            Finding(
                type=finding_type,
                severity="high",
                confidence=0.95,
                source_ip=response.source_ip,
                destination_ip=response.destination_ip,
                description=description,
                evidence=[
                    *_flow_evidence(flow),
                    f"Response: {response.status_code} {response.reason_phrase or ''}".strip(),
                    f"CSeq method: {method}",
                ],
                recommendation=recommendation,
            )
        )

    return findings


def _flow_evidence(flow):
    return [
        f"Call-ID: {flow.call_id}",
        f"Dialog-Key: {flow.dialog_key}",
    ]


def _first_affected_message(flow, predicate):
    return next((message for message in flow.messages if predicate(message)), None)


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
