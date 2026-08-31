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
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
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
                ],
                recommendation=(
                    "Check whether SIP headers are oversized due to excessive routing, "
                    "identity, or contact information that could stress MTU limits."
                ),
            )
        )

    return findings


def detect_sip_signaling_fragmentation(flows):
    findings = []

    for flow in flows.values():
        if flow.fragmented_messages == 0:
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
                ],
                recommendation=(
                    "Check MTU, transport choice, and SIP message size. Fragmented "
                    "signaling can be dropped by network devices and break call setup."
                ),
            )
        )

    return findings
