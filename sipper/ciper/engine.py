from ciper.flows import build_tcp_flows, build_icmp_flows
from ciper.rtp import build_rtp_streams
from ciper.sip import build_sip_flows
from ciper.udp_flows import build_udp_flows
from ciper.detectors.udp import detect_udp_burst_no_response, detect_udp_no_response
from ciper.findings import Finding
from ciper.detectors.icmp import (
    detect_icmp_no_response,
    detect_icmp_parameter_problem,
    detect_icmp_redirect,
    detect_icmp_time_exceeded,
    detect_icmp_unreachable,
)
from ciper.detectors.tcp import (
    detect_tcp_handshake_incomplete,
    detect_tcp_handshake_reset,
    detect_syn_failures,
    detect_slow_handshakes,
    detect_tcp_retransmissions,
    detect_tcp_resets,
)
from ciper.detectors.sip import (
    detect_sip_call_established,
    detect_sip_call_cancelled,
    detect_sip_call_terminated,
    detect_sip_error_responses,
    detect_sip_invite_no_response,
    detect_sip_large_headers,
    detect_sip_ok_without_ack,
    detect_sip_signaling_fragmentation,
)
from ciper.detectors.rtp import (
    detect_rtp_high_jitter,
    detect_rtp_one_way_audio,
    detect_rtp_out_of_order,
    detect_rtp_packet_loss,
    detect_rtp_payload_type_change,
    detect_rtp_ssrc_change,
    detect_rtp_stream_interruption,
    detect_rtp_timestamp_anomaly,
)


def analyze_pcap(packets):
    flows = build_tcp_flows(packets)
    udp_flows = build_udp_flows(packets)
    icmp_flows = build_icmp_flows(packets)
    sip_flows = build_sip_flows(packets)
    rtp_streams = build_rtp_streams(packets)

    findings = []

    findings.extend(detect_syn_failures(flows))
    findings.extend(detect_tcp_handshake_incomplete(flows))
    findings.extend(detect_tcp_handshake_reset(flows))
    findings.extend(detect_slow_handshakes(flows))
    findings.extend(detect_tcp_retransmissions(flows))
    findings.extend(detect_tcp_resets(flows))

    findings.extend(detect_udp_no_response(udp_flows))
    findings.extend(detect_udp_burst_no_response(udp_flows))
    findings.extend(detect_sip_call_established(sip_flows))
    findings.extend(detect_sip_call_cancelled(sip_flows))
    findings.extend(detect_sip_call_terminated(sip_flows))
    findings.extend(detect_sip_error_responses(sip_flows))
    findings.extend(detect_sip_invite_no_response(sip_flows))
    findings.extend(detect_sip_large_headers(sip_flows))
    findings.extend(detect_sip_ok_without_ack(sip_flows))
    findings.extend(detect_sip_signaling_fragmentation(sip_flows))
    findings.extend(detect_rtp_packet_loss(rtp_streams))
    findings.extend(detect_rtp_out_of_order(rtp_streams))
    findings.extend(detect_rtp_high_jitter(rtp_streams))
    findings.extend(detect_rtp_timestamp_anomaly(rtp_streams))
    findings.extend(detect_rtp_stream_interruption(rtp_streams))
    findings.extend(detect_rtp_payload_type_change(rtp_streams))
    findings.extend(detect_rtp_ssrc_change(rtp_streams))
    findings.extend(detect_rtp_one_way_audio(rtp_streams))

    findings.extend(detect_icmp_no_response(icmp_flows))
    findings.extend(detect_icmp_redirect(icmp_flows))
    findings.extend(detect_icmp_parameter_problem(icmp_flows))
    findings.extend(detect_icmp_time_exceeded(icmp_flows))
    findings.extend(detect_icmp_unreachable(icmp_flows))
    findings.extend(correlate_findings(findings, sip_flows, rtp_streams))
    findings = prioritize_findings(findings)
    call_summaries = build_call_summaries(sip_flows, rtp_streams, findings)

    return {
        "flows": flows,
        "udp_flows": udp_flows,
        "icmp_flows": icmp_flows,
        "sip_flows": sip_flows,
        "rtp_streams": rtp_streams,
        "findings": findings,
        "call_summaries": call_summaries,
    }


def correlate_findings(findings, sip_flows, rtp_streams):
    correlated = []

    udp_no_response_findings = [
        finding for finding in findings if finding.type == "udp_no_response"
    ]
    icmp_unreachable_findings = [
        finding
        for finding in findings
        if finding.type in {
            "icmp_destination_unreachable",
            "icmp_host_unreachable",
            "icmp_network_unreachable",
            "icmp_fragmentation_needed",
            "icmp_admin_prohibited",
        }
    ]

    for udp_finding in udp_no_response_findings:
        for icmp_finding in icmp_unreachable_findings:
            if (
                udp_finding.source_ip == icmp_finding.destination_ip
                and udp_finding.destination_ip == icmp_finding.source_ip
            ):
                correlated.append(
                    Finding(
                        type="udp_service_unreachable",
                        severity="high",
                        confidence=0.95,
                        source_ip=udp_finding.source_ip,
                        destination_ip=udp_finding.destination_ip,
                        description="UDP request had no response and ICMP unreachable indicates the service or path rejected it.",
                        evidence=[
                            f"UDP finding: {udp_finding.type}",
                            f"ICMP finding: {icmp_finding.type}",
                            f"Source: {udp_finding.source_ip}",
                            f"Destination: {udp_finding.destination_ip}",
                        ],
                        recommendation=(
                            "Check whether the destination service is listening, "
                            "whether the target port is open, and whether any "
                            "firewall or network policy is rejecting the traffic."
                        ),
                    )
                )
                break

    if sip_flows and not rtp_streams:
        for flow in sip_flows.values():
            if flow.success_responses > 0 and flow.acknowledgements > 0:
                correlated.append(
                    Finding(
                        type="sip_call_established_without_rtp",
                        severity="high",
                        confidence=0.90,
                        source_ip=flow.source_ip,
                        destination_ip=flow.destination_ip,
                        description="SIP call signaling completed, but no RTP media stream was observed.",
                        evidence=[
                            f"Call-ID: {flow.call_id}",
                            f"200 OK responses: {flow.success_responses}",
                            f"ACKs: {flow.acknowledgements}",
                            "RTP streams observed: 0",
                        ],
                        recommendation=(
                            "Check SDP/media negotiation, NAT traversal, RTP port reachability, or endpoints failing to start media."
                        ),
                    )
                )

    if rtp_streams and not sip_flows:
        for stream in rtp_streams.values():
            correlated.append(
                Finding(
                    type="rtp_without_sip",
                    severity="medium",
                    confidence=0.80,
                    source_ip=stream.source_ip,
                    destination_ip=stream.destination_ip,
                    description="RTP media was observed without a corresponding SIP dialog.",
                    evidence=[
                        f"SSRC: {stream.ssrc}",
                        f"Packets observed: {stream.packet_count}",
                    ],
                    recommendation=(
                        "Check whether signaling was captured, whether the call uses another signaling protocol, "
                        "or whether media is orphaned from the expected dialog."
                    ),
                )
            )
            break

    one_way_findings = [
        finding for finding in findings if finding.type == "rtp_one_way_audio"
    ]

    for flow in sip_flows.values():
        if flow.success_responses <= 0 or flow.acknowledgements <= 0:
            continue

        for finding in one_way_findings:
            if (
                (finding.source_ip == flow.source_ip and finding.destination_ip == flow.destination_ip)
                or (finding.source_ip == flow.destination_ip and finding.destination_ip == flow.source_ip)
            ):
                correlated.append(
                    Finding(
                        type="sip_call_one_way_audio",
                        severity="high",
                        confidence=0.90,
                        source_ip=flow.source_ip,
                        destination_ip=flow.destination_ip,
                        description="SIP call was established, but RTP indicates probable one-way audio.",
                        evidence=[
                            f"Call-ID: {flow.call_id}",
                            f"RTP finding: {finding.type}",
                        ],
                        recommendation=(
                            "Check NAT traversal, SDP media addresses, firewall rules, and whether both endpoints can send and receive RTP."
                        ),
                    )
                )
                break

    if sip_flows and rtp_streams:
        bye_times = []

        for flow in sip_flows.values():
            for message in flow.messages:
                if message.is_request and message.method == "BYE":
                    bye_times.append((flow, message))

        for flow, message in bye_times:
            for stream in rtp_streams.values():
                if stream.first_timestamp is None:
                    continue

                if stream.first_timestamp > message.packet_time:
                    correlated.append(
                        Finding(
                            type="rtp_after_bye",
                            severity="medium",
                            confidence=0.85,
                            source_ip=stream.source_ip,
                            destination_ip=stream.destination_ip,
                            description="RTP media was observed after SIP BYE terminated the call.",
                            evidence=[
                                f"Call-ID: {flow.call_id}",
                                f"BYE method observed: {message.method}",
                                f"RTP SSRC: {stream.ssrc}",
                            ],
                            recommendation=(
                                "Check delayed media teardown, endpoint behavior after hangup, or media streams not stopping when signaling ends."
                            ),
                        )
                    )
                    break

    return correlated


def prioritize_findings(findings):
    suppressed = set()

    for finding in findings:
        if finding.type == "tcp_handshake_reset":
            suppressed.add(
                ("tcp_reset", finding.source_ip, finding.destination_ip)
            )

        if finding.type == "udp_service_unreachable":
            suppressed.add(
                ("udp_no_response", finding.source_ip, finding.destination_ip)
            )

        if finding.type == "udp_burst_no_response":
            suppressed.add(
                ("udp_no_response", finding.source_ip, finding.destination_ip)
            )

    prioritized = []

    for finding in findings:
        key = (finding.type, finding.source_ip, finding.destination_ip)

        if key in suppressed:
            continue

        prioritized.append(finding)

    return prioritized


def build_call_summaries(sip_flows, rtp_streams, findings):
    summaries = []

    rtp_by_pair = {}

    for stream in rtp_streams.values():
        key = tuple(sorted([stream.source_ip, stream.destination_ip]))
        rtp_by_pair.setdefault(key, []).append(stream)

    for flow in sip_flows.values():
        pair_key = tuple(sorted([flow.source_ip, flow.destination_ip]))
        related_streams = rtp_by_pair.get(pair_key, [])
        related_findings = [
            finding
            for finding in findings
            if (
                (finding.source_ip == flow.source_ip and finding.destination_ip == flow.destination_ip)
                or (finding.source_ip == flow.destination_ip and finding.destination_ip == flow.source_ip)
            )
        ]

        summaries.append(
            {
                "call_id": flow.call_id,
                "source_ip": flow.source_ip,
                "destination_ip": flow.destination_ip,
                "signaling_state": _get_signaling_state(flow),
                "media_state": _get_media_state(flow, related_streams, related_findings),
                "has_rtp": bool(related_streams),
                "rtp_stream_count": len(related_streams),
                "finding_types": [finding.type for finding in related_findings],
                "severity": _get_summary_severity(related_findings),
                "primary_issue": _get_primary_issue(related_findings),
                "codec_guesses": _get_codec_guesses(related_streams),
                "key_evidence": _get_key_evidence(flow, related_findings, related_streams),
                "recommended_action": _get_recommended_action(related_findings),
            }
        )

    return summaries


def _get_signaling_state(flow):
    if flow.error_responses > 0:
        return "failed"

    if flow.cancels > 0:
        return "cancelled"

    if flow.success_responses > 0 and flow.acknowledgements > 0:
        if flow.byes > 0:
            return "terminated"
        return "established"

    if flow.success_responses > 0 and flow.acknowledgements == 0:
        return "missing_ack"

    if flow.invites > 0 and flow.responses == 0:
        return "no_response"

    return "incomplete"


def _get_media_state(flow, related_streams, related_findings):
    finding_types = {finding.type for finding in related_findings}

    if not related_streams:
        return "no_media"

    if "sip_call_one_way_audio" in finding_types or "rtp_one_way_audio" in finding_types:
        return "one_way_media"

    if any(
        finding_type in finding_types
        for finding_type in {
            "rtp_packet_loss",
            "rtp_high_jitter",
            "rtp_out_of_order",
            "rtp_timestamp_anomaly",
            "rtp_stream_interruption",
        }
    ):
        return "degraded_media"

    return "media_present"


def _get_summary_severity(related_findings):
    severity_rank = {
        "low": 1,
        "medium": 2,
        "high": 3,
    }

    highest = "low"

    for finding in related_findings:
        if severity_rank.get(finding.severity, 0) > severity_rank[highest]:
            highest = finding.severity

    return highest


def _get_primary_issue(related_findings):
    if not related_findings:
        return None

    priority = {
        "sip_call_one_way_audio": 100,
        "sip_call_established_without_rtp": 95,
        "sip_ok_without_ack": 90,
        "sip_error_response": 90,
        "rtp_after_bye": 85,
        "rtp_packet_loss": 80,
        "rtp_high_jitter": 75,
        "rtp_stream_interruption": 75,
        "rtp_one_way_audio": 75,
        "rtp_out_of_order": 70,
        "rtp_timestamp_anomaly": 70,
        "sip_invite_no_response": 70,
        "sip_call_cancelled": 60,
        "udp_service_unreachable": 60,
        "udp_no_response": 50,
    }

    best_finding = None
    best_score = -1

    for finding in related_findings:
        score = priority.get(finding.type, 10)

        if score > best_score:
            best_score = score
            best_finding = finding

    return best_finding.type if best_finding is not None else None


def _get_codec_guesses(related_streams):
    codec_guesses = []

    for stream in related_streams:
        for codec in stream.codec_guesses:
            if codec not in codec_guesses:
                codec_guesses.append(codec)

    return codec_guesses


def _get_key_evidence(flow, related_findings, related_streams):
    evidence = [f"Call-ID: {flow.call_id}"]

    if related_streams:
        evidence.append(f"RTP streams: {len(related_streams)}")

    for finding in related_findings:
        for item in finding.evidence:
            if item not in evidence:
                evidence.append(item)

            if len(evidence) >= 5:
                return evidence

    return evidence


def _get_recommended_action(related_findings):
    primary_issue = _get_primary_issue(related_findings)

    for finding in related_findings:
        if finding.type == primary_issue:
            return finding.recommendation

    if related_findings:
        return related_findings[0].recommendation

    return ""
