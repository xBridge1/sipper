from itertools import chain

from ciper.flows import build_tcp_flows, build_icmp_flows
from ciper.fragmentation import build_ip_fragment_groups
from ciper.rtp import build_rtp_streams
from ciper.sip import build_sip_flows
from ciper.tls import build_tls_flows
from ciper.udp_flows import build_udp_flows
from ciper.pcap_reader import iter_pcap
from ciper.settings import AnalysisSettings
from ciper.analysis_control import raise_if_cancelled
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6ExtHdrFragment
from ciper.detectors.fragmentation import detect_ip_fragmentation
from ciper.detectors.udp import detect_udp_burst_no_response, detect_udp_no_response
from ciper.findings import Finding
from ciper.references import attach_references
from ciper.voip_quality import estimate_mos
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
    detect_sip_header_fragmentation_risk,
    detect_sip_header_validation_errors,
    detect_sip_invite_no_response,
    detect_sip_large_headers,
    detect_sip_ok_without_ack,
    detect_sip_options_no_response,
    detect_sip_register_failures,
    detect_sip_signaling_fragmentation,
    detect_sip_transfer_failures,
    detect_sip_udp_fragmentation_risk,
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
from ciper.detectors.tls import (
    detect_tls_client_hello_no_response,
    detect_tls_fatal_alerts,
    detect_tls_legacy_versions,
    detect_tls_malformed_records,
    detect_tls_weak_cipher_suites,
)


def analyze_pcap(packets, settings=None, cancel_event=None, packet_observer=None):
    return _analyze_pcap_sources(
        lambda: _iter_with_cancellation(iter(packets), cancel_event),
        settings,
        cancel_event,
        packet_observer,
    )


def analyze_pcap_file(file_path, settings=None, cancel_event=None, packet_observer=None):
    return _analyze_pcap_sources(
        lambda: _iter_with_cancellation(iter_pcap(file_path), cancel_event),
        settings,
        cancel_event,
        packet_observer,
    )


def _analyze_pcap_sources(packet_source, settings=None, cancel_event=None, packet_observer=None):
    settings = settings or AnalysisSettings()
    raise_if_cancelled(cancel_event)
    tcp_packets = []
    udp_packets = []
    icmp_packets = []
    fragmented_packets = []
    packet_count = 0

    for packet in packet_source():
        packet_count += 1
        raise_if_cancelled(cancel_event)
        if packet_observer is not None:
            packet_observer(packet)
        if TCP in packet:
            tcp_packets.append(packet)
        if UDP in packet:
            udp_packets.append(packet)
        if ICMP in packet:
            icmp_packets.append(packet)
        if (
            (IP in packet and (packet[IP].flags.MF or packet[IP].frag > 0))
            or IPv6ExtHdrFragment in packet
        ):
            fragmented_packets.append(packet)

    flows = build_tcp_flows(tcp_packets)
    udp_flows = build_udp_flows(udp_packets)
    icmp_flows = build_icmp_flows(icmp_packets)
    sip_flows = build_sip_flows(chain(tcp_packets, udp_packets))
    rtp_streams = build_rtp_streams(udp_packets)
    fragment_groups = build_ip_fragment_groups(fragmented_packets)
    tls_flows = build_tls_flows(flows)

    findings = []

    findings.extend(detect_syn_failures(flows))
    findings.extend(detect_tcp_handshake_incomplete(flows))
    findings.extend(detect_tcp_handshake_reset(flows))
    findings.extend(detect_slow_handshakes(flows))
    findings.extend(detect_tcp_retransmissions(flows))
    findings.extend(detect_tcp_resets(flows))
    findings.extend(detect_tls_fatal_alerts(tls_flows))
    findings.extend(detect_tls_client_hello_no_response(tls_flows))
    findings.extend(detect_tls_legacy_versions(tls_flows))
    findings.extend(detect_tls_malformed_records(tls_flows))
    findings.extend(detect_tls_weak_cipher_suites(tls_flows))

    findings.extend(detect_udp_no_response(udp_flows))
    findings.extend(detect_udp_burst_no_response(udp_flows))
    findings.extend(detect_sip_call_established(sip_flows))
    findings.extend(detect_sip_call_cancelled(sip_flows))
    findings.extend(detect_sip_call_terminated(sip_flows))
    findings.extend(detect_sip_error_responses(sip_flows))
    findings.extend(detect_sip_invite_no_response(sip_flows))
    findings.extend(detect_sip_large_headers(sip_flows))
    findings.extend(detect_sip_header_validation_errors(sip_flows))
    findings.extend(detect_sip_header_fragmentation_risk(sip_flows))
    findings.extend(detect_sip_ok_without_ack(sip_flows))
    findings.extend(detect_sip_register_failures(sip_flows))
    findings.extend(detect_sip_transfer_failures(sip_flows))
    findings.extend(detect_sip_options_no_response(sip_flows))
    findings.extend(detect_sip_udp_fragmentation_risk(sip_flows))
    findings.extend(detect_sip_signaling_fragmentation(sip_flows, fragment_groups))
    findings.extend(detect_rtp_packet_loss(rtp_streams, settings.rtp_loss_high_threshold))
    findings.extend(detect_rtp_out_of_order(rtp_streams))
    findings.extend(detect_rtp_high_jitter(rtp_streams, settings.rtp_high_jitter_threshold))
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
    findings.extend(detect_ip_fragmentation(fragment_groups))
    findings.extend(correlate_findings(findings, sip_flows, rtp_streams))
    attach_references(findings)
    findings = prioritize_findings(findings)
    call_summaries = build_call_summaries(sip_flows, rtp_streams, findings)

    return {
        "flows": flows,
        "udp_flows": udp_flows,
        "icmp_flows": icmp_flows,
        "fragment_groups": fragment_groups,
        "sip_flows": sip_flows,
        "rtp_streams": rtp_streams,
        "tls_flows": tls_flows,
        "findings": findings,
        "call_summaries": call_summaries,
        "analysis_stats": {
            "packet_count": packet_count,
            "tcp_packet_count": len(tcp_packets),
            "udp_packet_count": len(udp_packets),
            "icmp_packet_count": len(icmp_packets),
        },
    }


def _iter_with_cancellation(packets, cancel_event):
    for packet in packets:
        raise_if_cancelled(cancel_event)
        yield packet


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

    for flow in sip_flows.values():
        if (
            flow.success_responses > 0
            and flow.acknowledgements > 0
            and _expects_media(flow)
            and not _get_related_rtp_streams(flow, rtp_streams)
        ):
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

    one_way_findings = [
        finding for finding in findings if finding.type == "rtp_one_way_audio"
    ]

    for flow in sip_flows.values():
        if (
            flow.success_responses <= 0
            or flow.acknowledgements <= 0
            or not _expects_bidirectional_media(flow)
        ):
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
            for stream in _get_related_rtp_streams(flow, rtp_streams):
                if stream.last_timestamp is None:
                    continue

                if stream.last_timestamp > message.packet_time:
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

    for flow in sip_flows.values():
        related_streams = _get_related_rtp_streams(flow, rtp_streams)
        sdp_media = _get_sdp_media(flow)
        related_findings = _get_related_call_findings(flow, findings, related_streams)
        codec_guesses = _get_codec_guesses(related_streams, sdp_media)
        rtp_metrics = _get_rtp_metrics(related_streams, codec_guesses)

        summaries.append(
            {
                "call_id": flow.call_id,
                "dialog_key": flow.dialog_key,
                "source_ip": flow.source_ip,
                "destination_ip": flow.destination_ip,
                "signaling_state": _get_signaling_state(flow),
                "media_state": _get_media_state(flow, related_streams, related_findings),
                "media_direction": _get_media_negotiation_state(flow),
                "has_rtp": bool(related_streams),
                "rtp_stream_count": len(related_streams),
                "start_time": _get_call_start_time(flow, related_streams),
                "end_time": _get_call_end_time(flow, related_streams),
                "duration": _get_call_duration(flow, related_streams),
                "rtp_metrics": rtp_metrics,
                "media_quality": _get_media_quality(related_streams),
                "media_quality_metrics": _get_media_quality_metrics(rtp_metrics),
                "signaling_timeline": _get_signaling_timeline(flow),
                "signaling_timings": _get_signaling_timings(flow),
                "signaling_operations": _get_signaling_operations(flow),
                "finding_types": [finding.type for finding in related_findings],
                "severity": _get_summary_severity(related_findings),
                "primary_issue": _get_primary_issue(related_findings),
                "codec_guesses": codec_guesses,
                "key_evidence": _get_key_evidence(flow, related_findings, related_streams),
                "recommended_action": _get_recommended_action(related_findings),
            }
        )

    return summaries


def _get_related_rtp_streams(flow, rtp_streams):
    sdp_messages = [message for message in flow.messages if message.sdp_media]
    if flow.invites > 1:
        sdp_messages = sdp_messages[-2:]
    audio_messages = [
        (message, media)
        for message in sdp_messages
        for media in message.sdp_media
        if media.media_type == "audio" and media.port > 0 and media.direction != "inactive"
    ]
    audio_media = [media for _message, media in audio_messages]
    endpoint_ips = {flow.source_ip, flow.destination_ip}
    endpoint_ips.update(
        media.connection_address
        for media in audio_media
        if media.connection_address
    )
    pair_streams = [
        stream
        for stream in rtp_streams.values()
        if stream.source_ip in endpoint_ips and stream.destination_ip in endpoint_ips
    ]

    if not audio_media:
        return pair_streams

    advertised_endpoints = {
        (media.connection_address or message.source_ip, media.port)
        for message, media in audio_messages
    }

    return [
        stream
        for stream in pair_streams
        if (stream.source_ip, stream.source_port) in advertised_endpoints
        or (stream.destination_ip, stream.destination_port) in advertised_endpoints
    ]


def _get_related_call_findings(flow, findings, related_streams):
    related_ssrcs = {stream.ssrc for stream in related_streams}
    related = []

    for finding in findings:
        if _finding_mentions_call_id(finding, flow.call_id):
            related.append(finding)
            continue

        if finding.type.startswith("rtp_") or finding.type == "sip_call_one_way_audio":
            if _finding_mentions_related_ssrc(finding, related_ssrcs):
                related.append(finding)
            continue

        if (
            (finding.source_ip == flow.source_ip and finding.destination_ip == flow.destination_ip)
            or (finding.source_ip == flow.destination_ip and finding.destination_ip == flow.source_ip)
        ):
            related.append(finding)

    return related


def _finding_mentions_call_id(finding, call_id):
    return f"Call-ID: {call_id}" in finding.evidence


def _finding_mentions_related_ssrc(finding, related_ssrcs):
    return any(
        evidence == f"SSRC: {ssrc}"
        for evidence in finding.evidence
        for ssrc in related_ssrcs
    )


def _get_sdp_media(flow):
    messages_with_sdp = [message for message in flow.messages if message.sdp_media]

    if flow.invites > 1:
        messages_with_sdp = messages_with_sdp[-2:]

    return [media for message in messages_with_sdp for media in message.sdp_media]


def _get_media_negotiation_state(flow):
    audio_media = [media for media in _get_sdp_media(flow) if media.media_type == "audio"]

    if not audio_media:
        return "unknown"

    if all(media.port == 0 or media.direction == "inactive" for media in audio_media):
        return "inactive"

    if any(media.direction in {"sendonly", "recvonly"} for media in audio_media):
        return "unidirectional"

    return "bidirectional"


def _get_signaling_operations(flow):
    return {
        "registers": flow.registers,
        "options": flow.options,
        "transfers": flow.refers,
        "reinvites": flow.reinvites,
        "holds": flow.hold_events,
        "resumes": flow.resume_events,
    }


def _expects_media(flow):
    return _get_media_negotiation_state(flow) != "inactive"


def _expects_bidirectional_media(flow):
    return _get_media_negotiation_state(flow) in {"unknown", "bidirectional"}


def _get_call_start_time(flow, related_streams):
    timestamps = [message.packet_time for message in flow.messages]
    timestamps.extend(
        stream.first_timestamp
        for stream in related_streams
        if stream.first_timestamp is not None
    )
    return min(timestamps) if timestamps else None


def _get_call_end_time(flow, related_streams):
    timestamps = [message.packet_time for message in flow.messages]
    timestamps.extend(
        stream.last_timestamp
        for stream in related_streams
        if stream.last_timestamp is not None
    )
    return max(timestamps) if timestamps else None


def _get_call_duration(flow, related_streams):
    start_time = _get_call_start_time(flow, related_streams)
    end_time = _get_call_end_time(flow, related_streams)

    if start_time is None or end_time is None:
        return 0.0

    return end_time - start_time


def _get_rtp_metrics(related_streams, codec_guesses=None):
    packet_count = sum(stream.packet_count for stream in related_streams)
    lost_packets = sum(stream.lost_packets for stream in related_streams)
    expected_packets = packet_count + lost_packets
    jitter_samples = [
        sample
        for stream in related_streams
        for sample in stream.jitter_samples
    ]

    directions = {}

    for stream in related_streams:
        key = f"{stream.source_ip}:{stream.source_port}->{stream.destination_ip}:{stream.destination_port}"
        metric = directions.setdefault(
            key,
            {
                "packet_count": 0,
                "lost_packets": 0,
                "out_of_order_packets": 0,
                "interruptions": 0,
                "max_jitter": 0.0,
                "duration": 0.0,
            },
        )
        metric["packet_count"] += stream.packet_count
        metric["lost_packets"] += stream.lost_packets
        metric["out_of_order_packets"] += stream.out_of_order_packets
        metric["interruptions"] += stream.interruptions
        metric["max_jitter"] = max(metric["max_jitter"], stream.max_jitter)
        metric["duration"] = max(metric["duration"], stream.duration)

    for metric in directions.values():
        expected = metric["packet_count"] + metric["lost_packets"]
        metric["loss_percent"] = (metric["lost_packets"] / expected * 100) if expected else 0.0
        metric["packet_rate"] = metric["packet_count"] / metric["duration"] if metric["duration"] else 0.0

    return {
        "packet_count": packet_count,
        "lost_packets": lost_packets,
        "loss_percent": (lost_packets / expected_packets * 100) if expected_packets else 0.0,
        "out_of_order_packets": sum(stream.out_of_order_packets for stream in related_streams),
        "interruptions": sum(stream.interruptions for stream in related_streams),
        "average_jitter": (sum(jitter_samples) / len(jitter_samples)) if jitter_samples else 0.0,
        "max_jitter": max((stream.max_jitter for stream in related_streams), default=0.0),
        "rfc_jitter": max((stream.rfc_jitter for stream in related_streams), default=0.0),
        "clock_rates": sorted({stream.clock_rate for stream in related_streams}),
        "codec_guesses": codec_guesses or [],
        "ssrcs": sorted({stream.ssrc for stream in related_streams}),
        "directions": directions,
    }


def _get_media_quality_metrics(rtp_metrics):
    if rtp_metrics["packet_count"] == 0:
        return {
            "mos_estimate": None,
            "latency_ms": None,
            "latency_status": "not_available_in_passive_capture",
            "method": "not_available_without_rtp",
        }

    codec = next(iter(rtp_metrics.get("codec_guesses", [])), None)
    mos = estimate_mos(
        rtp_metrics["loss_percent"],
        rtp_metrics["max_jitter"],
        codec,
    )
    return {
        "mos_estimate": mos,
        "latency_ms": None,
        "latency_status": "not_available_in_passive_capture",
        "method": "loss_and_rtp_transit_variation",
    }


def _get_signaling_timeline(flow):
    if not flow.messages:
        return []

    start_time = min(message.packet_time for message in flow.messages)
    timeline = []

    for message in flow.messages:
        if message.is_request:
            event = message.method or "REQUEST"
        else:
            event = f"{message.status_code} {message.reason_phrase or ''}".strip()

        timeline.append(
            {
                "event": event,
                "timestamp": message.packet_time,
                "offset": max(0.0, message.packet_time - start_time),
                "source_ip": message.source_ip,
                "destination_ip": message.destination_ip,
            }
        )

    return timeline


def _get_signaling_timings(flow):
    event_times = {
        "invite": None,
        "trying": None,
        "ringing": None,
        "ok": None,
        "ack": None,
    }

    for message in flow.messages:
        if message.is_request and message.method == "INVITE" and event_times["invite"] is None:
            event_times["invite"] = message.packet_time
        elif message.is_request and message.method == "ACK" and event_times["ack"] is None:
            event_times["ack"] = message.packet_time
        elif not message.is_request and message.status_code == 100 and event_times["trying"] is None:
            event_times["trying"] = message.packet_time
        elif not message.is_request and message.status_code == 180 and event_times["ringing"] is None:
            event_times["ringing"] = message.packet_time
        elif not message.is_request and 200 <= message.status_code < 300 and event_times["ok"] is None:
            event_times["ok"] = message.packet_time

    invite_time = event_times["invite"]
    return {
        "invite_to_trying": _elapsed_seconds(invite_time, event_times["trying"]),
        "invite_to_ringing": _elapsed_seconds(invite_time, event_times["ringing"]),
        "invite_to_ok": _elapsed_seconds(invite_time, event_times["ok"]),
        "ok_to_ack": _elapsed_seconds(event_times["ok"], event_times["ack"]),
        "invite_to_ack": _elapsed_seconds(invite_time, event_times["ack"]),
    }


def _elapsed_seconds(start_time, end_time):
    if start_time is None or end_time is None:
        return None
    return max(0.0, end_time - start_time)


def _get_media_quality(related_streams):
    metrics = _get_rtp_metrics(related_streams)

    if not metrics["packet_count"]:
        return "unknown"

    if (
        metrics["loss_percent"] >= 5
        or metrics["max_jitter"] >= 0.1
        or metrics["interruptions"] > 0
    ):
        return "poor"

    if metrics["loss_percent"] >= 1 or metrics["max_jitter"] >= 0.04:
        return "degraded"

    return "good"


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

    if _get_media_negotiation_state(flow) == "inactive":
        return "inactive_media"

    if not related_streams:
        return "no_media"

    if _expects_bidirectional_media(flow) and (
        "sip_call_one_way_audio" in finding_types or "rtp_one_way_audio" in finding_types
    ):
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


def _get_codec_guesses(related_streams, sdp_media):
    codec_guesses = []
    codecs_by_payload_type = {
        payload_type: codec
        for media in sdp_media
        for payload_type, codec in media.codecs.items()
    }

    for stream in related_streams:
        codecs = [
            codecs_by_payload_type.get(payload_type)
            for payload_type in sorted(stream.payload_types)
        ]
        codecs = [codec for codec in codecs if codec] or stream.codec_guesses

        for codec in codecs:
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
