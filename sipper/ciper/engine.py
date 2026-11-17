from ciper.flows import build_tcp_flows, build_icmp_flows
from ciper.fragmentation import build_ip_fragment_groups
from ciper.rtcp import build_rtcp_reports
from ciper.rtp import build_rtp_streams, filter_rtp_candidates
from ciper.sip import (
    build_sip_flows,
    get_sip_method_responses,
    get_successful_invite_responses,
    get_terminal_sip_method_errors,
    has_matching_sip_ack,
)
from ciper.tls import build_tls_flows
from ciper.tcp_reassembly import reassemble_tcp_payloads
from ciper.packets import ensure_decoded
from ciper.udp_flows import build_udp_flows
from ciper.pcap_reader import iter_pcap
from ciper.settings import AnalysisSettings
from ciper.analysis_control import raise_if_cancelled
from ciper.detectors.fragmentation import detect_ip_fragmentation
from ciper.detectors.freeswitch import detect_freeswitch_compatibility
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
    detect_sip_retransmissions,
    detect_sip_sdp_private_address,
    detect_sip_signaling_fragmentation,
    detect_sip_slow_call_setup,
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
from ciper.detectors.rtcp import (
    detect_rtcp_high_rtt,
    detect_rtcp_reported_jitter,
    detect_rtcp_reported_loss,
)
from ciper.detectors.tls import (
    detect_tls_client_hello_no_response,
    detect_tls_fatal_alerts,
    detect_tls_legacy_versions,
    detect_tls_malformed_records,
    detect_tls_weak_cipher_suites,
)


ANALYSIS_STAGES = (
    "Lendo pacotes",
    "Montando fluxos",
    "Analisando SIP e RTP",
    "Executando diagnosticos",
    "Correlacionando eventos",
)


def analyze_pcap(packets, settings=None, cancel_event=None, packet_observer=None, progress=None):
    return _analyze_pcap_sources(
        lambda: iter(packets),
        settings,
        cancel_event,
        packet_observer,
        progress,
    )


def analyze_pcap_file(file_path, settings=None, cancel_event=None, packet_observer=None, progress=None):
    """Analyze a capture file.

    ``progress``, when given, is called as ``progress(stage, fraction)`` where
    ``stage`` is one of ``ANALYSIS_STAGES`` and ``fraction`` is the overall
    completion between 0 and 1. Reading the file accounts for most of the
    work, so it maps to the first 80% of the range.
    """
    if progress is None:
        source = lambda: iter_pcap(file_path)
    else:
        def report_read(bytes_read, total_bytes):
            progress(ANALYSIS_STAGES[0], 0.8 * bytes_read / max(1, total_bytes))

        source = lambda: iter_pcap(file_path, progress=report_read)

    return _analyze_pcap_sources(source, settings, cancel_event, packet_observer, progress)


def _analyze_pcap_sources(packet_source, settings=None, cancel_event=None, packet_observer=None, progress=None):
    settings = settings or AnalysisSettings()
    raise_if_cancelled(cancel_event)
    report = progress or (lambda _stage, _fraction: None)
    tcp_packets = []
    udp_packets = []
    icmp_packets = []
    fragmented_packets = []
    packet_count = 0
    is_cancelled = cancel_event.is_set if cancel_event is not None else None

    for packet in packet_source():
        packet = ensure_decoded(packet)
        packet_count += 1
        if is_cancelled is not None and is_cancelled():
            raise_if_cancelled(cancel_event)
        if packet_observer is not None:
            packet_observer(packet)
        transport = packet.transport
        if transport == "UDP":
            udp_packets.append(packet)
        elif transport == "TCP":
            tcp_packets.append(packet)
        elif transport == "ICMP":
            icmp_packets.append(packet)
        if packet.fragmented:
            fragmented_packets.append(packet)

    report(ANALYSIS_STAGES[1], 0.82)
    raise_if_cancelled(cancel_event)
    flows = build_tcp_flows(tcp_packets)
    udp_flows = build_udp_flows(udp_packets)
    icmp_flows = build_icmp_flows(icmp_packets)
    tcp_blocks = reassemble_tcp_payloads(tcp_packets)
    raise_if_cancelled(cancel_event)

    report(ANALYSIS_STAGES[2], 0.88)
    sip_flows = build_sip_flows(udp_packets, tcp_blocks=tcp_blocks)
    rtp_streams = filter_rtp_candidates(
        build_rtp_streams(
            udp_packets,
            _get_rtp_clock_rates(sip_flows),
            _get_rtp_payload_names(sip_flows),
        ),
        _get_announced_media_endpoints(sip_flows),
        _get_signaled_host_pairs(sip_flows),
    )
    rtcp_reports = build_rtcp_reports(udp_packets, rtp_streams)
    fragment_groups = build_ip_fragment_groups(fragmented_packets)
    tls_flows = build_tls_flows(flows, tcp_blocks=tcp_blocks)
    del tcp_blocks
    raise_if_cancelled(cancel_event)

    report(ANALYSIS_STAGES[3], 0.93)

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
    findings.extend(detect_sip_retransmissions(sip_flows))
    findings.extend(detect_sip_slow_call_setup(sip_flows))
    findings.extend(detect_sip_sdp_private_address(sip_flows))
    if settings.target_platform == "freeswitch":
        findings.extend(
            detect_freeswitch_compatibility(sip_flows, settings.target_platform_ips)
        )
    hold_stream_keys, one_way_expected_keys = _get_negotiated_media_exceptions(sip_flows, rtp_streams)
    findings.extend(
        detect_rtp_packet_loss(
            rtp_streams,
            settings.rtp_loss_high_threshold,
            settings.rtp_loss_high_percent,
        )
    )
    findings.extend(detect_rtp_out_of_order(rtp_streams))
    findings.extend(detect_rtp_high_jitter(rtp_streams, settings.rtp_high_jitter_threshold))
    findings.extend(detect_rtp_timestamp_anomaly(rtp_streams))
    findings.extend(detect_rtp_stream_interruption(rtp_streams, hold_stream_keys))
    findings.extend(detect_rtp_payload_type_change(rtp_streams))
    findings.extend(detect_rtp_ssrc_change(rtp_streams))
    findings.extend(detect_rtp_one_way_audio(rtp_streams, one_way_expected_keys))
    findings.extend(detect_rtcp_reported_loss(rtcp_reports, settings.rtp_loss_high_percent))
    findings.extend(detect_rtcp_reported_jitter(rtcp_reports, settings.rtp_high_jitter_threshold))
    findings.extend(detect_rtcp_high_rtt(rtcp_reports))
    findings.extend(detect_sdp_media_mismatches(sip_flows, rtp_streams))

    findings.extend(detect_icmp_no_response(icmp_flows))
    findings.extend(detect_icmp_redirect(icmp_flows))
    findings.extend(detect_icmp_parameter_problem(icmp_flows))
    findings.extend(detect_icmp_time_exceeded(icmp_flows))
    findings.extend(detect_icmp_unreachable(icmp_flows))
    findings.extend(detect_ip_fragmentation(fragment_groups))
    raise_if_cancelled(cancel_event)
    report(ANALYSIS_STAGES[4], 0.97)
    findings.extend(correlate_findings(findings, sip_flows, rtp_streams))
    attach_references(findings)
    findings = prioritize_findings(findings)
    call_summaries = build_call_summaries(sip_flows, rtp_streams, findings, rtcp_reports)
    report(ANALYSIS_STAGES[4], 1.0)

    return {
        "flows": flows,
        "udp_flows": udp_flows,
        "icmp_flows": icmp_flows,
        "fragment_groups": fragment_groups,
        "sip_flows": sip_flows,
        "rtp_streams": rtp_streams,
        "rtcp_reports": rtcp_reports,
        "tls_flows": tls_flows,
        "findings": findings,
        "call_summaries": call_summaries,
        "analysis_profile": {
            "target_platform": settings.target_platform,
            "target_platform_ips": settings.target_platform_ips,
        },
        "analysis_stats": {
            "packet_count": packet_count,
            "tcp_packet_count": len(tcp_packets),
            "udp_packet_count": len(udp_packets),
            "icmp_packet_count": len(icmp_packets),
        },
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
                        description="A requisicao UDP ficou sem resposta e um ICMP unreachable indica que o servico ou o caminho a rejeitou.",
                        evidence=[
                            f"UDP finding: {udp_finding.type}",
                            f"ICMP finding: {icmp_finding.type}",
                            f"Source: {udp_finding.source_ip}",
                            f"Destination: {udp_finding.destination_ip}",
                        ],
                        recommendation=(
                            "Verifique se o servico de destino esta escutando, se a porta esta aberta e se algum firewall ou politica de rede esta rejeitando o trafego."
                        ),
                    )
                )
                break

    for flow in sip_flows.values():
        if (
            _call_is_established(flow)
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
                    description="A sinalizacao SIP da chamada foi concluida, mas nenhum stream RTP foi observado.",
                    evidence=[
                        f"Call-ID: {flow.call_id}",
                        f"Dialog-Key: {flow.dialog_key}",
                        f"200 OK responses: {flow.success_responses}",
                        f"ACKs: {flow.acknowledgements}",
                        "RTP streams observed: 0",
                    ],
                    recommendation=(
                        "Verifique a negociacao SDP, NAT, alcance das portas RTP ou endpoints que nao iniciaram a midia."
                    ),
                )
            )

    if rtp_streams:
        for stream_key, stream in rtp_streams.items():
            if any(
                _get_related_rtp_streams(flow, {stream_key: stream})
                for flow in sip_flows.values()
            ):
                continue
            correlated.append(
                Finding(
                    type="rtp_without_sip",
                    severity="medium",
                    confidence=0.80,
                    source_ip=stream.source_ip,
                    destination_ip=stream.destination_ip,
                    description="Midia RTP foi observada sem um dialogo SIP correspondente.",
                    evidence=[
                        f"SSRC: {stream.ssrc}",
                        f"Packets observed: {stream.packet_count}",
                    ],
                    recommendation=(
                        "Verifique se a sinalizacao foi capturada, se a chamada usa outro protocolo de sinalizacao ou se a midia ficou orfa do dialogo esperado."
                    ),
                )
            )

    one_way_findings = [
        finding for finding in findings if finding.type == "rtp_one_way_audio"
    ]

    for flow in sip_flows.values():
        if (
            not _call_is_established(flow)
            or not _expects_bidirectional_media(flow)
        ):
            continue

        related_streams = _get_related_rtp_streams(flow, rtp_streams)
        for finding in one_way_findings:
            if _finding_matches_related_stream(finding, related_streams):
                correlated.append(
                    Finding(
                        type="sip_call_one_way_audio",
                        severity="high",
                        confidence=0.90,
                        source_ip=flow.source_ip,
                        destination_ip=flow.destination_ip,
                        description="A chamada SIP foi estabelecida, mas o RTP indica provavel audio em uma via.",
                        evidence=[
                            f"Call-ID: {flow.call_id}",
                            f"Dialog-Key: {flow.dialog_key}",
                            f"RTP finding: {finding.type}",
                        ],
                        recommendation=(
                            "Verifique NAT, enderecos de midia no SDP, regras de firewall e se os dois endpoints conseguem enviar e receber RTP."
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

                teardown_delay = stream.last_timestamp - message.packet_time
                if teardown_delay > 0.1:
                    correlated.append(
                        Finding(
                            type="rtp_after_bye",
                            severity="medium",
                            confidence=0.85,
                            source_ip=stream.source_ip,
                            destination_ip=stream.destination_ip,
                            description="Midia RTP foi observada depois que o BYE SIP encerrou a chamada.",
                            evidence=[
                                f"Call-ID: {flow.call_id}",
                                f"Dialog-Key: {flow.dialog_key}",
                                f"BYE method observed: {message.method}",
                                f"RTP SSRC: {stream.ssrc}",
                                f"Media after BYE: {teardown_delay:.3f} s",
                            ],
                            recommendation=(
                                "Verifique atraso no encerramento da midia, comportamento do endpoint apos desligar ou streams que nao param quando a sinalizacao termina."
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


def build_call_summaries(sip_flows, rtp_streams, findings, rtcp_reports=None):
    summaries = []

    for flow in sip_flows.values():
        related_streams = _get_related_rtp_streams(flow, rtp_streams)
        sdp_media = _get_sdp_media(flow)
        related_findings = _get_related_call_findings(flow, findings, related_streams)
        codec_guesses = _get_codec_guesses(related_streams, sdp_media)
        rtp_metrics = _get_rtp_metrics(related_streams, codec_guesses)
        rtp_metrics["rtt"] = _get_related_rtt(related_streams, rtcp_reports)

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
                "rtp_stream_keys": [
                    (
                        stream.source_ip,
                        stream.source_port,
                        stream.destination_ip,
                        stream.destination_port,
                        stream.ssrc,
                    )
                    for stream in related_streams
                ],
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
        and _stream_overlaps_sip_flow(flow, stream)
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


def _stream_overlaps_sip_flow(flow, stream):
    if stream.first_timestamp is None or stream.last_timestamp is None or not flow.messages:
        return True

    flow_start = min(message.packet_time for message in flow.messages)
    if stream.last_timestamp < flow_start - 1.0:
        return False

    terminal_times = [
        message.packet_time
        for message in flow.messages
        if message.is_request and message.method in {"BYE", "CANCEL"}
    ]
    if terminal_times and stream.first_timestamp > min(terminal_times) + 1.0:
        return False

    return True


def _get_related_call_findings(flow, findings, related_streams):
    related = []

    for finding in findings:
        finding_dialog_keys = _get_finding_dialog_keys(finding)
        if finding_dialog_keys:
            if flow.dialog_key in finding_dialog_keys:
                related.append(finding)
            continue

        finding_call_ids = _get_finding_call_ids(finding)
        if finding_call_ids:
            if flow.call_id in finding_call_ids:
                related.append(finding)
            continue

        if finding.type.startswith("rtp_") or finding.type == "sip_call_one_way_audio":
            if _finding_matches_related_stream(finding, related_streams):
                related.append(finding)
            continue

        if (
            (finding.source_ip == flow.source_ip and finding.destination_ip == flow.destination_ip)
            or (finding.source_ip == flow.destination_ip and finding.destination_ip == flow.source_ip)
        ):
            related.append(finding)

    return related


def _get_finding_dialog_keys(finding):
    return {
        evidence.removeprefix("Dialog-Key: ").strip()
        for evidence in finding.evidence
        if evidence.startswith("Dialog-Key: ")
    }


def _get_finding_call_ids(finding):
    return {
        evidence.removeprefix("Call-ID: ").strip()
        for evidence in finding.evidence
        if evidence.startswith("Call-ID: ")
    }


def _finding_matches_related_stream(finding, related_streams):
    return any(
        finding.source_ip == stream.source_ip
        and finding.destination_ip == stream.destination_ip
        and f"SSRC: {stream.ssrc}" in finding.evidence
        for stream in related_streams
    )


def _get_sdp_media(flow):
    messages_with_sdp = [message for message in flow.messages if message.sdp_media]

    if flow.invites > 1:
        messages_with_sdp = messages_with_sdp[-2:]

    return [media for message in messages_with_sdp for media in message.sdp_media]


def _get_rtp_clock_rates(sip_flows):
    clock_rates = {}

    for flow in sip_flows.values():
        for message in flow.messages:
            for media in message.sdp_media:
                if media.media_type != "audio":
                    continue
                address = media.connection_address or message.source_ip
                for payload_type, clock_rate in media.clock_rates.items():
                    key = (address, media.port, payload_type)
                    clock_rates.setdefault(key, []).append(
                        (float(message.packet_time), clock_rate)
                    )

    return clock_rates


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
    unique_packet_count = sum(
        getattr(stream, "unique_packet_count", 0) or stream.packet_count
        for stream in related_streams
    )
    loss_observed_packet_count = sum(
        getattr(stream, "loss_observed_packet_count", 0)
        or getattr(stream, "unique_packet_count", 0)
        or stream.packet_count
        for stream in related_streams
    )
    duplicate_packets = sum(getattr(stream, "duplicate_packets", 0) for stream in related_streams)
    lost_packets = sum(stream.lost_packets for stream in related_streams)
    expected_packets = loss_observed_packet_count + lost_packets
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
                "unique_packet_count": 0,
                "loss_observed_packet_count": 0,
                "duplicate_packets": 0,
                "lost_packets": 0,
                "out_of_order_packets": 0,
                "interruptions": 0,
                "max_jitter": 0.0,
                "duration": 0.0,
            },
        )
        metric["packet_count"] += stream.packet_count
        metric["unique_packet_count"] += getattr(stream, "unique_packet_count", 0) or stream.packet_count
        metric["loss_observed_packet_count"] += (
            getattr(stream, "loss_observed_packet_count", 0)
            or getattr(stream, "unique_packet_count", 0)
            or stream.packet_count
        )
        metric["duplicate_packets"] += getattr(stream, "duplicate_packets", 0)
        metric["lost_packets"] += stream.lost_packets
        metric["out_of_order_packets"] += stream.out_of_order_packets
        metric["interruptions"] += stream.interruptions
        metric["max_jitter"] = max(metric["max_jitter"], stream.max_jitter)
        metric["duration"] = max(metric["duration"], stream.duration)

    for metric in directions.values():
        expected = metric["loss_observed_packet_count"] + metric["lost_packets"]
        metric["loss_percent"] = (metric["lost_packets"] / expected * 100) if expected else 0.0
        metric["packet_rate"] = metric["packet_count"] / metric["duration"] if metric["duration"] else 0.0

    return {
        "packet_count": packet_count,
        "unique_packet_count": unique_packet_count,
        "loss_observed_packet_count": loss_observed_packet_count,
        "duplicate_packets": duplicate_packets,
        "lost_packets": lost_packets,
        "loss_percent": (lost_packets / expected_packets * 100) if expected_packets else 0.0,
        "out_of_order_packets": sum(stream.out_of_order_packets for stream in related_streams),
        "interruptions": sum(stream.interruptions for stream in related_streams),
        "average_jitter": (sum(jitter_samples) / len(jitter_samples)) if jitter_samples else 0.0,
        "max_jitter": max((stream.max_jitter for stream in related_streams), default=0.0),
        "peak_transit_variation": max(
            (getattr(stream, "max_transit_variation", 0.0) for stream in related_streams),
            default=0.0,
        ),
        "silence_periods": sum(getattr(stream, "silence_periods", 0) for stream in related_streams),
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
    rtt = rtp_metrics.get("rtt")
    mos = estimate_mos(
        rtp_metrics["loss_percent"],
        rtp_metrics["max_jitter"],
        codec,
        rtt,
    )
    return {
        "mos_estimate": mos,
        "latency_ms": round(rtt * 1000 / 2, 1) if rtt is not None else None,
        "latency_status": "estimated_from_rtcp_rtt" if rtt is not None else "not_available_in_passive_capture",
        "method": "itu_t_g107_e_model",
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
    invite_errors = get_terminal_sip_method_errors(
        flow,
        "INVITE",
        allow_unspecified=True,
    )
    invite_successes = _invite_responses(flow, 200, 300)

    if flow.cancels > 0:
        return "cancelled"

    if any(has_matching_sip_ack(flow, response) for response in invite_successes):
        if flow.byes > 0:
            return "terminated"
        return "established"

    if invite_successes:
        return "missing_ack"

    if invite_errors:
        return "failed"

    if flow.invites > 0 and not _invite_responses(flow, 100, 700):
        return "no_response"

    return "incomplete"


def _invite_responses(flow, minimum, maximum):
    return [
        response
        for response in get_sip_method_responses(
            flow,
            "INVITE",
            allow_unspecified=True,
        )
        if minimum <= response.status_code < maximum
    ]


def _call_is_established(flow):
    return any(
        has_matching_sip_ack(flow, response)
        for response in get_successful_invite_responses(flow)
    )


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
    evidence = [
        f"Call-ID: {flow.call_id}",
        f"Dialog-Key: {flow.dialog_key}",
    ]

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


def _get_rtp_payload_names(sip_flows):
    names = {}
    for flow in sip_flows.values():
        for message in flow.messages:
            for media in message.sdp_media:
                if media.media_type != "audio":
                    continue
                address = media.connection_address or message.source_ip
                for payload_type, codec in media.codecs.items():
                    names.setdefault((address, media.port, payload_type), []).append(
                        (float(message.packet_time), codec)
                    )
    return names


def _get_announced_media_endpoints(sip_flows):
    endpoints = set()
    for flow in sip_flows.values():
        for message in flow.messages:
            for media in message.sdp_media:
                if media.port <= 0:
                    continue
                address = media.connection_address or message.source_ip
                endpoints.add((address, media.port))
                if media.rtcp_port:
                    endpoints.add((address, media.rtcp_port))
    return endpoints


def _get_signaled_host_pairs(sip_flows):
    pairs = set()
    for flow in sip_flows.values():
        hosts = {flow.source_ip, flow.destination_ip}
        for message in flow.messages:
            for media in message.sdp_media:
                if media.connection_address:
                    hosts.add(media.connection_address)
        hosts = sorted(hosts)
        for index, first in enumerate(hosts):
            for second in hosts[index + 1:]:
                pairs.add(frozenset((first, second)))
    return pairs


def _stream_key(stream):
    return (
        stream.source_ip,
        stream.destination_ip,
        stream.source_port,
        stream.destination_port,
        stream.ssrc,
    )


def _get_negotiated_media_exceptions(sip_flows, rtp_streams):
    """Streams whose gaps or single direction are explained by the SDP.

    Returns (keys whose gaps are explained by hold, keys where one-way media
    was negotiated on purpose).
    """
    hold_keys = set()
    one_way_keys = set()
    for flow in sip_flows.values():
        related = _get_related_rtp_streams(flow, rtp_streams)
        if not related:
            continue
        keys = {_stream_key(stream) for stream in related}
        if flow.hold_events:
            hold_keys.update(keys)
        if _get_media_negotiation_state(flow) in {"unidirectional", "inactive"}:
            one_way_keys.update(keys)
    return hold_keys, one_way_keys


def _get_related_rtt(related_streams, rtcp_reports):
    if not rtcp_reports or not related_streams:
        return None
    ssrcs = {stream.ssrc for stream in related_streams}
    samples = [
        report.max_rtt
        for report in rtcp_reports.values()
        if report.source_ssrc in ssrcs and report.max_rtt is not None
    ]
    return max(samples) if samples else None


def _observed_ptime_ms(stream):
    deltas = []
    previous = None
    auxiliary = getattr(stream, "auxiliary_payload_types", set())
    for packet in stream.packets:
        if packet.payload_type in auxiliary:
            continue
        if previous is not None and (packet.sequence - previous.sequence) & 0xFFFF == 1:
            delta = (packet.timestamp - previous.timestamp) & 0xFFFFFFFF
            if 0 < delta < stream.clock_rate:
                deltas.append(delta)
        previous = packet
    if len(deltas) < 5:
        return None
    deltas.sort()
    return deltas[len(deltas) // 2] / stream.clock_rate * 1000


def detect_sdp_media_mismatches(sip_flows, rtp_streams):
    """Compare what SDP negotiated with what RTP actually carried."""
    findings = []
    for flow in sip_flows.values():
        related = _get_related_rtp_streams(flow, rtp_streams)
        audio = [
            (message, media)
            for message in flow.messages
            for media in message.sdp_media
            if media.media_type == "audio" and media.port > 0
        ]
        if not related or not audio:
            continue

        negotiated = {payload_type for _message, media in audio for payload_type in media.payload_types}
        ptimes = {media.ptime for _message, media in audio if media.ptime}
        advertised = {
            (media.connection_address or message.source_ip, media.port)
            for message, media in audio
        }

        for stream in related:
            unexpected = sorted(getattr(stream, "media_payload_types", stream.payload_types) - negotiated)
            if negotiated and unexpected:
                findings.append(
                    Finding(
                        type="rtp_payload_not_negotiated",
                        severity="medium",
                        confidence=0.85,
                        source_ip=stream.source_ip,
                        destination_ip=stream.destination_ip,
                        description="O RTP usa um payload type que nao foi negociado no SDP.",
                        evidence=[
                            f"Call-ID: {flow.call_id}",
                            f"Dialog-Key: {flow.dialog_key}",
                            f"SSRC: {stream.ssrc}",
                            f"Payload types: {unexpected}",
                            f"Negotiated payload types: {sorted(negotiated)}",
                        ],
                        recommendation=(
                            "O endpoint ignorou a negociacao ou um intermediario transcodificou sem atualizar o SDP. "
                            "O receptor pode descartar a midia, gerando silencio ou ruido."
                        ),
                    )
                )

            observed_ptime = _observed_ptime_ms(stream)
            if ptimes and observed_ptime is not None and all(abs(observed_ptime - ptime) > 5 for ptime in ptimes):
                findings.append(
                    Finding(
                        type="rtp_ptime_mismatch",
                        severity="low",
                        confidence=0.75,
                        source_ip=stream.source_ip,
                        destination_ip=stream.destination_ip,
                        description="A paquetizacao observada no RTP difere do ptime negociado no SDP.",
                        evidence=[
                            f"Call-ID: {flow.call_id}",
                            f"Dialog-Key: {flow.dialog_key}",
                            f"SSRC: {stream.ssrc}",
                            f"Observed ptime: {observed_ptime:.0f} ms",
                            f"SDP ptime: {', '.join(f'{value} ms' for value in sorted(ptimes))}",
                        ],
                        recommendation=(
                            "Alinhe o ptime dos endpoints. Diferencas costumam ser toleradas, mas alguns gateways "
                            "e jitter buffers falham com tamanhos de pacote inesperados."
                        ),
                    )
                )

            destination = (stream.destination_ip, stream.destination_port)
            source = (stream.source_ip, stream.source_port)
            if destination in advertised and source not in advertised:
                findings.append(
                    Finding(
                        type="rtp_source_mismatch",
                        severity="low",
                        confidence=0.70,
                        source_ip=stream.source_ip,
                        destination_ip=stream.destination_ip,
                        description="O RTP chega de um endereco ou porta diferente do anunciado no SDP pelo remetente.",
                        evidence=[
                            f"Call-ID: {flow.call_id}",
                            f"Dialog-Key: {flow.dialog_key}",
                            f"SSRC: {stream.ssrc}",
                            f"RTP source: {stream.source_ip}:{stream.source_port}",
                            f"SDP audio endpoints: {', '.join(f'{ip}:{port}' for ip, port in sorted(advertised))}",
                        ],
                        recommendation=(
                            "Indica NAT ou RTP nao simetrico. Se houver audio em uma via, habilite media latching / "
                            "symmetric RTP no SBC ou PBX e revise o NAT do endpoint."
                        ),
                    )
                )
    return findings
