from ciper.findings import Finding


def detect_rtp_packet_loss(streams):
    findings = []
    for stream in streams.values():
        if stream.lost_packets == 0:
            continue
        findings.append(
            Finding(
                type="rtp_packet_loss",
                severity="high" if stream.lost_packets >= 2 else "medium",
                confidence=0.95,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="RTP packet loss was detected.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Lost packets: {stream.lost_packets}",
                    f"Packets observed: {stream.packet_count}",
                ],
                recommendation="Check congestion, packet drops, QoS, or unstable WAN/LAN links.",
            )
        )
    return findings


def detect_rtp_out_of_order(streams):
    findings = []
    for stream in streams.values():
        if stream.out_of_order_packets == 0:
            continue
        findings.append(
            Finding(
                type="rtp_out_of_order",
                severity="medium",
                confidence=0.90,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="Out-of-order RTP packets were detected.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Out-of-order packets: {stream.out_of_order_packets}",
                ],
                recommendation="Check packet reordering, load balancing behavior, or jitter buffer stress.",
            )
        )
    return findings


def detect_rtp_high_jitter(streams):
    findings = []
    for stream in streams.values():
        if stream.max_jitter <= 0.04:
            continue
        findings.append(
            Finding(
                type="rtp_high_jitter",
                severity="high",
                confidence=0.90,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="High RTP jitter was detected.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Max jitter: {stream.max_jitter:.3f}s",
                ],
                recommendation="Check latency variation, queueing, wireless instability, or overloaded network paths.",
            )
        )
    return findings


def detect_rtp_timestamp_anomaly(streams):
    findings = []
    for stream in streams.values():
        if stream.timestamp_anomalies == 0:
            continue
        findings.append(
            Finding(
                type="rtp_timestamp_anomaly",
                severity="high",
                confidence=0.90,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="RTP timestamp inconsistency was detected.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Timestamp anomalies: {stream.timestamp_anomalies}",
                ],
                recommendation="Check media source behavior, transcoding issues, or faulty RTP generation.",
            )
        )
    return findings


def detect_rtp_stream_interruption(streams):
    findings = []
    for stream in streams.values():
        if stream.interruptions == 0:
            continue
        findings.append(
            Finding(
                type="rtp_stream_interruption",
                severity="high",
                confidence=0.90,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="RTP stream interruption was detected.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Interruptions: {stream.interruptions}",
                ],
                recommendation="Check endpoint CPU, media pauses, network stalls, or power-saving/network transitions.",
            )
        )
    return findings


def detect_rtp_payload_type_change(streams):
    findings = []
    endpoint_groups = {}
    for stream in streams.values():
        key = (stream.source_ip, stream.destination_ip, stream.source_port, stream.destination_port)
        endpoint_groups.setdefault(key, set()).update(stream.payload_types)
    for (source_ip, destination_ip, _, _), payload_types in endpoint_groups.items():
        if len(payload_types) <= 1:
            continue
        findings.append(
            Finding(
                type="rtp_payload_type_change",
                severity="medium",
                confidence=0.85,
                source_ip=source_ip,
                destination_ip=destination_ip,
                description="RTP payload type changed within the media path.",
                evidence=[f"Payload types: {sorted(payload_types)}"],
                recommendation="Check codec negotiation consistency, transcoding, or unexpected media profile changes.",
            )
        )
    return findings


def detect_rtp_ssrc_change(streams):
    findings = []
    endpoint_groups = {}
    for stream in streams.values():
        key = (stream.source_ip, stream.destination_ip, stream.source_port, stream.destination_port)
        endpoint_groups.setdefault(key, set()).add(stream.ssrc)
    for (source_ip, destination_ip, _, _), ssrcs in endpoint_groups.items():
        if len(ssrcs) <= 1:
            continue
        findings.append(
            Finding(
                type="rtp_ssrc_change",
                severity="medium",
                confidence=0.85,
                source_ip=source_ip,
                destination_ip=destination_ip,
                description="Multiple RTP SSRC values were observed in the same media path.",
                evidence=[f"SSRCs: {sorted(ssrcs)}"],
                recommendation="Check renegotiation, media source resets, hold/resume behavior, or endpoint instability.",
            )
        )
    return findings


def detect_rtp_one_way_audio(streams):
    findings = []
    path_counts = {}
    for stream in streams.values():
        forward = (stream.source_ip, stream.destination_ip)
        reverse = (stream.destination_ip, stream.source_ip)
        path_counts[forward] = path_counts.get(forward, 0) + stream.packet_count
        path_counts.setdefault(reverse, path_counts.get(reverse, 0))
    seen = set()
    for (source_ip, destination_ip), count in path_counts.items():
        reverse_count = path_counts.get((destination_ip, source_ip), 0)
        key = tuple(sorted([source_ip, destination_ip]))
        if key in seen:
            continue
        seen.add(key)
        if count >= 3 and reverse_count == 0:
            findings.append(
                Finding(
                    type="rtp_one_way_audio",
                    severity="high",
                    confidence=0.85,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    description="Probable one-way RTP audio was detected.",
                    evidence=[
                        f"Forward packets: {count}",
                        f"Reverse packets: {reverse_count}",
                    ],
                    recommendation="Check NAT traversal, firewall rules, RTP port ranges, or asymmetric media routing.",
                )
            )
    return findings
