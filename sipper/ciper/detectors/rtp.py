from ciper.findings import Finding
from ciper.voip_quality import jitter_observation, packet_loss_observation


def detect_rtp_packet_loss(streams, high_loss_threshold=2):
    findings = []
    for stream in streams.values():
        if stream.lost_packets == 0:
            continue
        unique_packet_count = getattr(stream, "unique_packet_count", 0) or stream.packet_count
        loss_observed_packet_count = (
            getattr(stream, "loss_observed_packet_count", 0)
            or unique_packet_count
        )
        expected_packets = loss_observed_packet_count + stream.lost_packets
        loss_percent = stream.lost_packets / expected_packets * 100 if expected_packets else 0.0
        findings.append(
            Finding(
                type="rtp_packet_loss",
                severity="high" if stream.lost_packets >= high_loss_threshold else "medium",
                confidence=0.95,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="RTP packet loss was detected.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Lost packets: {stream.lost_packets}",
                    f"Packets observed: {stream.packet_count}",
                    f"Unique packets: {unique_packet_count}",
                    f"Duplicate packets: {getattr(stream, 'duplicate_packets', 0)}",
                    packet_loss_observation(loss_percent),
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


def detect_rtp_high_jitter(streams, threshold=0.04):
    findings = []
    for stream in streams.values():
        if stream.max_jitter <= threshold:
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
                    jitter_observation(stream.average_jitter, stream.max_jitter),
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
    for stream in streams.values():
        if len(stream.payload_types) <= 1:
            continue
        findings.append(
            Finding(
                type="rtp_payload_type_change",
                severity="medium",
                confidence=0.85,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="RTP payload type changed within the media path.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Payload types: {sorted(stream.payload_types)}",
                ],
                recommendation="Check codec negotiation consistency, transcoding, or unexpected media profile changes.",
            )
        )
    return findings


def detect_rtp_ssrc_change(streams):
    findings = []
    endpoint_groups = {}
    for stream in streams.values():
        key = (stream.source_ip, stream.destination_ip, stream.source_port, stream.destination_port)
        endpoint_groups.setdefault(key, []).append(stream)
    for (source_ip, destination_ip, _, _), path_streams in endpoint_groups.items():
        related_streams = set()
        for index, first_stream in enumerate(path_streams):
            for second_stream in path_streams[index + 1:]:
                if _stream_time_gap(first_stream, second_stream) <= 1.0:
                    related_streams.add(first_stream.ssrc)
                    related_streams.add(second_stream.ssrc)
        ssrcs = sorted(related_streams)
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
                evidence=[f"SSRCs: {ssrcs}"],
                recommendation="Check renegotiation, media source resets, hold/resume behavior, or endpoint instability.",
            )
        )
    return findings


def _stream_time_gap(first_stream, second_stream):
    if (
        first_stream.first_timestamp is None
        or first_stream.last_timestamp is None
        or second_stream.first_timestamp is None
        or second_stream.last_timestamp is None
    ):
        return 0.0
    if first_stream.last_timestamp < second_stream.first_timestamp:
        return second_stream.first_timestamp - first_stream.last_timestamp
    if second_stream.last_timestamp < first_stream.first_timestamp:
        return first_stream.first_timestamp - second_stream.last_timestamp
    return 0.0


def detect_rtp_one_way_audio(streams):
    findings = []
    paths = {}
    for stream in streams.values():
        direction = (
            stream.source_ip,
            stream.source_port,
            stream.destination_ip,
            stream.destination_port,
        )
        path = paths.setdefault(direction, {"packet_count": 0, "ssrcs": set()})
        path["packet_count"] += stream.packet_count
        path["ssrcs"].add(stream.ssrc)

    seen = set()
    for direction, path in paths.items():
        source_ip, source_port, destination_ip, destination_port = direction
        reverse = (destination_ip, destination_port, source_ip, source_port)
        reverse_count = paths.get(reverse, {}).get("packet_count", 0)
        key = tuple(sorted(((source_ip, source_port), (destination_ip, destination_port))))
        if key in seen:
            continue
        seen.add(key)
        count = path["packet_count"]
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
                        f"Source port: {source_port}",
                        f"Destination port: {destination_port}",
                        *[f"SSRC: {ssrc}" for ssrc in sorted(path["ssrcs"])],
                    ],
                    recommendation="Check NAT traversal, firewall rules, RTP port ranges, or asymmetric media routing.",
                )
            )
    return findings
