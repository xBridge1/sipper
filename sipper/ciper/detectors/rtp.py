from ciper.findings import Finding
from ciper.voip_quality import (
    LOSS_HIGH_QUALITY_PERCENT,
    LOSS_TARGET_PERCENT,
    jitter_observation,
    packet_loss_observation,
)

# Out-of-order ratio from which reordering is likely to stress jitter buffers.
OUT_OF_ORDER_MEDIUM_PERCENT = 1.0
# Timestamp anomalies below this ratio are typically isolated encoder quirks.
TIMESTAMP_ANOMALY_HIGH_PERCENT = 5.0
# A one-way verdict needs at least this much media in the forward direction.
ONE_WAY_MIN_PACKETS = 10


def detect_rtp_packet_loss(streams, high_loss_threshold=2, high_loss_percent=LOSS_HIGH_QUALITY_PERCENT):
    """Report loss per stream, graded by percentage rather than raw count.

    ``high_loss_threshold`` is the minimum number of lost packets for a high
    severity, so one lost packet in a ten packet sample is not "critical".
    """
    findings = []
    for stream in streams.values():
        if stream.lost_packets == 0:
            continue
        loss_percent = _loss_percent(stream)
        if loss_percent >= high_loss_percent and stream.lost_packets >= high_loss_threshold:
            severity = "high"
        elif loss_percent >= LOSS_TARGET_PERCENT:
            severity = "medium"
        else:
            severity = "low"
        unique_packet_count = getattr(stream, "unique_packet_count", 0) or stream.packet_count
        findings.append(
            Finding(
                type="rtp_packet_loss",
                severity=severity,
                confidence=0.95,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="Perda de pacotes RTP foi detectada.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Lost packets: {stream.lost_packets}",
                    f"Loss: {loss_percent:.2f}%",
                    f"Packets observed: {stream.packet_count}",
                    f"Unique packets: {unique_packet_count}",
                    f"Duplicate packets: {getattr(stream, 'duplicate_packets', 0)}",
                    packet_loss_observation(loss_percent),
                ],
                recommendation="Verifique congestionamento, descartes de pacotes, QoS ou links WAN/LAN instaveis.",
            )
        )
    return findings


def detect_rtp_out_of_order(streams):
    findings = []
    for stream in streams.values():
        if stream.out_of_order_packets == 0:
            continue
        ratio = stream.out_of_order_packets / max(1, stream.packet_count) * 100
        findings.append(
            Finding(
                type="rtp_out_of_order",
                severity="medium" if ratio >= OUT_OF_ORDER_MEDIUM_PERCENT else "low",
                confidence=0.90,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="Pacotes RTP fora de ordem foram detectados.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Out-of-order packets: {stream.out_of_order_packets}",
                    f"Packets observed: {stream.packet_count}",
                ],
                recommendation="Verifique reordenacao de pacotes, balanceamento de carga ou sobrecarga do jitter buffer.",
            )
        )
    return findings


def detect_rtp_high_jitter(streams, threshold=0.04):
    """Compare the smoothed RFC 3550 jitter (not a single-packet peak) to the threshold."""
    findings = []
    for stream in streams.values():
        if stream.max_jitter <= threshold:
            continue
        findings.append(
            Finding(
                type="rtp_high_jitter",
                severity="high" if stream.max_jitter > threshold * 2 else "medium",
                confidence=0.90,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="Jitter RTP alto foi detectado.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Max jitter (RFC 3550): {stream.max_jitter * 1000:.1f} ms",
                    f"Average jitter (RFC 3550): {stream.average_jitter * 1000:.1f} ms",
                    f"Peak transit variation: {getattr(stream, 'max_transit_variation', 0.0) * 1000:.1f} ms",
                    jitter_observation(stream.average_jitter, stream.max_jitter),
                ],
                recommendation="Verifique variacao de latencia, filas, instabilidade de Wi-Fi ou caminhos de rede sobrecarregados.",
            )
        )
    return findings


def detect_rtp_timestamp_anomaly(streams):
    findings = []
    for stream in streams.values():
        if stream.timestamp_anomalies == 0:
            continue
        media_packets = getattr(stream, "media_packet_count", 0) or stream.packet_count
        ratio = stream.timestamp_anomalies / max(1, media_packets - 1) * 100
        findings.append(
            Finding(
                type="rtp_timestamp_anomaly",
                severity="high" if ratio >= TIMESTAMP_ANOMALY_HIGH_PERCENT else "medium",
                confidence=0.90,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="Inconsistencia no timestamp RTP foi detectada.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Timestamp anomalies: {stream.timestamp_anomalies}",
                ],
                recommendation="Verifique o comportamento da fonte de midia, problemas de transcodificacao ou geracao RTP defeituosa.",
            )
        )
    return findings


def detect_rtp_stream_interruption(streams, ignored_stream_keys=()):
    """Gaps explained by silence suppression (CN, marker bit) are not interruptions."""
    ignored = set(ignored_stream_keys)
    findings = []
    for key, stream in streams.items():
        if stream.interruptions == 0 or key in ignored:
            continue
        findings.append(
            Finding(
                type="rtp_stream_interruption",
                severity="high",
                confidence=0.90,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="Interrupcao no stream RTP foi detectada.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Interruptions: {stream.interruptions}",
                    f"Longest gap: {getattr(stream, 'longest_interruption', 0.0):.2f} s",
                ],
                recommendation="Verifique CPU do endpoint, pausas de midia, travamentos de rede ou transicoes de rede/economia de energia.",
            )
        )
    return findings


def detect_rtp_payload_type_change(streams):
    """Only audio codecs count; comfort noise and DTMF events are expected to interleave."""
    findings = []
    for stream in streams.values():
        media_types = getattr(stream, "media_payload_types", stream.payload_types)
        if len(media_types) <= 1:
            continue
        findings.append(
            Finding(
                type="rtp_payload_type_change",
                severity="medium",
                confidence=0.85,
                source_ip=stream.source_ip,
                destination_ip=stream.destination_ip,
                description="O payload type RTP mudou dentro do caminho de midia.",
                evidence=[
                    f"SSRC: {stream.ssrc}",
                    f"Payload types: {sorted(media_types)}",
                ],
                recommendation="Verifique a consistencia da negociacao de codec, transcodificacao ou mudancas inesperadas no perfil de midia.",
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
                description="Varios SSRC RTP foram observados no mesmo caminho de midia.",
                evidence=[f"SSRCs: {ssrcs}"],
                recommendation="Verifique renegociacao, reinicio da fonte de midia, hold/resume ou instabilidade do endpoint.",
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


def detect_rtp_one_way_audio(streams, ignored_stream_keys=(), min_packets=ONE_WAY_MIN_PACKETS):
    """Flag media paths with no return media between the same hosts.

    Return media counts when it flows back between the same IPs, overlaps in
    time and reuses either port: endpoints without symmetric RTP send from a
    different port than they receive on, which is not one-way audio.
    """
    ignored = set(ignored_stream_keys)
    paths = {}
    for key, stream in streams.items():
        direction = (
            stream.source_ip,
            stream.source_port,
            stream.destination_ip,
            stream.destination_port,
        )
        path = paths.setdefault(direction, {"packet_count": 0, "ssrcs": set(), "streams": [], "ignored": False})
        path["packet_count"] += stream.packet_count
        path["ssrcs"].add(stream.ssrc)
        path["streams"].append(stream)
        path["ignored"] = path["ignored"] or key in ignored

    findings = []
    seen = set()
    for direction, path in paths.items():
        source_ip, source_port, destination_ip, destination_port = direction
        key = tuple(sorted(((source_ip, source_port), (destination_ip, destination_port))))
        if key in seen:
            continue
        seen.add(key)
        if path["ignored"] or path["packet_count"] < min_packets:
            continue
        reverse_count = sum(
            other["packet_count"]
            for (other_src, other_sport, other_dst, other_dport), other in paths.items()
            if other_src == destination_ip
            and other_dst == source_ip
            and (other_sport == destination_port or other_dport == source_port)
            and _paths_overlap(path["streams"], other["streams"])
        )
        if reverse_count:
            continue
        findings.append(
            Finding(
                type="rtp_one_way_audio",
                severity="high",
                confidence=0.85,
                source_ip=source_ip,
                destination_ip=destination_ip,
                description="Provavel audio RTP em uma via foi detectado.",
                evidence=[
                    f"Forward packets: {path['packet_count']}",
                    f"Reverse packets: {reverse_count}",
                    f"Source port: {source_port}",
                    f"Destination port: {destination_port}",
                    *[f"SSRC: {ssrc}" for ssrc in sorted(path["ssrcs"])],
                ],
                recommendation="Verifique NAT, regras de firewall, faixas de portas RTP ou roteamento assimetrico da midia.",
            )
        )
    return findings


def _paths_overlap(first_streams, second_streams, tolerance=2.0):
    for first in first_streams:
        for second in second_streams:
            if _stream_time_gap(first, second) <= tolerance:
                return True
    return False


def _loss_percent(stream):
    unique_packet_count = getattr(stream, "unique_packet_count", 0) or stream.packet_count
    observed = getattr(stream, "loss_observed_packet_count", 0) or unique_packet_count
    expected = observed + stream.lost_packets
    return stream.lost_packets / expected * 100 if expected else 0.0
