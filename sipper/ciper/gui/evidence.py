from ciper.voip_quality import jitter_observation, packet_loss_observation


def build_finding_evidence_context(engine_result, finding):
    if engine_result is None or finding is None:
        return []

    source = finding.get("source", "")
    destination = finding.get("destination", "")
    finding_type = finding.get("type", "")
    call_id = _extract_call_id(finding.get("evidence", []))
    lines = []

    flow = engine_result.get("sip_flows", {}).get(call_id) if call_id else None
    if flow is not None:
        lines.append("Sinalizacao SIP correlacionada:")
        for message in flow.messages:
            kind = message.method if message.is_request else f"{message.status_code} {message.reason_phrase or ''}".strip()
            lines.append(
                f"SIP {message.packet_time:.3f}: {kind} | "
                f"{message.source_ip}:{message.source_port} -> "
                f"{message.destination_ip}:{message.destination_port}"
            )
            for media in message.sdp_media:
                lines.append(
                    f"  SDP {media.media_type}: {media.connection_address or message.source_ip}:{media.port} "
                    f"{media.protocol} {media.direction}"
                )

    related_streams = _related_rtp_streams(engine_result, finding)
    if finding_type.startswith("rtp_") or "rtp" in finding_type or flow is not None:
        if related_streams:
            if finding_type == "rtp_high_jitter":
                lines.extend(_high_jitter_context(related_streams))
                return lines

            lines.append("Pacotes RTP correlacionados:")
            for stream in related_streams:
                lines.append(
                    f"RTP SSRC {stream.ssrc}: {stream.source_ip}:{stream.source_port} -> "
                    f"{stream.destination_ip}:{stream.destination_port} | "
                    f"observados={stream.packet_count}, perda={stream.lost_packets}, "
                    f"fora de ordem={stream.out_of_order_packets}"
                )
                lines.extend(_rtp_packet_samples(stream))
                expected_packets = stream.packet_count + stream.lost_packets
                loss_percent = stream.lost_packets / expected_packets * 100 if expected_packets else 0.0
                lines.append(f"  {packet_loss_observation(loss_percent)}")
                lines.append(f"  {jitter_observation(stream.average_jitter, stream.max_jitter)}")
        elif finding_type in {"sip_call_established_without_rtp", "sip_call_one_way_audio"}:
            lines.append("Nenhum pacote RTP correspondente foi encontrado entre os endpoints negociados.")

    if "fragment" in finding_type:
        groups = _related_fragment_groups(engine_result, source, destination)
        if groups:
            lines.append("Conjuntos de fragmentos correlacionados:")
            for group in groups:
                ranges = ", ".join(f"{start}-{end}" for start, end in sorted(group.fragments))
                ports = (
                    f":{group.source_port}->{group.destination_port}"
                    if group.source_port is not None
                    else ""
                )
                lines.append(
                    f"IP ID {group.identification}, protocolo {group.protocol}, "
                    f"{group.source_ip}{ports} -> {group.destination_ip} | ranges: {ranges}"
                )
                if group.is_incomplete:
                    lines.append("  Possivel culpado: caminho de rede, firewall ou ponto de captura que perdeu fragmentos.")
                elif group.has_overlap:
                    lines.append("  Possivel culpado: origem ou middlebox que gerou fragmentos sobrepostos.")
                else:
                    lines.append(f"  Possivel culpado: {group.source_ip}, que originou o conjunto fragmentado.")
        else:
            lines.append("Nao foi possivel associar um conjunto IP completo; valide MTU e o ponto de captura.")

    return lines


def _extract_call_id(evidence):
    for item in evidence:
        if item.startswith("Call-ID: "):
            return item.removeprefix("Call-ID: ").strip()
    return None


def _related_rtp_streams(engine_result, finding):
    source = finding.get("source", "")
    destination = finding.get("destination", "")
    finding_type = finding.get("type", "")
    ssrc = _extract_ssrc(finding.get("evidence", []))
    directional = finding_type.startswith("rtp_")

    return [
        stream
        for stream in engine_result.get("rtp_streams", {}).values()
        if (stream.source_ip, stream.destination_ip) == (source, destination)
        or (
            not directional
            and {stream.source_ip, stream.destination_ip} == {source, destination}
        )
        if ssrc is None or stream.ssrc == ssrc
    ]


def _extract_ssrc(evidence):
    for item in evidence:
        if item.startswith("SSRC: "):
            try:
                return int(item.removeprefix("SSRC: ").strip())
            except ValueError:
                return None
    return None


def _high_jitter_context(streams):
    stream = max(streams, key=lambda item: item.max_jitter)
    peak = _worst_jitter_sample(stream)
    jitter_ms = stream.max_jitter * 1000
    multiple = jitter_ms / 30 if jitter_ms else 0
    lines = [
        f"IMPACTO: jitter maximo de {jitter_ms:.1f} ms, {multiple:.0f}x acima da referencia de 30 ms.",
        "POR QUE E RUIM: o buffer de jitter tende a esgotar ou aumentar o atraso, causando audio robotico, cortes ou silencio.",
        (
            f"FLUXO AFETADO: SSRC {stream.ssrc} | {stream.source_ip}:{stream.source_port} -> "
            f"{stream.destination_ip}:{stream.destination_port} | {stream.packet_count} pacotes."
        ),
    ]

    if peak is not None:
        previous, current, variation_ms = peak
        lines.append(
            f"PIOR PICO: entre seq {previous.sequence} ({previous.packet_time:.3f}) e "
            f"seq {current.sequence} ({current.packet_time:.3f}); variacao de {variation_ms:.1f} ms."
        )

    lines.append(f"PERDA NO FLUXO: {stream.lost_packets} pacote(s) detectado(s).")
    return lines


def _worst_jitter_sample(stream):
    if len(stream.packets) < 3:
        return None

    previous_delta = None
    worst = None

    for index in range(1, len(stream.packets)):
        previous = stream.packets[index - 1]
        current = stream.packets[index]
        arrival_delta = current.packet_time - previous.packet_time
        if previous_delta is not None:
            variation = abs(arrival_delta - previous_delta)
            if worst is None or variation > worst[2]:
                worst = (previous, current, variation)
        previous_delta = arrival_delta

    return worst


def _rtp_packet_samples(stream):
    packets = stream.packets
    if not packets:
        return []

    samples = packets[:2]
    if len(packets) > 2:
        samples.append(packets[-1])

    return [
        f"  pacote {packet.packet_time:.3f}: seq={packet.sequence}, ts={packet.timestamp}, "
        f"PT={packet.payload_type}, bytes={packet.payload_length}"
        for packet in samples
    ]


def _related_fragment_groups(engine_result, source, destination):
    endpoints = {source, destination}
    return [
        group
        for group in engine_result.get("fragment_groups", {}).values()
        if {group.source_ip, group.destination_ip} == endpoints
    ]
