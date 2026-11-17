from ciper.findings import Finding

from ciper.packets import TCP_RST, ensure_decoded


TCP_RETRANSMISSION_MEDIUM_PERCENT = 1.0
TCP_RETRANSMISSION_HIGH_PERCENT = 3.0


def detect_syn_failures(flows):
    findings = []

    for flow in flows.values():
        if flow.syn and not flow.syn_ack and not flow.established and not flow.rst:
            finding = Finding(
                type="tcp_syn_failure",
                severity="high",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                recommendation=(
                    "Verifique se o host de destino e alcancavel, se a porta esta escutando ou se um firewall esta bloqueando a conexao."
                ),
                description=(
                    "SYN TCP foi detectado, mas nenhum SYN/ACK foi observado."
                ),
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    "SYN observed: yes",
                    "SYN/ACK observed: no",
                    f"Packets in flow: {flow.packet_count}",
                ],
            )

            findings.append(finding)

    return findings

def detect_slow_handshakes(flows):
    findings = []

    for flow in flows.values():
        handshake_time = flow.handshake_time

        if handshake_time is None:
            continue

        if handshake_time > 0.5:
            severity = "high"
        elif handshake_time > 0.1:
            severity = "medium"
        else:
            continue

        findings.append(
            Finding(
                type="tcp_slow_handshake",
                severity=severity,
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description=(
                    "O tempo de resposta do handshake TCP foi excepcionalmente alto."
                ),
                recommendation=(
                    "Verifique latencia da rede, tempo de resposta do servidor, firewalls, proxies ou endpoints sobrecarregados."
                ),
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Handshake time: {handshake_time:.3f}s",
                    "SYN observed: yes",
                    "SYN/ACK observed: yes",
                ],
            )
        )

    return findings


def detect_tcp_handshake_incomplete(flows):
    findings = []

    for flow in flows.values():
        if not flow.syn:
            continue

        if not flow.syn_ack:
            continue

        if flow.ack:
            continue

        findings.append(
            Finding(
                type="tcp_handshake_incomplete",
                severity="medium",
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="O handshake TCP comecou, mas nao foi concluido.",
                recommendation=(
                    "Verifique se o cliente completou o handshake, se pacotes foram descartados ou se um equipamento intermediario interrompeu a conexao."
                ),
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    "SYN observed: yes",
                    "SYN/ACK observed: yes",
                    "ACK observed: no",
                ],
            )
        )

    return findings

from ciper.tcp_tracker import track_tcp_packets


def detect_tcp_retransmissions(flows):
    findings = []

    for flow in flows.values():
        events = track_tcp_packets(flow.packets, flow)

        retransmissions = [
            event
            for event in events
            if event.event_type == "retransmission"
        ]

        if not retransmissions:
            continue

        first = retransmissions[0]
        retransmission_count = len(retransmissions)

        # Grade by rate, not count: a handful of retransmissions in a long
        # transfer is normal TCP behaviour.
        retransmission_rate = retransmission_count / max(1, len(flow.packets)) * 100
        if retransmission_count >= 2 and retransmission_rate >= TCP_RETRANSMISSION_HIGH_PERCENT:
            severity = "high"
            confidence = 0.95
        elif retransmission_rate >= TCP_RETRANSMISSION_MEDIUM_PERCENT:
            severity = "medium"
            confidence = 0.90
        else:
            severity = "low"
            confidence = 0.85

        findings.append(
            Finding(
                type="tcp_retransmission",
                severity=severity,
                confidence=confidence,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="Retransmissao TCP detectada.",
                recommendation=(
                    "Verifique perda de pacotes, congestionamento, links instaveis ou problemas entre os endpoints."
                ),
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Sequence: {first.sequence}",
                    f"Payload: {first.payload_length} bytes",
                    f"Direction: {first.direction}",
                    f"Retransmissions: {retransmission_count}",
                    f"Packets in flow: {len(flow.packets)}",
                    f"Retransmission rate: {retransmission_rate:.2f}%",
                ],
            )
        )

    return findings


def detect_tcp_handshake_reset(flows):
    findings = []

    for flow in flows.values():
        if not flow.syn or flow.established or not flow.rst:
            continue

        reset_packet = None

        for packet in flow.packets:
            packet = ensure_decoded(packet)
            if packet.transport == "TCP" and packet.tcp_flags & TCP_RST:
                reset_packet = packet
                break

        if reset_packet is None:
            continue

        source_ip, destination_ip = reset_packet.src, reset_packet.dst

        findings.append(
            Finding(
                type="tcp_handshake_reset",
                severity="high",
                confidence=0.95,
                source_ip=source_ip,
                destination_ip=destination_ip,
                description="O estabelecimento da conexao TCP foi resetado antes de completar.",
                evidence=[
                    f"Source: {source_ip}:{reset_packet.sport}",
                    f"Destination: {destination_ip}:{reset_packet.dport}",
                    "RST observed during handshake: yes",
                ],
                recommendation=(
                    "Verifique se a porta de destino esta fechada, se um firewall rejeitou a conexao ou se um equipamento intermediario resetou a sessao."
                ),
            )
        )

    return findings

def detect_tcp_resets(flows):
    findings = []

    for flow in flows.values():
        if not flow.rst:
            continue

        reset_packet = None

        for packet in flow.packets:
            packet = ensure_decoded(packet)
            if packet.transport == "TCP" and packet.tcp_flags & TCP_RST:
                reset_packet = packet
                break

        if reset_packet is None:
            continue

        source_ip, destination_ip = reset_packet.src, reset_packet.dst

        findings.append(
            Finding(
                type="tcp_reset",
                severity="high",
                confidence=0.95,
                source_ip=source_ip,
                destination_ip=destination_ip,
                description="A conexao TCP foi resetada inesperadamente.",
                evidence=[
                    f"Source: {source_ip}:{reset_packet.sport}",
                    f"Destination: {destination_ip}:{reset_packet.dport}",
                    "RST observed: yes",
                ],
                recommendation=(
                    "Verifique se a aplicacao rejeitou a conexao, se um firewall encerrou a sessao ou se o servico caiu."
                ),
            )
        )

    return findings
