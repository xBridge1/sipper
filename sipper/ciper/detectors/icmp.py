from ciper.findings import Finding
from ciper.packets import ensure_decoded


UNREACHABLE_CODE_DETAILS = {
    0: (
        "icmp_network_unreachable",
        "ICMP Network Unreachable foi observado.",
        "Verifique se a rede de destino e alcancavel e se o roteamento esta configurado corretamente.",
    ),
    1: (
        "icmp_host_unreachable",
        "ICMP Host Unreachable foi observado.",
        "Verifique se o host de destino esta online e se existe rota valida ate ele.",
    ),
    3: (
        "icmp_destination_unreachable",
        "ICMP Port Unreachable foi observado.",
        "Verifique se o servico de destino esta escutando na porta e se algum filtro esta bloqueando o trafego.",
    ),
    4: (
        "icmp_fragmentation_needed",
        "ICMP Fragmentation Needed foi observado.",
        "Verifique o Path MTU Discovery, as configuracoes de MTU e equipamentos que descartam trafego fragmentado.",
    ),
    13: (
        "icmp_admin_prohibited",
        "ICMP Communication Administratively Prohibited foi observado.",
        "Verifique regras de firewall e politicas de seguranca que bloqueiam o caminho.",
    ),
}


def detect_icmp_no_response(flows):
    findings = []

    for flow in flows.values():
        if flow.echo_requests == 0:
            continue

        if flow.echo_replies != 0:
            continue

        findings.append(
            Finding(
                type="icmp_no_response",
                severity="medium",
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="ICMP Echo Request foi observado sem resposta.",
                evidence=[
                    f"Source: {flow.source_ip}",
                    f"Destination: {flow.destination_ip}",
                    f"Echo requests: {flow.echo_requests}",
                    f"Echo replies: {flow.echo_replies}",
                ],
                recommendation=(
                    "Verifique se o host de destino e alcancavel, se o ICMP esta bloqueado por firewall ou se o destino ignora ping."
                ),
            )
        )

    return findings


def detect_icmp_unreachable(flows):
    findings = []

    for flow in flows.values():
        if flow.unreachable_messages == 0:
            continue

        codes = sorted(set(flow.unreachable_codes)) or [None]

        for code in codes:
            packet = _first_icmp_packet(flow, 3, code)
            source_ip = packet.src if packet is not None else flow.source_ip
            destination_ip = packet.dst if packet is not None else flow.destination_ip
            if code is not None:
                finding_type, description, recommendation = UNREACHABLE_CODE_DETAILS.get(
                    code,
                    (
                        "icmp_destination_unreachable",
                        "ICMP Destination Unreachable foi observado.",
                        "Verifique se o host, a rede ou o servico de destino sao alcancaveis e se um firewall esta bloqueando o trafego.",
                    ),
                )
            else:
                finding_type = "icmp_destination_unreachable"
                description = "ICMP Destination Unreachable foi observado."
                recommendation = (
                    "Verifique se o host, a rede ou o servico de destino "
                    "sao alcancaveis e se um firewall esta bloqueando o trafego."
                )

            evidence = [
                f"Source: {source_ip}",
                f"Destination: {destination_ip}",
                f"Unreachable messages: {flow.unreachable_messages}",
            ]

            if code is not None:
                evidence.append(f"ICMP code: {code}")

            findings.append(
                Finding(
                    type=finding_type,
                    severity="high",
                    confidence=0.95,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    description=description,
                    evidence=evidence,
                    recommendation=recommendation,
                )
            )

    return findings


def detect_icmp_time_exceeded(flows):
    findings = []

    for flow in flows.values():
        if flow.time_exceeded_messages == 0:
            continue

        packet = _first_icmp_packet(flow, 11)
        source_ip = packet.src if packet is not None else flow.source_ip
        destination_ip = packet.dst if packet is not None else flow.destination_ip

        findings.append(
            Finding(
                type="icmp_time_exceeded",
                severity="high",
                confidence=0.95,
                source_ip=source_ip,
                destination_ip=destination_ip,
                description="ICMP Time Exceeded foi observado.",
                evidence=[
                    f"Source: {source_ip}",
                    f"Destination: {destination_ip}",
                    f"Time Exceeded messages: {flow.time_exceeded_messages}",
                ],
                recommendation=(
                    "Verifique o roteamento, a configuracao de TTL ou possiveis loops de roteamento entre os endpoints."
                ),
            )
        )

    return findings


def detect_icmp_redirect(flows):
    findings = []

    for flow in flows.values():
        if flow.redirect_messages == 0:
            continue

        packet = _first_icmp_packet(flow, 5)
        source_ip = packet.src if packet is not None else flow.source_ip
        destination_ip = packet.dst if packet is not None else flow.destination_ip

        findings.append(
            Finding(
                type="icmp_redirect",
                severity="medium",
                confidence=0.90,
                source_ip=source_ip,
                destination_ip=destination_ip,
                description="ICMP Redirect foi observado.",
                evidence=[
                    f"Source: {source_ip}",
                    f"Destination: {destination_ip}",
                    f"Redirect messages: {flow.redirect_messages}",
                ],
                recommendation=(
                    "Verifique o desenho de roteamento, a escolha de gateway e se os hosts usam o next-hop esperado."
                ),
            )
        )

    return findings


def detect_icmp_parameter_problem(flows):
    findings = []

    for flow in flows.values():
        if flow.parameter_problem_messages == 0:
            continue

        packet = _first_icmp_packet(flow, 12)
        source_ip = packet.src if packet is not None else flow.source_ip
        destination_ip = packet.dst if packet is not None else flow.destination_ip

        findings.append(
            Finding(
                type="icmp_parameter_problem",
                severity="high",
                confidence=0.95,
                source_ip=source_ip,
                destination_ip=destination_ip,
                description="ICMP Parameter Problem foi observado.",
                evidence=[
                    f"Source: {source_ip}",
                    f"Destination: {destination_ip}",
                    f"Parameter problem messages: {flow.parameter_problem_messages}",
                ],
                recommendation=(
                    "Verifique pacotes malformados, problemas de implementacao do protocolo ou equipamentos alterando cabecalhos incorretamente."
                ),
            )
        )

    return findings


def _first_icmp_packet(flow, icmp_type, code=None):
    for packet in flow.packets:
        packet = ensure_decoded(packet)
        if (
            packet.ip_version == 4
            and packet.transport == "ICMP"
            and packet.icmp_type == icmp_type
            and (code is None or packet.icmp_code == code)
        ):
            return packet
    return None
