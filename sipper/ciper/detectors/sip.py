import ipaddress

from ciper.detectors.sip_headers import header_display_name
from ciper.findings import Finding
from ciper.q850 import message_q850
from ciper.sip_status import sip_status_info
from ciper.sip import (
    SIP_FRAGMENTATION_RISK_HEADER_BYTES,
    SIP_LARGE_HEADER_LINE_BYTES,
    SIP_UDP_FRAGMENTATION_RISK_BYTES,
    get_sip_method_responses,
    get_successful_invite_responses,
    get_terminal_sip_method_errors,
    has_matching_sip_ack,
)


# RFC 3261 Timer B: a client gives up on an INVITE after 64*T1 = 32 s.
SIP_TIMER_B_SECONDS = 32.0


def detect_sip_invite_no_response(flows, capture_end=None):
    findings = []

    for flow in flows.values():
        if flow.invites == 0:
            continue

        invite_responses = get_sip_method_responses(flow, "INVITE", allow_unspecified=True)
        if invite_responses:
            continue

        invites = [message for message in flow.messages if message.is_request and message.method == "INVITE"]
        first_invite = invites[0]
        copies = len(invites)
        waited = (capture_end - first_invite.packet_time) if capture_end is not None else None
        # Over UDP the client resends at 0.5, 1, 2, 4... s: four or more copies
        # prove at least ~7 s of silence even in a short capture.
        truncated = (
            waited is not None
            and waited < SIP_TIMER_B_SECONDS
            and not (first_invite.transport == "UDP" and copies >= 4)
        )
        evidence = [
            *_flow_evidence(flow),
            f"Source: {flow.source_ip}",
            f"Destination: {flow.destination_ip}",
            f"INVITEs: {flow.invites}",
            f"INVITE copies sent: {copies}",
            "INVITE responses: 0",
        ]
        if waited is not None:
            evidence.append(f"Capture after INVITE: {waited:.1f} s")
        if truncated:
            description = (
                f"INVITE SIP sem resposta, mas a captura terminou {waited:.1f} s depois dele, antes do timeout "
                "de 32 s (Timer B). Pode ser apenas o fim da captura: confirme com uma captura mais longa."
            )
            severity, confidence = "medium", 0.55
        else:
            description = "INVITE SIP foi observado sem nenhuma resposta SIP."
            if copies > 1:
                description += f" O chamador retransmitiu o INVITE {copies - 1} vez(es) sem retorno."
            severity, confidence = "high", 0.95

        findings.append(
            Finding(
                type="sip_invite_no_response",
                severity=severity,
                confidence=confidence,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description=description,
                evidence=evidence,
                recommendation=(
                    "Verifique se o servidor SIP ou peer e alcancavel, se a sinalizacao esta bloqueada ou se o destino nao esta processando a chamada."
                ),
            )
        )

    return findings


def detect_sip_error_responses(flows):
    findings = []

    for flow in flows.values():
        if flow.invites == 0:
            continue

        error_messages = get_terminal_sip_method_errors(flow, "INVITE", allow_unspecified=True)

        if not error_messages:
            continue

        first_error = error_messages[0]
        status = f"{first_error.status_code} {first_error.reason_phrase or ''}".strip()
        info = sip_status_info(first_error.status_code)
        invite = next(
            (
                message
                for message in flow.messages
                if message.is_request and message.method == "INVITE"
                and (first_error.cseq_number is None or message.cseq_number == first_error.cseq_number)
            ),
            None,
        )
        # The response travels back to the requester: its source is the side
        # that refused the call.
        responder_ip = first_error.source_ip
        requester_ip = first_error.destination_ip
        if info is None:
            severity = "high"
            culprit = responder_ip
            description = f"O estabelecimento da chamada SIP recebeu a resposta de erro {status}."
            recommendation = (
                "Verifique roteamento SIP, autenticacao, dial plan ou disponibilidade do destino conforme o codigo de status retornado."
            )
            blame = "responder"
        else:
            blame = info.blame
            severity = "low" if blame == "user" else "high"
            culprit = requester_ip if blame == "requester" else responder_ip
            description = (
                f"A chamada foi recusada por {responder_ip} com {status} ({info.meaning}). {info.explanation}"
            )
            recommendation = info.action
        cause, cause_text = message_q850(first_error)
        if cause is not None:
            # The Q.850 cause is more specific than the SIP class: a 503 with
            # cause 17 is a busy user, a 480 with cause 18 a silent terminal.
            blame = cause.blame
            severity = "low" if blame == "user" else "high"
            culprit = requester_ip if blame == "requester" else responder_ip
            description += f" Causa Q.850 {cause.cause}: {cause.meaning}."
        evidence = [
            *_flow_evidence(flow),
            f"Status: {status}",
            f"Rejected by: {responder_ip}",
            f"Requested by: {requester_ip}",
            f"INVITEs: {flow.invites}",
            f"INVITE error responses: {len(error_messages)}",
        ]
        if info is not None:
            evidence.append(f"Meaning: {info.meaning}")
            if info.freeswitch and cause is None:
                evidence.append(f"FreeSWITCH hangup cause: {info.freeswitch}")
        if cause is not None:
            evidence.append(f"Q.850 cause: {cause.cause} - {cause.meaning}" + (f" ({cause_text})" if cause_text else ""))
            if cause.freeswitch:
                evidence.append(f"FreeSWITCH hangup cause: {cause.freeswitch}")
        evidence.append(f"Blame: {blame}")
        for header in ("reason", "warning", "unsupported", "x-reason"):
            value = first_error.headers.get(header)
            if value:
                evidence.append(f"Response {header_display_name(header)}: {value[:200]}")
        if invite is not None and invite.request_uri:
            evidence.append(f"Request-URI: {invite.request_uri}")

        findings.append(
            Finding(
                type="sip_error_response",
                severity=severity,
                confidence=0.95,
                source_ip=first_error.source_ip,
                destination_ip=first_error.destination_ip,
                description=description,
                evidence=evidence,
                recommendation=recommendation,
                culprit_ip=culprit,
            )
        )

    return findings


def detect_sip_ok_without_ack(flows):
    findings = []

    for flow in flows.values():
        if flow.invites == 0:
            continue

        success_responses = get_successful_invite_responses(flow)
        if not success_responses:
            continue

        missing_ack = next(
            (response for response in success_responses if not has_matching_sip_ack(flow, response)),
            None,
        )
        if missing_ack is None:
            continue

        findings.append(
            Finding(
                type="sip_ok_without_ack",
                severity="high",
                confidence=0.95,
                source_ip=missing_ack.source_ip,
                destination_ip=missing_ack.destination_ip,
                description="200 OK SIP foi observado sem o ACK correspondente.",
                evidence=[
                    *_flow_evidence(flow),
                    f"INVITEs: {flow.invites}",
                    f"INVITE 2xx responses: {len(success_responses)}",
                    f"ACKs: {flow.acknowledgements}",
                    f"Unacknowledged CSeq: {missing_ack.cseq_number or 'unknown'}",
                ],
                recommendation=(
                    "Verifique se o chamador enviou o ACK, se pacotes de sinalizacao foram perdidos ou se NAT/firewall esta quebrando o dialogo."
                ),
            )
        )

    return findings


def detect_sip_call_established(flows):
    findings = []

    for flow in flows.values():
        if flow.invites == 0:
            continue

        success_responses = get_successful_invite_responses(flow)
        if not any(has_matching_sip_ack(flow, response) for response in success_responses):
            continue

        findings.append(
            Finding(
                type="sip_call_established",
                severity="low",
                confidence=0.98,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="O estabelecimento da chamada SIP foi concluido com sucesso.",
                evidence=[
                    *_flow_evidence(flow),
                    f"INVITEs: {flow.invites}",
                    f"Provisional responses: {flow.provisional_responses}",
                    f"INVITE 2xx responses: {len(success_responses)}",
                    f"ACKs: {flow.acknowledgements}",
                ],
                recommendation=(
                    "A sinalizacao parece completa. Se ainda houver problema de voz, o proximo passo e inspecionar qualidade e direcao do RTP."
                ),
            )
        )

    return findings


NORMAL_HANGUP_CAUSES = {16, 17, 19, 21, 31}


def detect_sip_abnormal_hangup(flows):
    """A BYE carrying a non-normal Q.850 cause: the call dropped, nobody hung up."""
    findings = []
    for flow in flows.values():
        bye = next(
            (message for message in flow.messages if message.is_request and message.method == "BYE"),
            None,
        )
        if bye is None:
            continue
        cause, text = message_q850(bye)
        if cause is None or cause.cause in NORMAL_HANGUP_CAUSES:
            continue
        answered = next(
            (
                message.packet_time
                for message in flow.messages
                if not message.is_request and message.status_code and 200 <= message.status_code < 300
                and message.cseq_method in {None, "INVITE"}
            ),
            None,
        )
        evidence = [
            *_flow_evidence(flow),
            f"Hangup by: {bye.source_ip}",
            f"Q.850 cause: {cause.cause} - {cause.meaning}" + (f" ({text})" if text else ""),
            f"Blame: {cause.blame}",
        ]
        if cause.freeswitch:
            evidence.append(f"FreeSWITCH hangup cause: {cause.freeswitch}")
        if answered is not None:
            evidence.append(f"Call duration before BYE: {bye.packet_time - answered:.1f} s")
        findings.append(
            Finding(
                type="sip_abnormal_hangup",
                severity="high" if cause.blame in {"downstream", "responder"} else "medium",
                confidence=0.90,
                source_ip=bye.source_ip,
                destination_ip=bye.destination_ip,
                description=(
                    f"A chamada foi encerrada por {bye.source_ip} com causa anormal Q.850 {cause.cause} "
                    f"({cause.meaning}). Ninguem desligou normalmente: o lado que enviou o BYE derrubou a chamada "
                    "por falha propria ou da rede atras dele."
                ),
                evidence=evidence,
                recommendation=(
                    f"Verifique os logs de {bye.source_ip} no horario do BYE. No FreeSWITCH, procure o hangup cause "
                    f"{cause.freeswitch or cause.cause} no CDR/fs_cli; causas como 102 e 38 indicam timeout ou rede, "
                    "e quedas logo apos ~30 s costumam ser ACK/re-INVITE perdidos por NAT."
                ),
                culprit_ip=bye.source_ip,
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
                description="A tentativa de chamada SIP foi cancelada antes de completar.",
                evidence=[
                    *_flow_evidence(flow),
                    f"INVITEs: {flow.invites}",
                    f"CANCELs: {flow.cancels}",
                ],
                recommendation=(
                    "Verifique se o chamador desistiu intencionalmente ou se atrasos no estabelecimento causaram o cancelamento."
                ),
            )
        )

    return findings


def detect_sip_call_terminated(flows):
    findings = []

    for flow in flows.values():
        if flow.byes == 0:
            continue

        success_responses = get_successful_invite_responses(flow)
        if not any(has_matching_sip_ack(flow, response) for response in success_responses):
            continue

        findings.append(
            Finding(
                type="sip_call_terminated",
                severity="low",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="A chamada SIP foi estabelecida e depois encerrada com BYE.",
                evidence=[
                    *_flow_evidence(flow),
                    f"INVITE 2xx responses: {len(success_responses)}",
                    f"ACKs: {flow.acknowledgements}",
                    f"BYEs: {flow.byes}",
                ],
                recommendation=(
                    "A sinalizacao mostra encerramento normal. Se usuarios relataram queda inesperada, correlacione com o tempo do RTP e o comportamento dos endpoints."
                ),
            )
        )

    return findings


def detect_sip_large_headers(flows):
    findings = []

    for flow in flows.values():
        if flow.large_header_messages == 0:
            continue

        message = _first_affected_message(
            flow,
            lambda item: item.max_header_length > SIP_LARGE_HEADER_LINE_BYTES
            or item.header_size > SIP_FRAGMENTATION_RISK_HEADER_BYTES,
        )

        findings.append(
            Finding(
                type="sip_large_header",
                severity="medium",
                confidence=0.90,
                source_ip=message.source_ip if message else flow.source_ip,
                destination_ip=message.destination_ip if message else flow.destination_ip,
                description="A mensagem SIP contem headers excepcionalmente grandes.",
                evidence=[
                    *_flow_evidence(flow),
                    f"Messages with large headers: {flow.large_header_messages}",
                    f"Header fragmentation risks: {flow.header_fragmentation_risk_messages}",
                ],
                recommendation=(
                    "Verifique se os headers SIP estao grandes por excesso de roteamento, identidade ou contato, pressionando o limite de MTU."
                ),
            )
        )

    return findings


def detect_sip_header_validation_errors(flows):
    findings = []

    for flow in flows.values():
        if flow.invalid_header_messages > 0:
            message = _first_affected_message(
                flow,
                lambda item: item.invalid_header_count > 0,
            )
            findings.append(
                Finding(
                    type="sip_invalid_header",
                    severity="medium",
                    confidence=0.95,
                    source_ip=message.source_ip if message else flow.source_ip,
                    destination_ip=message.destination_ip if message else flow.destination_ip,
                    description="Mensagens SIP contem linhas de header malformadas.",
                    evidence=[
                        *_flow_evidence(flow),
                        f"Messages with invalid headers: {flow.invalid_header_messages}",
                    ],
                    recommendation=(
                        "Verifique a geracao das mensagens SIP e qualquer SBC, proxy ou equipamento de inspecao que possa reescrever headers."
                    ),
                )
            )

        if flow.content_length_mismatches > 0:
            message = _first_affected_message(
                flow,
                lambda item: item.content_length_mismatch,
            )
            findings.append(
                Finding(
                    type="sip_content_length_mismatch",
                    severity="high",
                    confidence=0.95,
                    source_ip=message.source_ip if message else flow.source_ip,
                    destination_ip=message.destination_ip if message else flow.destination_ip,
                    description="O Content-Length SIP nao corresponde ao tamanho do corpo da mensagem.",
                    evidence=[
                        *_flow_evidence(flow),
                        f"Content-Length mismatches: {flow.content_length_mismatches}",
                    ],
                    recommendation=(
                        "Corrija o gerador da mensagem SIP ou o intermediario que reescreve o corpo. Content-Length divergente pode quebrar o parsing e a remontagem TCP."
                    ),
                )
            )

    return findings


def detect_sip_header_fragmentation_risk(flows):
    findings = []

    for flow in flows.values():
        if flow.header_fragmentation_risk_messages == 0:
            continue

        message = _first_affected_message(
            flow,
            lambda item: item.header_size > SIP_FRAGMENTATION_RISK_HEADER_BYTES,
        )

        findings.append(
            Finding(
                type="sip_header_fragmentation_risk",
                severity="high",
                confidence=0.90,
                source_ip=message.source_ip if message else flow.source_ip,
                destination_ip=message.destination_ip if message else flow.destination_ip,
                description="O tamanho do bloco de headers SIP cria alto risco de fragmentacao IP.",
                evidence=[
                    *_flow_evidence(flow),
                    f"Oversized header blocks: {flow.header_fragmentation_risk_messages}",
                    "Header threshold: 1200 bytes",
                ],
                recommendation=(
                    "Reduza headers Via, Route, Record-Route, Contact e de identidade muito grandes, ou use transporte TCP/TLS quando apropriado."
                ),
            )
        )

    return findings


def detect_sip_udp_fragmentation_risk(flows):
    findings = []

    for flow in flows.values():
        if flow.udp_fragmentation_risk_messages == 0:
            continue

        message = _first_affected_message(
            flow,
            lambda item: item.transport == "UDP"
            and item.message_size > SIP_UDP_FRAGMENTATION_RISK_BYTES,
        )

        findings.append(
            Finding(
                type="sip_udp_fragmentation_risk",
                severity="medium",
                confidence=0.90,
                source_ip=message.source_ip if message else flow.source_ip,
                destination_ip=message.destination_ip if message else flow.destination_ip,
                description="Mensagens SIP sobre UDP excedem o limite seguro de 1200 bytes para o MTU.",
                evidence=[
                    *_flow_evidence(flow),
                    f"Oversized SIP/UDP messages: {flow.udp_fragmentation_risk_messages}",
                    "Safe message threshold: 1200 bytes",
                ],
                recommendation=(
                    "Reduza o tamanho das mensagens SIP ou use TCP/TLS quando suportado. Pacotes UDP acima do MTU do caminho podem ser fragmentados ou descartados silenciosamente."
                ),
            )
        )

    return findings


def detect_sip_signaling_fragmentation(flows, fragment_groups=None):
    findings = []
    fragment_groups = fragment_groups or {}

    for flow in flows.values():
        related_groups = _find_related_fragment_groups(flow, fragment_groups)

        if flow.fragmented_messages == 0 and not related_groups:
            continue

        findings.append(
            Finding(
                type="sip_signaling_fragmentation",
                severity="high",
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="Pacotes IP fragmentados foram observados carregando sinalizacao SIP.",
                evidence=[
                    *_flow_evidence(flow),
                    f"Fragmented SIP messages: {flow.fragmented_messages}",
                    f"Related IP fragment sets: {len(related_groups)}",
                    f"TCP-segmented SIP messages: {flow.tcp_segmented_messages}",
                ],
                recommendation=(
                    "Verifique MTU, transporte escolhido e tamanho das mensagens SIP. Sinalizacao fragmentada pode ser descartada por equipamentos e quebrar o estabelecimento."
                ),
            )
        )

    return findings


def detect_sip_register_failures(flows):
    return _detect_method_failures(
        flows,
        "REGISTER",
        "sip_register_failure",
        "O registro SIP foi rejeitado pelo registrar.",
        "Verifique credenciais, realm, politica de registro e alcance do registrar.",
    )


def detect_sip_transfer_failures(flows):
    return _detect_method_failures(
        flows,
        "REFER",
        "sip_transfer_failure",
        "A transferencia de chamada SIP foi rejeitada.",
        "Verifique permissoes de transferencia, roteamento do Refer-To, dial plan e disponibilidade do destino.",
    )


def detect_sip_options_no_response(flows):
    findings = []

    for flow in flows.values():
        options_requests = [
            message
            for message in flow.messages
            if message.is_request and message.method == "OPTIONS"
        ]
        options_responses = [
            message
            for message in flow.messages
            if not message.is_request and message.cseq_method == "OPTIONS"
        ]
        if not options_requests or options_responses:
            continue

        request = options_requests[0]
        findings.append(
            Finding(
                type="sip_options_no_response",
                severity="medium",
                confidence=0.85,
                source_ip=request.source_ip,
                destination_ip=request.destination_ip,
                description="A sonda SIP OPTIONS nao recebeu resposta.",
                evidence=[
                    *_flow_evidence(flow),
                    f"OPTIONS requests: {len(options_requests)}",
                    "OPTIONS responses: 0",
                ],
                recommendation=(
                    "Verifique o alcance SIP, a configuracao de keepalive OPTIONS, regras de firewall e o servico SIP de destino."
                ),
            )
        )

    return findings


def _detect_method_failures(flows, method, finding_type, description, recommendation):
    findings = []

    for flow in flows.values():
        errors = get_terminal_sip_method_errors(flow, method)
        if not errors:
            continue

        response = errors[0]
        findings.append(
            Finding(
                type=finding_type,
                severity="high",
                confidence=0.95,
                source_ip=response.source_ip,
                destination_ip=response.destination_ip,
                description=description,
                evidence=[
                    *_flow_evidence(flow),
                    f"Response: {response.status_code} {response.reason_phrase or ''}".strip(),
                    f"CSeq method: {method}",
                ],
                recommendation=recommendation,
            )
        )

    return findings


def _flow_evidence(flow):
    return [
        f"Call-ID: {flow.call_id}",
        f"Dialog-Key: {flow.dialog_key}",
    ]


def _first_affected_message(flow, predicate):
    return next((message for message in flow.messages if predicate(message)), None)


def _find_related_fragment_groups(flow, fragment_groups):
    return [
        group
        for group in fragment_groups.values()
        if any(_fragment_group_matches_message(group, message) for message in flow.messages)
    ]


def _fragment_group_matches_message(group, message):
    protocol = 17 if message.transport == "UDP" else 6 if message.transport == "TCP" else None

    if protocol is None or group.protocol != protocol:
        return False

    if (group.source_ip, group.destination_ip) != (message.source_ip, message.destination_ip):
        return False

    if group.source_port is None:
        return message.is_fragmented

    return (group.source_port, group.destination_port) == (
        message.source_port,
        message.destination_port,
    )


# RFC 3261 timer T1. Copies closer than this are capture duplicates (same
# packet seen on two interfaces), not retransmissions.
SIP_RETRANSMISSION_MIN_INTERVAL = 0.4
# Post-dial delay (INVITE to first 180/183) thresholds in seconds.
SIP_PDD_MEDIUM_SECONDS = 5.0
SIP_PDD_HIGH_SECONDS = 10.0
# Carrier-grade NAT space (RFC 6598) is not flagged by ipaddress.is_private.
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def detect_sip_retransmissions(flows):
    """Requests or responses resent over UDP: signaling packets are being lost."""
    findings = []
    for flow in flows.values():
        copies = {}
        for message in flow.messages:
            if message.transport != "UDP":
                continue
            key = (
                message.is_request,
                message.method,
                message.status_code,
                message.cseq_number,
                message.cseq_method,
                message.via_branch,
                message.source_ip,
                message.destination_ip,
            )
            copies.setdefault(key, []).append(message.packet_time)

        retransmitted = []
        for key, times in copies.items():
            times.sort()
            resent = sum(
                1
                for previous, current in zip(times, times[1:])
                if current - previous >= SIP_RETRANSMISSION_MIN_INTERVAL
            )
            if resent:
                retransmitted.append((key, resent))
        if not retransmitted:
            continue

        total = sum(resent for _key, resent in retransmitted)
        invite_resends = max(
            (resent for key, resent in retransmitted if key[0] and key[1] == "INVITE"),
            default=0,
        )
        labels = [
            f"{key[1] if key[0] else key[2]} (CSeq {key[3]} {key[4] or ''}".strip() + f"): {resent}x"
            for key, resent in retransmitted[:5]
        ]
        first_key = retransmitted[0][0]
        findings.append(
            Finding(
                type="sip_retransmission",
                severity="high" if invite_resends >= 3 or total >= 5 else "medium",
                confidence=0.90,
                source_ip=first_key[6],
                destination_ip=first_key[7],
                description="Mensagens SIP foram retransmitidas sobre UDP, indicando perda ou atraso na sinalizacao.",
                evidence=[
                    *_flow_evidence(flow),
                    f"Retransmissions: {total}",
                    *labels,
                ],
                recommendation=(
                    "Verifique perda de pacotes no caminho da sinalizacao, firewall ou ALG SIP descartando mensagens, "
                    "e se o destino esta sobrecarregado e demorando a responder."
                ),
            )
        )
    return findings


def detect_sip_slow_call_setup(flows, medium_seconds=SIP_PDD_MEDIUM_SECONDS, high_seconds=SIP_PDD_HIGH_SECONDS):
    """Post-dial delay: time from the first INVITE to the first ringing response."""
    findings = []
    for flow in flows.values():
        invite_time = next(
            (message.packet_time for message in flow.messages if message.is_request and message.method == "INVITE"),
            None,
        )
        if invite_time is None:
            continue
        ringing = next(
            (
                message
                for message in flow.messages
                if not message.is_request
                and message.status_code in {180, 183}
                and message.cseq_method in {None, "INVITE"}
            ),
            None,
        )
        if ringing is None:
            continue
        delay = ringing.packet_time - invite_time
        if delay < medium_seconds:
            continue
        findings.append(
            Finding(
                type="sip_slow_call_setup",
                severity="high" if delay >= high_seconds else "medium",
                confidence=0.90,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="O tempo entre o INVITE e o toque (post-dial delay) esta alto.",
                evidence=[
                    *_flow_evidence(flow),
                    f"Post-dial delay: {delay:.2f} s",
                    f"Ringing response: {ringing.status_code} {ringing.reason_phrase or ''}".strip(),
                ],
                recommendation=(
                    "Verifique consultas DNS/ENUM lentas, rotas de saida com failover, autenticacao "
                    "repetida e o tempo de processamento do proxy ou da operadora."
                ),
            )
        )
    return findings


def detect_sip_sdp_private_address(flows):
    """Private media address in SDP sent from a public signaling address: classic NAT breakage."""
    findings = []
    for flow in flows.values():
        for message in flow.messages:
            if not _is_public_ip(message.source_ip):
                continue
            private_media = [
                media
                for media in message.sdp_media
                if media.media_type == "audio"
                and media.port > 0
                and media.connection_address
                and _is_private_ip(media.connection_address)
            ]
            if not private_media:
                continue
            media = private_media[0]
            findings.append(
                Finding(
                    type="sip_sdp_private_address",
                    severity="medium",
                    confidence=0.85,
                    source_ip=message.source_ip,
                    destination_ip=message.destination_ip,
                    description="O SDP anuncia um endereco de midia privado, mas a sinalizacao veio de um IP publico.",
                    evidence=[
                        *_flow_evidence(flow),
                        f"SDP audio endpoint: {media.connection_address}:{media.port}",
                        f"Signaling source: {message.source_ip}",
                        f"Message: {message.start_line}",
                    ],
                    recommendation=(
                        "O endpoint esta atras de NAT sem reescrever o SDP. Habilite NAT traversal no SBC/PBX "
                        "(media latching / symmetric RTP), configure o IP externo no endpoint ou desative ALG SIP defeituoso."
                    ),
                )
            )
            break
    return findings


def _ip_address(value):
    try:
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None


def _is_private_ip(value):
    address = _ip_address(value)
    if address is None:
        return False
    shared = address.version == 4 and address in _CGNAT_NETWORK
    return (address.is_private or shared) and not address.is_loopback and not address.is_unspecified


def _is_public_ip(value):
    address = _ip_address(value)
    return address is not None and address.is_global


