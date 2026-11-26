"""Turn findings into a verdict: what happened, the probable culprit and why.

Findings describe isolated facts ("200 OK without ACK", "private IP in SDP").
An analyst needs the causal story instead: which fact explains the others,
which host is responsible and how sure the evidence is. This module ranks the
findings of each call by how *causal* they are (a malformed header that was
rejected with 400 explains the failed call; the failed call does not explain
the header), keeps the strongest as the root cause and lists the rest as
symptoms.
"""

from ciper.text import is_ascii_digits
from collections import Counter
from ipaddress import ip_address, ip_network

from ciper.findings import describe_responsibility
from ciper.labels import INFORMATIONAL_FINDINGS, finding_title
from ciper.sip_status import sip_status_info


# How much a finding explains other problems. Higher means "more root".
CAUSE_RANK = {
    # Network/path evidence that explains silence or missing responses.
    "udp_service_unreachable": 84,
    "icmp_admin_prohibited": 83,
    "icmp_port_unreachable": 82,
    "icmp_host_unreachable": 82,
    "icmp_network_unreachable": 82,
    "icmp_destination_unreachable": 80,
    "icmp_fragmentation_needed": 80,
    "sip_signaling_fragmentation": 78,
    "ip_fragment_incomplete": 76,
    # SDP / NAT problems that explain no-audio and one-way audio.
    "freeswitch_unusable_media_address": 86,
    "sip_sdp_private_address": 74,
    "sip_sdp_malformed": 72,
    "freeswitch_inactive_initial_offer": 70,
    "rtp_payload_not_negotiated": 62,
    # Signaling outcomes.
    "sip_error_response": 80,
    "sip_invite_no_response": 72,
    "sip_ok_without_ack": 70,
    "sip_abnormal_hangup": 68,
    "b2bua_leg_failure": 90,
    "sip_header_variable_injection": 66,
    "sip_call_one_way_audio": 66,
    "sip_call_established_without_rtp": 65,
    "rtp_one_way_audio": 67,
    "rtp_silent_audio": 64,
    "sip_sdp_no_common_codec": 80,
    "sip_sdp_answer_media_count": 66,
    "sip_sdp_direction_mismatch": 60,
    "sip_sdp_answer_codec_not_offered": 58,
    "sip_sdp_dtmf_not_negotiated": 42,
    "sip_sdp_dtmf_payload_mismatch": 25,
    "sip_contact_private_address": 56,
    "sip_register_auth_rejected": 82,
    "sip_register_expires_nat": 40,
    "sip_tls_signaling": 15,
    "freeswitch_codec_mismatch": 84,
    "freeswitch_profile_extension_disabled": 82,
    "freeswitch_srtp_disabled": 82,
    "sip_header_missing_contact": 64,
    "sip_header_duplicate_singleton": 62,
    "sip_header_control_characters": 62,
    "sip_header_malformed_address": 60,
    "sip_header_cseq_mismatch": 60,
    "sip_header_missing_mandatory": 60,
    "sip_header_invalid_encoding": 58,
    "sip_request_uri_invalid": 58,
    "sip_content_length_mismatch": 58,
    "sip_header_tcp_missing_content_length": 58,
    "sip_udp_fragmentation_risk": 55,
    "sip_header_max_forwards": 55,
    "sip_header_require_unsupported": 54,
    "sip_header_content_encoding": 54,
    "sip_header_missing_content_type": 54,
    "sip_sdp_dynamic_payload_without_rtpmap": 52,
    "sip_invalid_header": 52,
    "sip_header_invalid_name": 50,
    "sip_header_missing_from_tag": 50,
    "sip_header_bare_lf": 48,
    "rtp_packet_loss": 56,
    "rtp_stream_interruption": 54,
    "rtp_high_jitter": 50,
    "rtcp_reported_loss": 46,
    "rtcp_reported_jitter": 44,
    "rtcp_high_rtt": 44,
    "sip_retransmission": 50,
    "freeswitch_callcenter_input_risk": 50,
    "freeswitch_callcenter_midcall_hold": 60,
    "freeswitch_session_timer_risk": 48,
    "freeswitch_dtmf_negotiation_risk": 45,
    "sip_header_fragmentation_risk": 45,
    "sip_slow_call_setup": 45,
    "freeswitch_unidirectional_initial_offer": 44,
    "rtp_out_of_order": 40,
    "rtp_timestamp_anomaly": 38,
    "rtp_after_bye": 35,
    "sip_large_header": 35,
    "sip_call_cancelled": 30,
    "freeswitch_anonymous_caller_identity": 30,
    "sip_sdp_secure_transport": 28,
    "freeswitch_routing_target_mismatch": 25,
    "sip_header_non_ascii": 22,
    "sip_header_folding": 20,
    "sip_header_missing_max_forwards": 18,
    "freeswitch_custom_header_input": 10,
}
SEVERITY_BONUS = {"high": 10, "medium": 5, "low": 0}
CONFIRMED_BONUS = 40

MEDIA_FAILURE_STATES = {"no_media", "one_way_media", "silent_media"}
SIGNALING_FAILURE_STATES = {"failed", "no_response", "missing_ack"}
QUALITY_TYPES = {
    "rtp_packet_loss",
    "rtp_high_jitter",
    "rtp_stream_interruption",
    "rtp_out_of_order",
    "rtp_timestamp_anomaly",
    "rtcp_reported_loss",
    "rtcp_reported_jitter",
    "rtcp_high_rtt",
}
# Findings that only become causes when the call actually has a media problem.
MEDIA_EXPLAINERS = {
    "sip_sdp_private_address",
    "rtp_payload_not_negotiated",
    "rtp_source_mismatch",
    "freeswitch_unusable_media_address",
}

MESSAGE_HYGIENE_TYPES = {
    "sip_request_uri_invalid",
    "sip_sdp_malformed",
    "sip_sdp_dynamic_payload_without_rtpmap",
    "sip_sdp_secure_transport",
    "sip_invalid_header",
    "sip_content_length_mismatch",
}


def is_message_hygiene(finding_type):
    return finding_type.startswith("sip_header_") or finding_type in MESSAGE_HYGIENE_TYPES


CONFIDENCE_LABELS = ((0.85, "Alta"), (0.6, "Media"), (0.0, "Baixa"))
ATTRIBUTION_WEIGHT = {"high": 1.0, "medium": 0.85, "low": 0.65}


def confidence_label(value):
    for threshold, label in CONFIDENCE_LABELS:
        if value >= threshold:
            return label
    return "Baixa"


class EndpointNamer:
    """Describe an IP by the role it plays in the call."""

    def __init__(self, platform_ips="", platform_name="FreeSWITCH", capture_ip=None, capture_auto=False):
        self.platform_name = platform_name
        self.capture_ip = capture_ip or None
        self.capture_auto = capture_auto
        self.targets = [
            value.strip()
            for value in (platform_ips or "").replace(";", ",").split(",")
            if value.strip()
        ]

    def is_platform(self, address):
        if not address or not self.targets:
            return False
        for target in self.targets:
            try:
                if "/" in target and ip_address(address) in ip_network(target, strict=False):
                    return True
                if ip_address(address) == ip_address(target):
                    return True
            except ValueError:
                if address == target:
                    return True
        return False

    def describe(self, address, caller=None, callee=None):
        if not address:
            return "-"
        roles = []
        if self.is_platform(address):
            roles.append(self.platform_name)
        if self.capture_ip and address == self.capture_ip:
            roles.append("ponto de captura")
        if address == caller:
            roles.append("chamador / origem do INVITE")
        elif address == callee:
            roles.append("destino do INVITE")
        return f"{address} ({', '.join(roles)})" if roles else address


def detect_capture_point(sip_flows):
    """IP present in nearly every SIP dialog: the host where the capture ran.

    With a single dialog both endpoints qualify, so nothing is guessed.
    """
    dialogs = [flow for flow in sip_flows.values() if flow.messages]
    if len(dialogs) < 2:
        return None
    counts = Counter()
    for flow in dialogs:
        hosts = set()
        for message in flow.messages:
            hosts.add(message.source_ip)
            hosts.add(message.destination_ip)
        counts.update(hosts)
    ranked = counts.most_common()
    if not ranked:
        return None
    best, best_count = ranked[0]
    if best_count < 0.8 * len(dialogs):
        return None
    if len(ranked) > 1 and ranked[1][1] == best_count:
        return None
    return best


def apply_capture_point(finding, culprit, namer, caller=None, callee=None):
    """Sharpen "something did not arrive" verdicts using where the capture ran.

    Returns (culprit text, culprit ip, attribution, note).
    """
    text, culprit_ip, attribution = culprit
    point = namer.capture_ip
    if not point:
        return text, culprit_ip, attribution, ""
    how = "detectado automaticamente" if namer.capture_auto else "configurado"
    prefix = f"Ponto de captura {point} ({how}): "
    source, destination = finding.source_ip, finding.destination_ip

    if finding.type == "rtp_one_way_audio":
        if point == destination:
            return (
                f"{namer.describe(destination, caller, callee)} - o proprio host capturado nao enviou RTP de volta",
                destination,
                "high",
                prefix + "a captura foi feita no host que deveria responder e nenhum RTP saiu dele; o problema e "
                "local (SDP recebido com endereco errado, NAT/media latching ou aplicacao sem midia), nao a rede.",
            )
        if point == source:
            return (
                text,
                culprit_ip,
                "medium",
                prefix + f"o retorno de {destination} nunca chegou ao host capturado; {destination} nao enviou ou "
                "o caminho bloqueou. Uma captura do lado remoto separa as duas hipoteses.",
            )

    if finding.type == "sip_invite_no_response":
        if point == destination:
            return (
                f"{namer.describe(destination, caller, callee)} - recebeu o INVITE e nao respondeu",
                destination,
                "high",
                prefix + "o INVITE chegou ao host capturado, entao a rede o entregou; a aplicacao SIP, o firewall "
                "local ou uma ACL descartou a requisicao.",
            )
        if point == source:
            return (
                text,
                culprit_ip,
                "medium",
                prefix + "o INVITE saiu do host capturado, mas nao da para saber se chegou ao destino.",
            )

    if finding.type == "sip_ok_without_ack":
        if point == destination:
            return (
                f"{namer.describe(destination, caller, callee)} - recebeu o 200 OK e nao enviou ACK por este caminho",
                destination,
                "high",
                prefix + "o chamador recebeu o 200 OK. O ACK vai para o Contact/Record-Route do 200 OK: se ele traz "
                "IP privado ou inalcancavel, o ACK sai para outro lugar e a chamada cai em ~32 s.",
            )
        if point == source:
            return (
                text,
                culprit_ip,
                "medium",
                prefix + "o 200 OK saiu do host capturado e o ACK nunca voltou: chamador sem rota para o Contact "
                "do 200 OK, NAT ou firewall no retorno.",
            )

    if finding.type in QUALITY_TYPES and finding.type.startswith("rtp_"):
        if point == source:
            return (
                f"{namer.describe(source, caller, callee)} - emissor (perda ja na origem)",
                source,
                "medium",
                prefix + "a degradacao ja aparece no proprio emissor: CPU ou placa sobrecarregada, gerador de midia "
                "com problema ou perda na propria captura (verifique pacotes descartados pelo capturador).",
            )
        if point == destination:
            return (
                text,
                culprit_ip,
                "medium",
                prefix + "medido no receptor: a degradacao ocorreu em algum ponto entre o emissor e este host.",
            )
        return (
            f"Trecho {source} -> {point} (ate o ponto de captura)",
            None,
            attribution,
            prefix + "a captura esta no meio do caminho: a degradacao ocorreu antes deste ponto.",
        )

    if finding.type == "sip_call_established_without_rtp" and point in {source, destination}:
        return (
            text,
            culprit_ip,
            attribution,
            prefix + "nenhum RTP entrou ou saiu do host capturado; se ele usa um servidor de midia separado, "
            "capture tambem nesse servidor.",
        )

    return text, culprit_ip, attribution, ""


def _cause_score(finding, call):
    if finding.type in INFORMATIONAL_FINDINGS:
        return -1
    score = CAUSE_RANK.get(finding.type, 20) + SEVERITY_BONUS.get(finding.severity, 0)
    if getattr(finding, "confirmed_by", None) and finding.type != "sip_error_response":
        score += CONFIRMED_BONUS
    signaling_state = call.get("signaling_state") if call else None
    if finding.type == "sip_error_response":
        if finding_blame(finding) == "user":
            score = 45
    elif is_message_hygiene(finding.type) and not getattr(finding, "confirmed_by", None):
        # An unconfirmed header risk never outranks the response that
        # actually ended the call: it stays a secondary observation.
        if signaling_state in SIGNALING_FAILURE_STATES or signaling_state == "cancelled":
            score = min(score, 40)
    if finding.type == "sip_contact_private_address" and signaling_state == "missing_ack":
        # A private Contact in the 200 OK is the classic reason the ACK never comes.
        score += 30
    media_state = call.get("media_state") if call else None
    if finding.type in MEDIA_EXPLAINERS:
        established = signaling_state in {"established", "terminated", None}
        if media_state in MEDIA_FAILURE_STATES and established:
            score += 20
        else:
            score -= 25
    return score


def specific_title(finding):
    """Finding title with the detail that matters (status code for SIP errors)."""
    if finding.type == "sip_error_response":
        code = _status_code(finding)
        info = sip_status_info(code)
        if code is not None:
            return f"Recusa SIP {code}" + (f" ({info.meaning})" if info else "")
    return finding_title(finding.type)


def finding_blame(finding):
    """Side blamed by a SIP error/hangup: the Q.850 cause wins over the SIP class."""
    explicit = _evidence_value(finding, "Blame")
    if explicit:
        return explicit
    info = sip_status_info(_status_code(finding))
    return info.blame if info is not None else "responder"


def _status_code(finding):
    for item in finding.evidence:
        if item.startswith("Status: "):
            code = item.removeprefix("Status: ").split(" ", 1)[0]
            if is_ascii_digits(code):
                return int(code)
    return None


def _evidence_value(finding, key):
    prefix = f"{key}: "
    for item in finding.evidence:
        if item.startswith(prefix):
            return item[len(prefix):]
    return None


def describe_culprit(finding, namer, caller=None, callee=None):
    """(culprit text, culprit ip or None, attribution confidence key, reason)."""
    label, attribution, reason = describe_responsibility(finding)

    if finding.type == "sip_error_response":
        info = sip_status_info(_status_code(finding))
        blame = finding_blame(finding)
        responder = _evidence_value(finding, "Rejected by") or finding.source_ip
        requester = _evidence_value(finding, "Requested by") or finding.destination_ip
        q850 = _evidence_value(finding, "Q.850 cause")
        explanation = info.explanation if info else reason
        if q850:
            explanation = f"{explanation} Causa Q.850 {q850}."
        if blame == "requester":
            return (
                f"{namer.describe(requester, caller, callee)} - enviou a requisicao recusada",
                requester,
                "high",
                explanation,
            )
        if blame == "negotiation":
            return (
                f"Negociacao entre {requester} e {responder} - ofertas incompativeis",
                None,
                "medium",
                explanation,
            )
        if blame == "downstream":
            return (
                f"Rede/servidor depois de {namer.describe(responder, caller, callee)}",
                responder,
                "medium",
                explanation,
            )
        if blame == "user":
            return (
                "Usuario chamado - resultado normal, nao e falha tecnica",
                responder,
                "high",
                explanation,
            )
        return (
            f"{namer.describe(responder, caller, callee)} - recusou a chamada",
            responder,
            "high",
            explanation,
        )

    if finding.type == "sip_abnormal_hangup":
        blame = finding_blame(finding)
        sender = namer.describe(finding.source_ip, caller, callee)
        cause = _evidence_value(finding, "Q.850 cause") or "-"
        if blame == "downstream":
            text = f"{sender} ou a rede/servidor atras dele - derrubou a chamada (Q.850 {cause})"
        else:
            text = f"{sender} - derrubou a chamada (Q.850 {cause})"
        return (
            text,
            finding.source_ip,
            "high" if blame != "downstream" else "medium",
            "Quem envia o BYE com causa anormal e quem decidiu encerrar; a causa diz se foi por falha propria ou da rede atras dele.",
        )

    if finding.type.startswith("icmp_") and finding.type != "icmp_no_response":
        emitter = namer.describe(finding.source_ip, caller, callee)
        code = _evidence_value(finding, "ICMP code")
        if finding.type == "icmp_admin_prohibited":
            text = f"{emitter} - firewall/ACL que bloqueou o trafego"
        elif code == "3" or "port" in finding.description.lower():
            text = f"{emitter} - nao ha servico escutando na porta de destino"
        elif finding.type == "icmp_time_exceeded":
            text = f"{emitter} - roteador onde o TTL expirou (loop ou rota longa)"
        elif finding.type == "icmp_fragmentation_needed":
            text = f"{emitter} - salto com MTU menor que o pacote enviado"
        else:
            text = f"{emitter} - roteador/host que nao alcanca o destino"
        return (text, finding.source_ip, "high", "O ICMP identifica quem rejeitou ou nao conseguiu entregar o pacote.")

    if finding.type == "rtp_one_way_audio":
        silent = namer.describe(finding.destination_ip, caller, callee)
        return (
            f"Sentido {finding.destination_ip} -> {finding.source_ip}: RTP ausente (NAT/firewall ou SDP de {finding.destination_ip})",
            finding.destination_ip,
            "medium",
            f"O audio de {finding.source_ip} chega a {silent}, mas nenhum RTP volta. Ou {finding.destination_ip} nao "
            "enviou midia (endereco/porta errados no SDP recebido, NAT sem media latching) ou um firewall/NAT "
            "descartou o retorno antes do ponto de captura.",
        )

    if finding.type == "sip_call_established_without_rtp":
        return (
            f"Caminho de midia entre {finding.source_ip} e {finding.destination_ip} (firewall, NAT ou SDP)",
            None,
            "medium",
            "A sinalizacao completou, mas nenhum RTP foi visto em nenhum sentido. Causas tipicas: endereco/porta "
            "do SDP inalcancavel, faixa de portas RTP bloqueada no firewall, ou a midia passa por outra interface/"
            "servidor de midia que o ponto de captura nao enxerga (confira antes de culpar a rede).",
        )

    if finding.type == "rtp_without_sip":
        return (
            f"Ponto de captura ou sinalizacao fora da captura ({finding.source_ip} -> {finding.destination_ip})",
            None,
            "low",
            "Ha midia sem dialogo SIP correspondente: a sinalizacao pode ter sido capturada em outro ponto, usar "
            "TLS (nao decifravel) ou o stream ficou orfao apos o encerramento.",
        )

    if finding.type in QUALITY_TYPES:
        return (
            f"Rede no sentido {finding.source_ip} -> {finding.destination_ip}",
            None,
            attribution,
            "A degradacao foi medida nos pacotes desse sentido; o problema esta no caminho entre os dois "
            "(enlace, QoS, Wi-Fi, VPN) ou na placa/CPU do emissor. Compare com uma captura perto do emissor para separar.",
        )

    culprit_ip = getattr(finding, "culprit_ip", None)
    if culprit_ip:
        return (
            f"{namer.describe(culprit_ip, caller, callee)} - enviou a mensagem com o problema",
            culprit_ip,
            attribution,
            reason,
        )

    if label.startswith("Caminho"):
        return (
            f"Rede entre {finding.source_ip} e {finding.destination_ip}",
            None,
            attribution,
            reason,
        )
    if label.startswith("Destino"):
        return (
            f"{namer.describe(finding.destination_ip, caller, callee)} ou o caminho ate ele",
            finding.destination_ip,
            attribution,
            reason,
        )
    if label.startswith("Origem"):
        return (
            f"{namer.describe(finding.source_ip, caller, callee)}",
            finding.source_ip,
            attribution,
            reason,
        )
    return ("Nao determinado pela captura", None, attribution, reason)


def _outcome(call, root):
    signaling = call.get("signaling_state")
    media = call.get("media_state")
    if signaling == "failed":
        status = None
        if root is not None:
            status = _evidence_value(root, "Status") if root.type == "sip_error_response" else root.confirmed_by
        return f"Chamada recusada{f' com {status}' if status else ''}"
    if signaling == "no_response":
        return "INVITE sem resposta"
    if signaling == "missing_ack":
        return "Chamada atendida, mas o ACK nao chegou"
    if signaling == "cancelled":
        return "Chamada cancelada antes de atender"
    if media == "no_media":
        return "Chamada atendida sem audio"
    if media == "one_way_media":
        return "Chamada com audio em uma via"
    if media == "silent_media":
        return "Chamada com audio mudo"
    if media == "degraded_media":
        return "Chamada com audio degradado"
    if signaling in {"established", "terminated"}:
        return "Chamada completada"
    return "Sinalizacao incompleta na captura"


def _status_for(call, root, actionable):
    signaling = call.get("signaling_state")
    media = call.get("media_state")
    if root is not None and root.type == "sip_error_response":
        if finding_blame(root) == "user":
            return "user"
    if signaling in SIGNALING_FAILURE_STATES or media in MEDIA_FAILURE_STATES:
        return "fail"
    if media == "degraded_media" or any(finding.type in QUALITY_TYPES and finding.severity != "low" for finding in actionable):
        return "degraded"
    if any(finding.severity in {"high", "medium"} for finding in actionable):
        return "risk"
    return "ok"


def build_verdict(call, findings, namer=None):
    """Verdict for one call summary and the findings related to it."""
    namer = namer or EndpointNamer()
    caller = call.get("source_ip")
    callee = call.get("destination_ip")
    actionable = [finding for finding in findings if finding.type not in INFORMATIONAL_FINDINGS]
    ranked = sorted(actionable, key=lambda finding: _cause_score(finding, call), reverse=True)
    root = ranked[0] if ranked else None
    status = _status_for(call, root, actionable)
    outcome = _outcome(call, root)

    if root is None or status == "ok":
        return {
            "status": "ok",
            "headline": f"{outcome}: nenhum problema detectado",
            "outcome": outcome,
            "root_type": None,
            "root_title": None,
            "culprit": "Nenhum",
            "culprit_ip": None,
            "confidence": 0.9 if call.get("signaling_state") in {"established", "terminated"} else 0.6,
            "confidence_label": "Alta" if call.get("signaling_state") in {"established", "terminated"} else "Media",
            "reasons": _ok_reasons(call),
            "actions": [],
            "symptoms": [],
            "confirmed_by": None,
            "offending_lines": [],
        }

    culprit, culprit_ip, attribution, culprit_reason = describe_culprit(root, namer, caller, callee)
    culprit, culprit_ip, attribution, capture_note = apply_capture_point(
        root, (culprit, culprit_ip, attribution), namer, caller, callee
    )
    if capture_note:
        culprit_reason = f"{culprit_reason} {capture_note}".strip()
        if namer.capture_auto and attribution == "high":
            # A port mirror next to the host looks the same as a capture on it.
            attribution = "medium"
    confirmed_by = getattr(root, "confirmed_by", None)
    confidence = root.confidence * ATTRIBUTION_WEIGHT.get(attribution, 0.7)
    if confirmed_by:
        confidence = min(0.99, confidence + 0.08)
    if len(ranked) > 1 and _cause_score(ranked[1], call) >= _cause_score(root, call) - 3 and not confirmed_by:
        # Two candidates explain the call equally well: be honest about it.
        confidence *= 0.85

    root_title = specific_title(root)
    if status == "user":
        meaning = _evidence_value(root, "Q.850 cause") or (sip_status_info(_status_code(root)) or sip_status_info(499)).meaning
        headline = f"{outcome}: {meaning.split(' - ', 1)[-1].lower()} (nao e falha tecnica)"
    elif status == "risk":
        headline = f"{outcome}, mas com risco: {root_title}"
    elif outcome.startswith("Chamada recusada") and root.type == "sip_error_response":
        info = sip_status_info(_status_code(root))
        headline = f"{outcome}" + (f" - {info.meaning.lower()}" if info else "")
    else:
        headline = f"{outcome} - provavel causa: {root_title}"

    symptoms = [finding for finding in ranked[1:] if finding.type != root.type]
    reasons = [_what_happened(call)]
    reasons.append(root.description)
    if confirmed_by and root.type != "sip_error_response":
        reasons.append(f"Confirmado: a resposta {confirmed_by} veio logo depois da mensagem com o problema.")
    if culprit_reason:
        reasons.append(f"Por que este culpado: {culprit_reason}")
    if symptoms:
        titles = []
        for finding in symptoms:
            title = specific_title(finding)
            if title not in titles:
                titles.append(title)
        reasons.append("Tambem observado (consequencia ou fator secundario): " + ", ".join(titles[:5]) + ".")

    actions = []
    for finding in [root, *symptoms]:
        action = finding.recommendation
        if action and action not in actions:
            actions.append(action)
        if len(actions) >= 3:
            break

    return {
        "status": status,
        "headline": headline,
        "outcome": outcome,
        "root_type": root.type,
        "root_title": root_title,
        "culprit": culprit,
        "culprit_ip": culprit_ip,
        "confidence": round(confidence, 2),
        "confidence_label": confidence_label(confidence),
        "reasons": reasons,
        "actions": actions,
        "symptoms": [finding.type for finding in symptoms],
        "confirmed_by": confirmed_by,
        "offending_lines": list(getattr(root, "offending_lines", []) or []),
    }


def _what_happened(call):
    timings = call.get("signaling_timings") or {}
    parts = []
    signaling = call.get("signaling_state")
    labels = {
        "established": "a chamada foi estabelecida",
        "terminated": "a chamada foi estabelecida e encerrada com BYE",
        "failed": "a chamada recebeu resposta final de erro",
        "no_response": "o INVITE nao recebeu nenhuma resposta",
        "missing_ack": "o 200 OK foi enviado mas o ACK nao foi visto",
        "cancelled": "o chamador cancelou antes do atendimento",
        "incomplete": "a sinalizacao ficou incompleta na captura",
    }
    parts.append(f"Na captura, {labels.get(signaling, 'a sinalizacao foi parcialmente observada')}")
    if timings.get("invite_to_ringing") is not None:
        parts.append(f"toque em {timings['invite_to_ringing']:.2f} s")
    if timings.get("invite_to_ok") is not None:
        parts.append(f"atendimento em {timings['invite_to_ok']:.2f} s")
    streams = call.get("rtp_stream_count", 0)
    parts.append(f"{streams} stream(s) RTP correlacionado(s)")
    return ", ".join(parts) + "."


def _ok_reasons(call):
    reasons = [_what_happened(call)]
    metrics = call.get("rtp_metrics") or {}
    if metrics.get("packet_count"):
        reasons.append(
            f"Midia: perda {metrics.get('loss_percent', 0.0):.2f}%, jitter maximo "
            f"{metrics.get('max_jitter', 0.0) * 1000:.1f} ms, dentro dos limites."
        )
    return reasons


def build_capture_diagnosis(call_summaries, findings, platform_ips="", platform_name="FreeSWITCH", namer=None):
    """One verdict for the whole capture, plus a breakdown of causes."""
    namer = namer or EndpointNamer(platform_ips, platform_name)
    # A B2BUA leg B is part of the same user call as its leg A: count calls once.
    logical_calls = [
        summary for summary in call_summaries if (summary.get("legs") or {}).get("role") != "B"
    ]
    verdicts = [(summary, summary.get("verdict") or {}) for summary in logical_calls]
    counts = Counter(verdict.get("status", "ok") for _summary, verdict in verdicts)
    causes = Counter()
    culprits = {}
    worst = None
    order = {"fail": 0, "degraded": 1, "risk": 2, "user": 3, "ok": 4}
    for summary, verdict in verdicts:
        if verdict.get("root_type") and verdict.get("status") in {"fail", "degraded", "risk"}:
            key = verdict["root_type"]
            causes[key] += 1
            culprits.setdefault(key, verdict.get("culprit"))
        if worst is None or order.get(verdict.get("status"), 9) < order.get(worst[1].get("status"), 9) or (
            order.get(verdict.get("status"), 9) == order.get(worst[1].get("status"), 9)
            and verdict.get("confidence", 0) > worst[1].get("confidence", 0)
        ):
            worst = (summary, verdict)

    call_finding_types = {item for summary in call_summaries for item in summary.get("finding_types", [])}
    orphan = [
        finding
        for finding in findings
        if finding.type not in INFORMATIONAL_FINDINGS
        and finding.type not in call_finding_types
        and finding.severity in {"high", "medium"}
    ]
    orphan.sort(key=lambda finding: _cause_score(finding, None), reverse=True)

    total = len(logical_calls)
    failed = counts.get("fail", 0)
    degraded = counts.get("degraded", 0)
    breakdown = [
        {
            "type": finding_type,
            "title": finding_title(finding_type),
            "calls": count,
            "culprit": culprits.get(finding_type),
        }
        for finding_type, count in causes.most_common()
    ]

    # The representative call must illustrate the headline cause, so pick
    # the cause first (worst status, then most calls, then most certain)
    # and then the most certain call that has it.
    groups = {}
    for summary, verdict in verdicts:
        if verdict.get("root_type") and verdict.get("status") in {"fail", "degraded", "risk"}:
            # Group by the specific title so a 488 and a 503 are different causes.
            key = (verdict["root_type"], verdict.get("root_title") or finding_title(verdict["root_type"]))
            groups.setdefault(key, []).append((summary, verdict))
    if groups:
        def group_key(item):
            _key, members = item
            best_status = min(order.get(verdict.get("status"), 9) for _summary, verdict in members)
            best_confidence = max(verdict.get("confidence", 0) for _summary, verdict in members)
            return (best_status, -len(members), -best_confidence)

        ranked_groups = sorted(groups.items(), key=group_key)
        breakdown = [
            {
                "type": finding_type,
                "title": title,
                "calls": len(members),
                "culprit": members[0][1].get("culprit"),
            }
            for (finding_type, title), members in ranked_groups
        ]
        _main_key, members = ranked_groups[0]
        worst = max(members, key=lambda item: (-order.get(item[1].get("status"), 9), item[1].get("confidence", 0)))

    if worst is not None and worst[1].get("status") in {"fail", "degraded", "risk", "user"}:
        summary, verdict = worst
        if breakdown and verdict.get("status") in {"fail", "degraded", "risk"}:
            main = breakdown[0]
            share = f"{failed} de {total} chamada(s) com falha" if failed else (
                f"{degraded} de {total} chamada(s) com audio degradado" if degraded else f"{total} chamada(s) com risco"
            )
            if len(breakdown) > 1 and main["calls"] == 1:
                headline = f"{share} - {len(breakdown)} causas diferentes; mais grave: {main['title']}"
            elif main["calls"] > 1:
                headline = f"{share} - principal causa: {main['title']} ({main['calls']} chamadas)"
            else:
                headline = f"{share} - causa: {main['title']}"
        else:
            headline = verdict["headline"]
        return {
            "status": verdict["status"],
            "headline": headline,
            "culprit": verdict.get("culprit"),
            "culprit_ip": verdict.get("culprit_ip"),
            "confidence": verdict.get("confidence", 0.0),
            "confidence_label": verdict.get("confidence_label", "Baixa"),
            "reasons": verdict.get("reasons", []),
            "actions": verdict.get("actions", []),
            "root_type": verdict.get("root_type"),
            "confirmed_by": verdict.get("confirmed_by"),
            "offending_lines": verdict.get("offending_lines", []),
            "worst_call_id": summary.get("call_id"),
            "worst_dialog_key": summary.get("dialog_key"),
            "calls": {"total": total, **{key: counts.get(key, 0) for key in order}},
            "breakdown": breakdown,
            "network_issues": [finding_title(finding.type) for finding in orphan[:5]],
        }

    if orphan:
        root = orphan[0]
        culprit, culprit_ip, attribution, reason = describe_culprit(root, namer)
        confidence = root.confidence * ATTRIBUTION_WEIGHT.get(attribution, 0.7)
        return {
            "status": "fail" if root.severity == "high" else "degraded",
            "headline": f"{finding_title(root.type)}" + (f" ({total} chamada(s) sem problema)" if total else ""),
            "culprit": culprit,
            "culprit_ip": culprit_ip,
            "confidence": round(confidence, 2),
            "confidence_label": confidence_label(confidence),
            "reasons": [root.description, *( [f"Por que este culpado: {reason}"] if reason else [])],
            "actions": [root.recommendation] if root.recommendation else [],
            "root_type": root.type,
            "confirmed_by": getattr(root, "confirmed_by", None),
            "offending_lines": list(getattr(root, "offending_lines", []) or []),
            "worst_call_id": None,
            "worst_dialog_key": None,
            "calls": {"total": total, **{key: counts.get(key, 0) for key in order}},
            "breakdown": breakdown,
            "network_issues": [finding_title(finding.type) for finding in orphan[1:6]],
        }

    return {
        "status": "ok",
        "headline": (
            f"{total} chamada(s) analisada(s): nenhum problema detectado" if total else "Nenhum problema detectado na captura"
        ),
        "culprit": "Nenhum",
        "culprit_ip": None,
        "confidence": 0.85 if total else 0.6,
        "confidence_label": "Alta" if total else "Media",
        "reasons": ["Sinalizacao e midia observadas dentro dos limites configurados."] if total else [
            "A captura nao contem chamadas SIP nem falhas de rede relevantes."
        ],
        "actions": [],
        "root_type": None,
        "confirmed_by": None,
        "offending_lines": [],
        "worst_call_id": None,
        "worst_dialog_key": None,
        "calls": {"total": total, **{key: counts.get(key, 0) for key in order}},
        "breakdown": [],
        "network_issues": [],
    }
