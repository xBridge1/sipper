from ciper.text import is_ascii_digits
from dataclasses import dataclass, field

from ciper.sip_status import sip_status_info


@dataclass
class Finding:
    type: str
    severity: str
    confidence: float

    source_ip: str
    destination_ip: str

    description: str

    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    references: list[dict[str, str]] = field(default_factory=list)
    # The IP whose message or behaviour the evidence points at, when known.
    culprit_ip: str | None = None
    # Response that proves the problem had an effect (e.g. "400 Bad Request").
    confirmed_by: str | None = None
    # Raw header lines that contain the problem, for display.
    offending_lines: list[str] = field(default_factory=list)


def describe_responsibility(finding):
    finding_type = finding.type

    if finding_type in {
        "freeswitch_custom_header_input",
        "freeswitch_routing_target_mismatch",
    }:
        return "Origem remota ou SBC", "medium", "O valor chegou no INVITE, mas pode ter sido inserido ou reescrito legitimamente por um SBC ou pela operadora."

    if finding_type.startswith("freeswitch_"):
        return "Origem remota", "high", "O INVITE recebido contem a condicao que pode afetar o processamento no FreeSWITCH."

    if finding_type == "sip_header_variable_injection":
        return "Origem da mensagem", "high", "O host que enviou a mensagem incluiu a sintaxe ${...} no header; verifique se a origem e confiavel."

    if finding_type in {"sip_header_fragmentation_risk"}:
        return "Origem ou caminho", "medium", "A origem gerou uma mensagem grande; o caminho pode fragmentar ou descartar os pacotes."

    if finding_type.startswith("sip_header_") or finding_type in {
        "sip_request_uri_invalid",
        "sip_sdp_malformed",
        "sip_sdp_dynamic_payload_without_rtpmap",
        "sip_sdp_secure_transport",
    }:
        confirmed = getattr(finding, "confirmed_by", None)
        reason = (
            "O host que enviou a mensagem gerou o header ou SDP com problema. Um SBC, B2BUA ou ALG SIP no caminho "
            "tambem pode te-lo reescrito: compare com uma captura antes desse elemento."
        )
        if confirmed:
            reason += f" O destino respondeu {confirmed}, confirmando o impacto."
        return "Origem da mensagem", "high" if confirmed else "medium", reason

    if finding_type in {
        "tcp_reset",
        "tcp_handshake_reset",
        "sip_invalid_header",
        "sip_content_length_mismatch",
    }:
        return "Origem", "high", "O endpoint de origem enviou o evento ou a mensagem invalida."

    if finding_type == "tls_fatal_alert":
        return "Origem", "high", "O endpoint de origem enviou o alerta TLS fatal."

    if finding_type in {
        "sip_sdp_answer_media_count",
        "sip_sdp_no_common_codec",
        "sip_sdp_answer_codec_not_offered",
        "sip_sdp_dtmf_not_negotiated",
        "sip_sdp_dtmf_payload_mismatch",
        "sip_sdp_direction_mismatch",
    }:
        return "Quem enviou a resposta SDP", "high", "A resposta SDP e gerada por quem atende a oferta; ela nao respeitou a oferta recebida."

    if finding_type in {"sip_contact_private_address", "sip_register_expires_nat"}:
        return "Origem atras de NAT", "high", "O host que enviou a mensagem esta atras de NAT e anunciou um endereco privado ou um intervalo incompativel com o NAT."

    if finding_type == "sip_register_auth_rejected":
        return "Origem (credenciais)", "high", "O endpoint enviou credenciais que o registrar recusou."

    if finding_type == "sip_tls_signaling":
        return "Ponto de captura", "high", "A sinalizacao esta cifrada; a captura nao permite analisa-la."

    if finding_type == "sip_abnormal_hangup":
        return "Quem enviou o BYE", "high", "O lado que enviou o BYE com causa anormal derrubou a chamada; a causa Q.850 indica se foi falha propria ou da rede atras dele."

    if finding_type == "sip_error_response":
        info = sip_status_info(_status_code(finding))
        blame = _evidence_blame(finding) or (info.blame if info else None)
        if blame is not None:
            return {
                "requester": ("Origem da requisicao", "high"),
                "responder": ("Destino (quem recusou)", "high"),
                "negotiation": ("Negociacao entre os lados", "medium"),
                "downstream": ("Proximo salto apos o destino", "medium"),
                "user": ("Usuario chamado (nao e falha)", "high"),
            }[blame] + ((info.explanation if info else "Resposta de erro SIP."),)

    if finding_type in {"sip_error_response", "sip_register_failure", "sip_transfer_failure"}:
        return "Origem", "high", "O endpoint de origem enviou a resposta SIP que recusou a operacao."

    if finding_type in {"tls_legacy_version", "tls_weak_cipher_suite"}:
        return "Origem", "medium", "O cliente de origem ofereceu configuracao TLS legada; a configuracao do destino tambem deve ser validada."

    if finding_type in {
        "tcp_syn_failure",
        "tcp_handshake_incomplete",
        "sip_invite_no_response",
        "sip_ok_without_ack",
        "sip_options_no_response",
        "tls_client_hello_no_response",
    }:
        return "Destino ou caminho", "medium", "O destino nao respondeu; firewall, proxy ou caminho tambem podem estar envolvidos."

    if finding_type in {"sip_call_established_without_rtp", "sip_call_one_way_audio"}:
        return "Caminho de midia", "medium", "A sinalizacao completou mas o RTP nao fluiu como negociado: SDP, NAT ou firewall entre os endpoints."

    if finding_type == "sip_sdp_private_address":
        return "Origem", "high", "O endpoint de origem anunciou no SDP um endereco que o outro lado nao alcanca."

    if finding_type in {"sip_retransmission", "sip_slow_call_setup"}:
        return "Destino ou caminho", "medium", "O destino demorou a responder ou mensagens se perderam no caminho."

    if finding_type in {"rtp_payload_not_negotiated", "rtp_ptime_mismatch", "rtp_source_mismatch"}:
        return "Origem", "medium", "O remetente do RTP nao seguiu o que foi negociado no SDP; um SBC ou NAT tambem pode ter alterado o fluxo."

    if finding_type.startswith(("rtp_", "rtcp_")):
        return "Caminho de rede", "medium", "A evidencia aponta para degradacao entre os endpoints, sem atribuir falha a apenas um lado."

    if finding_type.startswith("ip_fragment") or "fragmentation" in finding_type:
        return "Origem ou caminho", "medium", "A origem gerou trafego fragmentado ou o caminho descartou fragmentos."

    if finding_type.startswith("tls_"):
        return "Origem ou caminho", "medium", "A captura mostra uma anomalia TLS, mas nao permite separar endpoint, proxy ou inspecao intermediaria."

    if finding_type.startswith("icmp_"):
        return "Caminho de rede", "medium", "A mensagem ICMP foi emitida por um endpoint ou roteador no caminho."

    if finding_type.startswith("udp_"):
        return "Destino ou caminho", "medium", "Nao houve resposta observada do destino; o caminho pode ter bloqueado o trafego."

    return "Em investigacao", "low", "A captura nao permite atribuir a causa a um unico componente."


def _status_code(finding):
    for item in finding.evidence:
        if item.startswith("Status: "):
            code = item.removeprefix("Status: ").split(" ", 1)[0]
            if is_ascii_digits(code):
                return int(code)
    return None


def _evidence_blame(finding):
    for item in finding.evidence:
        if item.startswith("Blame: "):
            return item.removeprefix("Blame: ").strip()
    return None
