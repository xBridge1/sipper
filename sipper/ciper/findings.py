from dataclasses import dataclass, field


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


def describe_responsibility(finding):
    finding_type = finding.type

    if finding_type in {"tcp_reset", "tcp_handshake_reset", "sip_invalid_header", "sip_content_length_mismatch"}:
        return "Origem", "high", "O endpoint de origem enviou o evento ou a mensagem invalida."

    if finding_type == "tls_fatal_alert":
        return "Origem", "high", "O endpoint de origem enviou o alerta TLS fatal."

    if finding_type in {
        "tcp_syn_failure",
        "tcp_handshake_incomplete",
        "sip_invite_no_response",
        "sip_ok_without_ack",
        "tls_client_hello_no_response",
    }:
        return "Destino ou caminho", "medium", "O destino nao respondeu; firewall, proxy ou caminho tambem podem estar envolvidos."

    if finding_type.startswith("rtp_"):
        return "Caminho de rede", "medium", "A evidencia aponta para degradacao entre os endpoints, sem atribuir falha a apenas um lado."

    if finding_type.startswith("ip_fragment") or "fragmentation" in finding_type:
        return "Origem ou caminho", "medium", "A origem gerou trafego fragmentado ou o caminho descartou fragmentos."

    if finding_type.startswith("tls_legacy"):
        return "Origem", "high", "O cliente de origem ofereceu uma versao TLS legada."

    if finding_type.startswith("sip_error_response"):
        return "Origem", "high", "O endpoint de origem enviou a resposta SIP de erro."

    if finding_type.startswith("icmp_"):
        return "Caminho de rede", "medium", "A mensagem ICMP foi emitida por um endpoint ou roteador no caminho."

    if finding_type.startswith("udp_"):
        return "Destino ou caminho", "medium", "Nao houve resposta observada do destino; o caminho pode ter bloqueado o trafego."

    return "Em investigacao", "low", "A captura nao permite atribuir a causa a um unico componente."


def describe_responsibility(finding):
    finding_type = finding.type

    if finding_type in {"tcp_reset", "tcp_handshake_reset", "sip_invalid_header", "sip_content_length_mismatch"}:
        return "Origem", "high", "O endpoint de origem enviou o evento ou a mensagem invalida."

    if finding_type == "tls_fatal_alert":
        return "Origem", "high", "O endpoint de origem enviou o alerta TLS fatal."

    if finding_type in {
        "tcp_syn_failure",
        "tcp_handshake_incomplete",
        "sip_invite_no_response",
        "sip_ok_without_ack",
        "tls_client_hello_no_response",
    }:
        return "Destino ou caminho", "medium", "O destino nao respondeu; firewall, proxy ou caminho tambem podem estar envolvidos."

    if finding_type.startswith("rtp_"):
        return "Caminho de rede", "medium", "A evidencia aponta para degradacao entre os endpoints, sem atribuir falha a apenas um lado."

    if finding_type.startswith("ip_fragment") or "fragmentation" in finding_type:
        return "Origem ou caminho", "medium", "A origem gerou trafego fragmentado ou o caminho descartou fragmentos."

    if finding_type.startswith("tls_legacy"):
        return "Origem", "high", "O cliente de origem ofereceu uma versao TLS legada."

    if finding_type.startswith("sip_error_response"):
        return "Origem", "high", "O endpoint de origem enviou a resposta SIP de erro."

    if finding_type.startswith("icmp_"):
        return "Caminho de rede", "medium", "A mensagem ICMP foi emitida por um endpoint ou roteador no caminho."

    if finding_type.startswith("udp_"):
        return "Destino ou caminho", "medium", "Nao houve resposta observada do destino; o caminho pode ter bloqueado o trafego."

    return "Em investigacao", "low", "A captura nao permite atribuir a causa a um unico componente."
