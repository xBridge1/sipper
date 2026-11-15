"""Human-readable Portuguese labels for findings, severities and call states.

The engine keeps stable machine identifiers (``rtp_high_jitter``); the GUI and
reports show these labels instead, with the identifier kept as secondary
information for searches and support tickets.
"""

FINDING_TITLES = {
    # TCP
    "tcp_syn_failure": "Conexao TCP sem resposta (SYN)",
    "tcp_handshake_incomplete": "Handshake TCP incompleto",
    "tcp_handshake_reset": "Conexao TCP recusada (RST no handshake)",
    "tcp_slow_handshake": "Handshake TCP lento",
    "tcp_retransmission": "Retransmissao TCP",
    "tcp_reset": "Conexao TCP encerrada por RST",
    # UDP
    "udp_no_response": "UDP sem resposta",
    "udp_burst_no_response": "Rajada UDP sem resposta",
    "udp_service_unreachable": "Servico UDP inalcancavel",
    # ICMP
    "icmp_no_response": "Ping sem resposta",
    "icmp_destination_unreachable": "Destino inalcancavel (ICMP)",
    "icmp_host_unreachable": "Host inalcancavel (ICMP)",
    "icmp_network_unreachable": "Rede inalcancavel (ICMP)",
    "icmp_fragmentation_needed": "Fragmentacao necessaria / MTU (ICMP)",
    "icmp_admin_prohibited": "Bloqueado administrativamente (ICMP)",
    "icmp_time_exceeded": "TTL expirado (ICMP)",
    "icmp_redirect": "Redirecionamento ICMP",
    "icmp_parameter_problem": "Cabecalho IP invalido (ICMP)",
    # SIP
    "sip_call_established": "Chamada estabelecida",
    "sip_call_terminated": "Chamada encerrada",
    "sip_call_cancelled": "Chamada cancelada",
    "sip_error_response": "Erro SIP na resposta",
    "sip_invite_no_response": "INVITE sem resposta",
    "sip_ok_without_ack": "200 OK sem ACK",
    "sip_register_failure": "Falha no REGISTER",
    "sip_transfer_failure": "Falha na transferencia (REFER)",
    "sip_options_no_response": "OPTIONS sem resposta",
    "sip_large_header": "Cabecalho SIP muito grande",
    "sip_invalid_header": "Cabecalho SIP invalido",
    "sip_content_length_mismatch": "Content-Length divergente",
    "sip_header_fragmentation_risk": "Risco de fragmentacao do cabecalho SIP",
    "sip_udp_fragmentation_risk": "SIP/UDP acima do MTU seguro",
    "sip_signaling_fragmentation": "Sinalizacao SIP fragmentada",
    "sip_call_established_without_rtp": "Chamada sem audio (sem RTP)",
    "sip_call_one_way_audio": "Chamada com audio em uma via",
    # RTP
    "rtp_packet_loss": "Perda de pacotes RTP",
    "rtp_high_jitter": "Jitter alto no RTP",
    "rtp_out_of_order": "Pacotes RTP fora de ordem",
    "rtp_timestamp_anomaly": "Timestamp RTP anomalo",
    "rtp_stream_interruption": "Interrupcao no stream RTP",
    "rtp_payload_type_change": "Troca de codec (payload type)",
    "rtp_ssrc_change": "Troca de SSRC no stream",
    "rtp_one_way_audio": "Audio em uma via",
    "rtp_without_sip": "RTP sem sinalizacao SIP",
    "rtp_after_bye": "RTP apos BYE",
    # TLS
    "tls_fatal_alert": "Alerta TLS fatal",
    "tls_client_hello_no_response": "TLS ClientHello sem resposta",
    "tls_legacy_version": "Versao TLS obsoleta",
    "tls_malformed_record": "Registro TLS malformado",
    "tls_weak_cipher_suite": "Cifra TLS fraca",
    # Fragmentacao IP
    "ip_fragmentation": "Fragmentacao IP",
    "ip_fragment_incomplete": "Fragmentos IP incompletos",
    "ip_fragment_overlap": "Fragmentos IP sobrepostos",
    # FreeSWITCH
    "freeswitch_anonymous_caller_identity": "Chamador anonimo (FreeSWITCH)",
    "freeswitch_callcenter_input_risk": "Risco no mod_callcenter",
    "freeswitch_custom_header_input": "Header SIP personalizado (FreeSWITCH)",
    "freeswitch_dtmf_negotiation_risk": "Negociacao DTMF arriscada",
    "freeswitch_inactive_initial_offer": "Oferta SDP inativa",
    "freeswitch_routing_target_mismatch": "Destino de roteamento divergente",
    "freeswitch_session_timer_risk": "Risco de session timer",
    "freeswitch_unidirectional_initial_offer": "Oferta SDP unidirecional",
    "freeswitch_unusable_media_address": "Endereco de midia inutilizavel",
}

# Findings that describe normal call progress rather than a problem.
INFORMATIONAL_FINDINGS = {
    "sip_call_established",
    "sip_call_terminated",
}

SEVERITY_LABELS = {
    "high": "Alta",
    "medium": "Media",
    "low": "Baixa",
    "info": "Info",
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

STATE_LABELS = {
    "established": "Estabelecida",
    "terminated": "Encerrada",
    "cancelled": "Cancelada",
    "failed": "Falhou",
    "missing_ack": "Sem ACK",
    "no_response": "Sem resposta",
    "incomplete": "Incompleta",
    "media_present": "Midia presente",
    "no_media": "Sem midia",
    "one_way_media": "Midia em uma via",
    "degraded_media": "Midia degradada",
    "inactive_media": "Midia inativa",
    "bidirectional": "Bidirecional",
    "unidirectional": "Unidirecional",
    "inactive": "Inativa",
    "good": "Boa",
    "degraded": "Degradada",
    "poor": "Ruim",
    "unknown": "Desconhecido",
}


def finding_title(finding_type):
    if not finding_type:
        return "Sem incidente"
    title = FINDING_TITLES.get(finding_type)
    if title:
        return title
    return finding_type.replace("_", " ").capitalize()


def display_severity(finding_type, severity):
    """Severity shown to the user; normal call progress is shown as Info."""
    if finding_type in INFORMATIONAL_FINDINGS:
        return "info"
    return severity


def severity_label(severity):
    return SEVERITY_LABELS.get(severity, str(severity).capitalize())


def state_label(state):
    if not state:
        return "-"
    return STATE_LABELS.get(state, str(state).replace("_", " ").capitalize())


def is_actionable(finding):
    """True when a viewmodel finding describes a problem worth acting on."""
    return finding.get("type") not in INFORMATIONAL_FINDINGS
