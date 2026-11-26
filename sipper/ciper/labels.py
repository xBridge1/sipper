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
    "sip_retransmission": "Retransmissao de sinalizacao SIP",
    "sip_slow_call_setup": "Post-dial delay alto",
    "sip_sdp_private_address": "IP privado no SDP (NAT)",
    "sip_header_control_characters": "Caractere de controle no header SIP",
    "sip_header_invalid_encoding": "Header SIP com encoding invalido (nao UTF-8)",
    "sip_header_non_ascii": "Acentos/UTF-8 em header de identidade",
    "sip_header_duplicate_singleton": "Header SIP duplicado",
    "sip_header_missing_mandatory": "Header SIP obrigatorio ausente",
    "sip_header_missing_max_forwards": "Max-Forwards ausente",
    "sip_header_missing_contact": "Contact ausente",
    "sip_header_cseq_mismatch": "CSeq invalido ou divergente",
    "sip_header_max_forwards": "Max-Forwards esgotado ou invalido",
    "sip_header_variable_injection": "Possivel injecao de variavel FreeSWITCH (${...})",
    "sip_header_malformed_address": "From/To/Contact malformado",
    "sip_header_require_unsupported": "Require com extensao nao suportada",
    "sip_header_content_encoding": "Corpo SIP comprimido (Content-Encoding)",
    "sip_header_missing_content_type": "Corpo sem Content-Type",
    "sip_header_tcp_missing_content_length": "SIP/TCP sem Content-Length",
    "sip_header_bare_lf": "Quebra de linha LF sem CR",
    "sip_header_folding": "Header SIP em varias linhas (folding)",
    "sip_header_invalid_name": "Nome de header invalido",
    "sip_header_missing_from_tag": "From sem tag",
    "sip_header_invalid_version": "Versao SIP invalida",
    "sip_request_uri_invalid": "Request-URI invalida",
    "sip_sdp_malformed": "SDP malformado ou incompleto",
    "sip_sdp_dynamic_payload_without_rtpmap": "Payload dinamico sem rtpmap no SDP",
    "sip_sdp_secure_transport": "Oferta SRTP/DTLS no SDP",
    "sip_abnormal_hangup": "Chamada derrubada (causa Q.850 anormal)",
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
    "rtp_payload_not_negotiated": "Codec RTP nao negociado no SDP",
    "rtp_ptime_mismatch": "Ptime diferente do negociado",
    "rtp_source_mismatch": "RTP de origem diferente do SDP",
    "rtp_silent_audio": "Audio mudo (RTP com silencio digital)",
    "sip_sdp_answer_media_count": "Resposta SDP com linhas m= divergentes",
    "sip_sdp_no_common_codec": "Sem codec de voz em comum no SDP",
    "sip_sdp_answer_codec_not_offered": "Resposta SDP com codec nao ofertado",
    "sip_sdp_dtmf_not_negotiated": "DTMF (telephone-event) removido na resposta",
    "sip_sdp_dtmf_payload_mismatch": "Payload DTMF diferente entre oferta e resposta",
    "sip_sdp_direction_mismatch": "Direcao SDP invalida na resposta",
    "sip_contact_private_address": "Contact com IP privado (NAT)",
    "sip_register_auth_rejected": "REGISTER com credenciais recusadas",
    "sip_register_expires_nat": "Registro longo demais atras de NAT",
    "sip_tls_signaling": "Sinalizacao SIP cifrada (TLS)",
    "freeswitch_codec_mismatch": "Nenhum codec aceito pelo FreeSWITCH",
    "freeswitch_profile_extension_disabled": "Extensao exigida desabilitada no FreeSWITCH",
    "freeswitch_srtp_disabled": "SRTP exigido e desabilitado no FreeSWITCH",
    # RTCP
    "rtcp_reported_loss": "Perda reportada pelo RTCP",
    "rtcp_reported_jitter": "Jitter reportado pelo RTCP",
    "rtcp_high_rtt": "RTT alto (RTCP)",
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
    "freeswitch_callcenter_midcall_hold": "Hold no meio da chamada (mod_callcenter)",
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
    "silent_media": "Audio mudo",
    "inactive_media": "Midia inativa",
    "bidirectional": "Bidirecional",
    "unidirectional": "Unidirecional",
    "inactive": "Inativa",
    "good": "Boa",
    "degraded": "Degradada",
    "poor": "Ruim",
    "unknown": "Desconhecido",
}

VERDICT_STATUS_LABELS = {
    "fail": "Falha",
    "degraded": "Degradada",
    "risk": "Risco",
    "user": "Resultado normal",
    "ok": "OK",
}


def verdict_status_label(status):
    return VERDICT_STATUS_LABELS.get(status, str(status or "-").capitalize())


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


# Evidence lines keep stable English keys in the engine (they are parsed, e.g.
# "Call-ID: ..."); only the displayed text is translated.
EVIDENCE_LABELS = {
    "Sender": "Enviado por",
    "Offer": "Oferta",
    "Answer": "Resposta",
    "Offer m-lines": "Linhas m= na oferta",
    "Answer m-lines": "Linhas m= na resposta",
    "Offered codecs": "Codecs ofertados",
    "Answered codecs": "Codecs da resposta",
    "Offered telephone-event PT": "PT telephone-event ofertado",
    "Answered telephone-event PT": "PT telephone-event da resposta",
    "Answered telephone-event": "telephone-event na resposta",
    "Offer direction": "Direcao da oferta",
    "Answer direction": "Direcao da resposta",
    "Contact": "Contact",
    "User": "Usuario",
    "Authenticated attempts rejected": "Tentativas autenticadas recusadas",
    "Expires": "Expires",
    "TLS session": "Sessao TLS",
    "SNI": "SNI",
    "FreeSWITCH codecs": "Codecs do FreeSWITCH",
    "Require": "Require",
    "G.711 packets": "Pacotes G.711",
    "Silent packets": "Pacotes em silencio",
    "Q.850 cause": "Causa Q.850",
    "Blame": "Lado apontado",
    "Hangup by": "Desligada por",
    "Call duration before BYE": "Duracao ate o BYE",
    "Receiver": "Recebido por",
    "Headers": "Headers",
    "Encoding": "Encoding",
    "Duplicated headers": "Headers duplicados",
    "Missing headers": "Headers ausentes",
    "Request method": "Metodo da requisicao",
    "Pattern": "Padrao",
    "Malformed headers": "Headers malformados",
    "Unquoted display names": "Display names sem aspas",
    "Request-URI": "Request-URI",
    "Problem": "Problema",
    "Transport": "Transporte",
    "Invalid header names": "Nomes de header invalidos",
    "LF-only lines": "Linhas so com LF",
    "Folded lines": "Linhas continuadas",
    "SIP version": "Versao SIP",
    "SDP problem": "Problema no SDP",
    "Payload types without rtpmap": "Payload types sem rtpmap",
    "Media profile": "Perfil de midia",
    "Unsupported option tags": "Option tags nao suportadas",
    "Messages affected": "Mensagens afetadas",
    "Peer response": "Resposta do destino",
    "Status": "Status",
    "Rejected by": "Recusado por",
    "Requested by": "Requisitado por",
    "Meaning": "Significado",
    "FreeSWITCH hangup cause": "Hangup cause no FreeSWITCH",
    "Response Reason": "Reason na resposta",
    "Response Warning": "Warning na resposta",
    "Response Unsupported": "Unsupported na resposta",
    "Response X-Reason": "X-Reason na resposta",
    "200 OK responses": "Respostas 200 OK",
    "ACK observed": "ACK observado",
    "ACKs": "ACKs",
    "Affected area": "Area afetada",
    "Affected variables": "Variaveis afetadas",
    "Alert direction": "Direcao do alerta",
    "Asserted identity available": "Identidade assertada disponivel",
    "Audio codecs": "Codecs de audio",
    "Average RTT": "RTT medio",
    "Average jitter (RFC 3550)": "Jitter medio (RFC 3550)",
    "Cumulative lost": "Perda acumulada",
    "Max RTT": "RTT maximo",
    "Max fraction lost": "Maior fracao perdida",
    "Message": "Mensagem",
    "Negotiated payload types": "Payload types negociados",
    "Observed ptime": "Ptime observado",
    "Post-dial delay": "Post-dial delay",
    "RTCP reports": "Relatorios RTCP",
    "RTP source": "Origem do RTP",
    "Reported by": "Reportado por",
    "Reported jitter": "Jitter reportado",
    "Ringing response": "Resposta de toque",
    "SDP audio endpoints": "Endpoints de audio no SDP",
    "SDP ptime": "Ptime no SDP",
    "Signaling source": "Origem da sinalizacao",
    "BYE method observed": "Metodo BYE observado",
    "Burst duration": "Duracao da rajada",
    "ClientHello messages": "Mensagens ClientHello",
    "Content-Length mismatches": "Content-Length divergentes",
    "Custom SIP headers": "Headers SIP personalizados",
    "Destination port": "Porta de destino",
    "Destination": "Destino",
    "Direction": "Direcao",
    "Duplicate fragments ignored": "Fragmentos duplicados ignorados",
    "Duplicate packets": "Pacotes duplicados",
    "Echo replies": "Echo replies",
    "Echo requests": "Echo requests",
    "Expected packets": "Pacotes esperados",
    "Fatal alert": "Alerta fatal",
    "Final fragment observed": "Fragmento final observado",
    "Forward packets": "Pacotes no sentido direto",
    "Fragmented SIP messages": "Mensagens SIP fragmentadas",
    "Fragments observed": "Fragmentos observados",
    "Handshake time": "Tempo de handshake",
    "Header fragmentation risks": "Riscos de fragmentacao do header",
    "Header threshold": "Limite de header",
    "ICMP finding": "Finding ICMP",
    "Identity header": "Header de identidade",
    "Identity trust": "Confianca da identidade",
    "Identity value": "Valor da identidade",
    "Initial INVITE": "INVITE inicial",
    "Initial fragment observed": "Fragmento inicial observado",
    "Interruptions": "Interrupcoes",
    "Longest gap": "Maior intervalo",
    "Loss": "Perda",
    "Lost packets": "Pacotes perdidos",
    "Malformed records": "Registros malformados",
    "Max jitter": "Jitter maximo",
    "Max jitter (RFC 3550)": "Jitter maximo (RFC 3550)",
    "Media after BYE": "Midia apos BYE",
    "Messages with invalid headers": "Mensagens com headers invalidos",
    "Messages with large headers": "Mensagens com headers grandes",
    "Negotiated weak cipher": "Cifra fraca negociada",
    "Out-of-order packets": "Pacotes fora de ordem",
    "Oversized SIP/UDP messages": "Mensagens SIP/UDP grandes demais",
    "Oversized header blocks": "Blocos de header grandes demais",
    "Packet path": "Caminho do pacote",
    "Packets in flow": "Pacotes no fluxo",
    "Packets observed": "Pacotes observados",
    "Packets sent": "Pacotes enviados",
    "Parameter problem messages": "Mensagens parameter problem",
    "Payload types": "Payload types",
    "Peak transit variation": "Pico de variacao de transito",
    "Provisional responses": "Respostas provisorias",
    "RFC 4028 minimum": "Minimo da RFC 4028",
    "RST observed during handshake": "RST observado no handshake",
    "RST observed": "RST observado",
    "RTP finding": "Finding RTP",
    "RTP streams observed": "Streams RTP observados",
    "RTP streams": "Streams RTP",
    "Redirect messages": "Mensagens redirect",
    "Related IP fragment sets": "Conjuntos de fragmentos IP relacionados",
    "Response packets": "Pacotes de resposta",
    "Response": "Resposta",
    "Retransmissions": "Retransmissoes",
    "Retransmission rate": "Taxa de retransmissao",
    "Reverse packets": "Pacotes no sentido reverso",
    "SDP audio endpoint": "Endpoint de audio no SDP",
    "SDP direction": "Direcao no SDP",
    "SIP INFO allowed": "SIP INFO permitido",
    "SIP request recognized": "Requisicao SIP reconhecida",
    "Safe message threshold": "Limite seguro de mensagem",
    "Sequence": "Sequencia",
    "ServerHello messages": "Mensagens ServerHello",
    "Source port": "Porta de origem",
    "Source": "Origem",
    "TCP reset observed": "Reset TCP observado",
    "TCP-segmented SIP messages": "Mensagens SIP segmentadas em TCP",
    "Time Exceeded messages": "Mensagens time exceeded",
    "Timestamp anomalies": "Anomalias de timestamp",
    "UDP finding": "Finding UDP",
    "Unacknowledged CSeq": "CSeq sem ACK",
    "Unique packets": "Pacotes unicos",
    "Unreachable messages": "Mensagens unreachable",
    "Versions": "Versoes",
    "Weak cipher suites": "Cipher suites fracas",
}

EVIDENCE_VALUES = {
    "requester": "quem fez a requisicao",
    "responder": "quem respondeu",
    "negotiation": "negociacao entre os lados",
    "downstream": "rede/servidor depois de quem respondeu",
    "user": "usuario (resultado normal)",
    "yes": "sim",
    "no": "nao",
    "none": "nenhum",
}


def evidence_label(item):
    """Portuguese display text for an engine evidence line."""
    text = str(item)
    key, separator, value = text.partition(": ")
    if not separator:
        return text
    label = EVIDENCE_LABELS.get(key)
    if label is None:
        return text
    value = EVIDENCE_VALUES.get(value.strip(), value)
    value = value.replace(" seconds", " segundos").replace(" (from ", " (de ")
    value = value.replace("not valid UTF-8 (probably Latin-1)", "nao e UTF-8 valido (provavelmente Latin-1)")
    return f"{label}: {value}"


def evidence_labels(items):
    return [evidence_label(item) for item in items]
