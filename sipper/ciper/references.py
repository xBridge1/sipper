TCP_REFERENCE = {
    "title": "RFC 9293 - Transmission Control Protocol",
    "url": "https://datatracker.ietf.org/doc/html/rfc9293",
    "scope": "SYN, ACK, RST, retransmissoes, handshake e encerramento TCP.",
}
UDP_REFERENCE = {
    "title": "RFC 768 - User Datagram Protocol",
    "url": "https://datatracker.ietf.org/doc/html/rfc768",
    "scope": "Datagramas UDP, portas e ausencia de garantia de entrega.",
}
ICMP_REFERENCE = {
    "title": "RFC 792 - Internet Control Message Protocol",
    "url": "https://datatracker.ietf.org/doc/html/rfc792",
    "scope": "Mensagens de destino inacessivel, tempo excedido e diagnostico ICMP.",
}
SIP_REFERENCE = {
    "title": "RFC 3261 - SIP: Session Initiation Protocol",
    "url": "https://datatracker.ietf.org/doc/html/rfc3261",
    "scope": "INVITE, respostas SIP, ACK, BYE, CANCEL, headers e Call-ID.",
}
SDP_REFERENCE = {
    "title": "RFC 3264 - An Offer/Answer Model with SDP",
    "url": "https://datatracker.ietf.org/doc/html/rfc3264",
    "scope": "Direcoes sendrecv, sendonly, recvonly e inactive em ofertas e respostas SDP.",
}
FREESWITCH_INBOUND_REFERENCE = {
    "title": "FreeSWITCH - Inbound Calls and the Public Context",
    "url": "https://developer.signalwire.com/freeswitch/dialplan/public-context/",
    "scope": "Mapeamento de From, P-Asserted-Identity e Remote-Party-ID para identidade da chamada.",
}
FREESWITCH_SOFIA_REFERENCE = {
    "title": "FreeSWITCH - SIP Profiles with Sofia",
    "url": "https://developer.signalwire.com/freeswitch/users-and-endpoints/sip-profiles/",
    "scope": "Processamento de INVITE, headers, SDP e comportamento de hold no mod_sofia.",
}
FREESWITCH_VARIABLES_REFERENCE = {
    "title": "FreeSWITCH - Channel Variables Catalog",
    "url": "https://developer.signalwire.com/freeswitch/reference/channel-variables/",
    "scope": "Variaveis SIP, identidade, DTMF, endpoints de midia e headers recebidos como sip_h_.",
}
FREESWITCH_CALLCENTER_REFERENCE = {
    "title": "FreeSWITCH - Queues and mod_callcenter",
    "url": "https://developer.signalwire.com/freeswitch/applications/call-queues/",
    "scope": "Filas, agentes e processamento de chamadas pelo mod_callcenter.",
}
FREESWITCH_AUDIO_REFERENCE = {
    "title": "FreeSWITCH - No Audio and One-Way Audio",
    "url": "https://developer.signalwire.com/freeswitch/troubleshooting/audio/",
    "scope": "Diagnostico de enderecos SDP, NAT, ext-rtp-ip, ausencia e assimetria de RTP.",
}
SIP_TIMER_REFERENCE = {
    "title": "RFC 4028 - Session Timers in SIP",
    "url": "https://datatracker.ietf.org/doc/html/rfc4028",
    "scope": "Session-Expires, Min-SE, refresh de sessao e intervalo minimo de 90 segundos.",
}
DTMF_REFERENCE = {
    "title": "RFC 4733 - Telephony Events over RTP",
    "url": "https://datatracker.ietf.org/doc/html/rfc4733",
    "scope": "Negociacao e transporte de eventos DTMF por RTP usando telephone-event.",
}
RTP_REFERENCE = {
    "title": "RFC 3550 - RTP: A Transport Protocol for Real-Time Applications",
    "url": "https://datatracker.ietf.org/doc/html/rfc3550",
    "scope": "Sequencia RTP, timestamp, SSRC, payload type e monitoramento de entrega.",
}
TLS_REFERENCE = {
    "title": "RFC 8446 - The Transport Layer Security Protocol Version 1.3",
    "url": "https://datatracker.ietf.org/doc/html/rfc8446",
    "scope": "Records TLS, ClientHello, alertas e validacao de versao.",
}
IPV4_REFERENCE = {
    "title": "RFC 791 - Internet Protocol (IPv4)",
    "url": "https://datatracker.ietf.org/doc/html/rfc791",
    "scope": "Fragmentacao e remontagem de datagramas IPv4.",
}
IPV6_REFERENCE = {
    "title": "RFC 8200 - Internet Protocol, Version 6 (IPv6) Specification",
    "url": "https://datatracker.ietf.org/doc/html/rfc8200",
    "scope": "Header de fragmentacao e remontagem de pacotes IPv6.",
}
VOIP_QOS_REFERENCE = {
    "title": "Cisco VoIP QoS reference - loss below 1% and jitter below 30 ms",
    "url": "https://www.cisco.com/c/en/us/td/docs/solutions/Enterprise/Branch/BRBranch/BRBranch/BRB_CH2.html",
    "scope": "Faixas operacionais para perda de pacotes, jitter e qualidade de voz.",
}


def references_for_finding_type(finding_type):
    if finding_type.startswith("freeswitch_"):
        references = [FREESWITCH_SOFIA_REFERENCE]
        if any(token in finding_type for token in ("identity", "callcenter", "routing")):
            references.append(FREESWITCH_INBOUND_REFERENCE)
        if any(token in finding_type for token in ("header", "dtmf", "identity")):
            references.append(FREESWITCH_VARIABLES_REFERENCE)
        if any(token in finding_type for token in ("offer", "callcenter", "media")):
            references.append(SDP_REFERENCE)
        if "callcenter" in finding_type:
            references.append(FREESWITCH_CALLCENTER_REFERENCE)
        if "timer" in finding_type:
            references.append(SIP_TIMER_REFERENCE)
        if "dtmf" in finding_type:
            references.append(DTMF_REFERENCE)
        if "media" in finding_type:
            references.append(FREESWITCH_AUDIO_REFERENCE)
        return references

    if finding_type.startswith("tcp_"):
        return [TCP_REFERENCE]

    if finding_type.startswith("udp_"):
        return [UDP_REFERENCE, ICMP_REFERENCE]

    if finding_type.startswith("icmp_"):
        return [ICMP_REFERENCE]

    if finding_type.startswith("tls_"):
        return [TLS_REFERENCE, TCP_REFERENCE]

    if finding_type.startswith("ip_fragment"):
        return [IPV4_REFERENCE, IPV6_REFERENCE]

    if finding_type.startswith("rtcp_"):
        return [RTP_REFERENCE, VOIP_QOS_REFERENCE]

    if finding_type in {"rtp_payload_not_negotiated", "rtp_ptime_mismatch", "rtp_source_mismatch"}:
        return [RTP_REFERENCE, SDP_REFERENCE]

    if finding_type.startswith("rtp_"):
        references = [RTP_REFERENCE]
        if any(token in finding_type for token in ("loss", "jitter", "interruption", "out_of_order")):
            references.append(VOIP_QOS_REFERENCE)
        return references

    if finding_type.startswith("sip_"):
        references = [SIP_REFERENCE]
        if any(token in finding_type for token in ("rtp", "audio", "media")):
            references.append(RTP_REFERENCE)
        if finding_type in {"sip_retransmission", "sip_slow_call_setup"}:
            references.append(SIP_TIMER_REFERENCE)
        if finding_type == "sip_sdp_private_address":
            references.append(SDP_REFERENCE)
        if any(token in finding_type for token in ("fragment", "mtu")):
            references.extend([IPV4_REFERENCE, IPV6_REFERENCE])
        return references

    return [IPV4_REFERENCE]


def attach_references(findings):
    for finding in findings:
        if not finding.references:
            finding.references = [dict(reference) for reference in references_for_finding_type(finding.type)]
    return findings
