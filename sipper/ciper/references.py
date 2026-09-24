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

    if finding_type.startswith("rtp_"):
        references = [RTP_REFERENCE]
        if any(token in finding_type for token in ("loss", "jitter", "interruption", "out_of_order")):
            references.append(VOIP_QOS_REFERENCE)
        return references

    if finding_type.startswith("sip_"):
        references = [SIP_REFERENCE]
        if any(token in finding_type for token in ("rtp", "audio", "media")):
            references.append(RTP_REFERENCE)
        if any(token in finding_type for token in ("fragment", "mtu")):
            references.extend([IPV4_REFERENCE, IPV6_REFERENCE])
        return references

    return [IPV4_REFERENCE]


def attach_references(findings):
    for finding in findings:
        if not finding.references:
            finding.references = [dict(reference) for reference in references_for_finding_type(finding.type)]
    return findings
