from ciper.findings import Finding
from ciper.tls import TLS_CIPHER_SUITE_NAMES, TLS_WEAK_CIPHER_SUITES


def detect_tls_fatal_alerts(flows):
    findings = []

    for flow in flows.values():
        if not flow.fatal_alerts:
            continue

        direction, alert = flow.fatal_alerts[0]
        source_ip = flow.source_ip if direction == "forward" else flow.destination_ip
        destination_ip = flow.destination_ip if direction == "forward" else flow.source_ip
        findings.append(
            Finding(
                type="tls_fatal_alert",
                severity="high",
                confidence=0.98,
                source_ip=source_ip,
                destination_ip=destination_ip,
                description="A negociacao TLS terminou com um alerta fatal.",
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Alert direction: {direction}",
                    f"Fatal alert: {alert}",
                ],
                recommendation=(
                    "Verifique a confianca do certificado, versoes TLS e cipher suites suportadas, configuracao de nome do servidor e equipamentos de inspecao TLS."
                ),
            )
        )

    return findings


def detect_tls_client_hello_no_response(flows):
    findings = []

    for flow in flows.values():
        if flow.client_hello_count == 0 or flow.server_hello_count > 0:
            continue

        findings.append(
            Finding(
                type="tls_client_hello_no_response",
                severity="high" if flow.reset else "medium",
                confidence=0.90 if flow.reset else 0.75,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="ClientHello TLS foi observado sem resposta ServerHello.",
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"ClientHello messages: {flow.client_hello_count}",
                    f"ServerHello messages: {flow.server_hello_count}",
                    f"TCP reset observed: {'yes' if flow.reset else 'no'}",
                ],
                recommendation=(
                    "Verifique se o servico TLS e alcancavel, se firewall ou proxy bloqueia o handshake e se o servidor aceita o SNI e a versao TLS solicitados."
                ),
            )
        )

    return findings


def detect_tls_legacy_versions(flows):
    findings = []

    for flow in flows.values():
        if not flow.legacy_versions:
            continue

        findings.append(
            Finding(
                type="tls_legacy_version",
                severity="medium",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="Uma versao TLS obsoleta foi proposta no handshake.",
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Versions: {', '.join(sorted(flow.legacy_versions))}",
                ],
                recommendation=(
                    "Desabilite TLS 1.0 e 1.1 quando possivel e configure os dois endpoints para negociar TLS 1.2 ou TLS 1.3."
                ),
            )
        )

    return findings


def detect_tls_malformed_records(flows):
    findings = []

    for flow in flows.values():
        if flow.malformed_records == 0:
            continue

        findings.append(
            Finding(
                type="tls_malformed_record",
                severity="medium",
                confidence=0.80,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="Registros TLS com cabecalho ou tamanho invalido foram observados.",
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Malformed records: {flow.malformed_records}",
                ],
                recommendation=(
                    "Verifique corrupcao de pacotes, incompatibilidade de protocolo, problemas de inspecao TLS ou um servico falando outro protocolo nesta porta."
                ),
            )
        )

    return findings


def detect_tls_weak_cipher_suites(flows):
    findings = []

    for flow in flows.values():
        offered_weak = sorted(flow.offered_cipher_suites & TLS_WEAK_CIPHER_SUITES)
        negotiated_weak = flow.negotiated_cipher_suite in TLS_WEAK_CIPHER_SUITES
        if not offered_weak and not negotiated_weak:
            continue

        weak_names = [TLS_CIPHER_SUITE_NAMES.get(cipher, f"0x{cipher:04X}") for cipher in offered_weak]
        if negotiated_weak:
            weak_names.append(TLS_CIPHER_SUITE_NAMES.get(flow.negotiated_cipher_suite, f"0x{flow.negotiated_cipher_suite:04X}"))

        findings.append(
            Finding(
                type="tls_weak_cipher_suite",
                severity="high" if negotiated_weak else "medium",
                confidence=0.95,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description="A negociacao TLS ofereceu ou selecionou cipher suites obsoletas.",
                evidence=[
                    f"Source: {flow.source_ip}:{flow.source_port}",
                    f"Destination: {flow.destination_ip}:{flow.destination_port}",
                    f"Weak cipher suites: {', '.join(dict.fromkeys(weak_names))}",
                    f"Negotiated weak cipher: {'yes' if negotiated_weak else 'no'}",
                ],
                recommendation=(
                    "Desabilite cipher suites RC4 e 3DES e prefira suites modernas de TLS 1.2 ou TLS 1.3 nos dois endpoints."
                ),
            )
        )

    return findings
