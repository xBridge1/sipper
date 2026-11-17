from ciper.findings import Finding


def detect_ip_fragmentation(groups):
    findings = []

    for group in groups.values():
        evidence = [
            f"IP identification: {group.identification}",
            f"IP protocol: {group.protocol}",
            f"Fragments observed: {group.fragment_count}",
            f"Duplicate fragments ignored: {group.duplicate_fragments}",
            f"Initial fragment observed: {'yes' if group.has_initial_fragment else 'no'}",
            f"Final fragment observed: {'yes' if group.has_final_fragment else 'no'}",
        ]

        if group.has_overlap:
            findings.append(
                Finding(
                    type="ip_fragment_overlap",
                    severity="high",
                    confidence=0.95,
                    source_ip=group.source_ip,
                    destination_ip=group.destination_ip,
                    description="Fragmentos IP sobrepostos foram observados.",
                    evidence=evidence,
                    recommendation=(
                        "Verifique o host de origem e equipamentos intermediarios quanto a trafego malformado, inconsistencias na remontagem ou violacoes de politica de seguranca."
                    ),
                )
            )
            continue

        if group.is_incomplete:
            findings.append(
                Finding(
                    type="ip_fragment_incomplete",
                    severity="medium",
                    confidence=0.85,
                    source_ip=group.source_ip,
                    destination_ip=group.destination_ip,
                    description="Um conjunto de fragmentos IP esta incompleto ou tem intervalos faltando.",
                    evidence=evidence,
                    recommendation=(
                        "Verifique MTU, perda de pacotes, cobertura do ponto de captura e equipamentos que possam descartar trafego fragmentado."
                    ),
                )
            )
            continue

        findings.append(
            Finding(
                type="ip_fragmentation",
                severity="low",
                confidence=0.95,
                source_ip=group.source_ip,
                destination_ip=group.destination_ip,
                description="Um conjunto completo de fragmentos IP foi observado.",
                evidence=evidence,
                recommendation=(
                    "Revise o MTU e o tamanho das mensagens da aplicacao. Evitar fragmentacao aumenta a confiabilidade, pois alguns equipamentos descartam pacotes fragmentados."
                ),
            )
        )

    return findings
