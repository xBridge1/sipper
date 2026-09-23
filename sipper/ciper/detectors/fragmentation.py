from ciper.findings import Finding


def detect_ip_fragmentation(groups):
    findings = []

    for group in groups.values():
        evidence = [
            f"IP identification: {group.identification}",
            f"IP protocol: {group.protocol}",
            f"Fragments observed: {group.fragment_count}",
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
                    description="Overlapping IP fragments were observed.",
                    evidence=evidence,
                    recommendation=(
                        "Check the source host and any middleboxes for malformed traffic, "
                        "fragment reassembly inconsistencies, or security policy violations."
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
                    description="An IP fragment set is incomplete or has missing fragment ranges.",
                    evidence=evidence,
                    recommendation=(
                        "Check MTU settings, packet loss, capture point coverage, and devices "
                        "that may be dropping fragmented traffic."
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
                description="A complete IP fragment set was observed.",
                evidence=evidence,
                recommendation=(
                    "Review MTU and application message sizes. Avoiding fragmentation improves "
                    "reliability because some network devices discard fragmented packets."
                ),
            )
        )

    return findings
