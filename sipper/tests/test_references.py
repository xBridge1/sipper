from ciper.findings import Finding
from ciper.references import attach_references, references_for_finding_type


def test_reference_catalog_covers_detector_categories():
    finding_types = [
        "tcp_reset",
        "udp_no_response",
        "icmp_destination_unreachable",
        "tls_fatal_alert",
        "ip_fragment_incomplete",
        "sip_content_length_mismatch",
        "rtp_packet_loss",
    ]

    for finding_type in finding_types:
        references = references_for_finding_type(finding_type)
        assert references
        assert all(reference["url"].startswith("https://") for reference in references)


def test_attach_references_populates_finding():
    finding = Finding(
        type="rtp_high_jitter",
        severity="high",
        confidence=0.9,
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        description="High jitter",
    )

    attach_references([finding])

    assert finding.references[0]["title"].startswith("RFC 3550")
    assert len(finding.references) == 2
