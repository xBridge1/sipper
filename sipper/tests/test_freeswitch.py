from scapy.layers.inet import IP, UDP

from ciper.engine import analyze_pcap
from ciper.settings import AnalysisSettings
from ciper.sip import parse_sip_message


def _sip_packet(payload, source="198.51.100.10", destination="10.0.0.20", timestamp=1.0):
    packet = IP(src=source, dst=destination) / UDP(sport=5060, dport=5060) / payload
    packet.time = timestamp
    return packet


def _settings(target_ips="10.0.0.20"):
    return AnalysisSettings(
        target_platform="freeswitch",
        target_platform_ips=target_ips,
    )


def test_sip_parser_preserves_normalized_headers_for_platform_analysis():
    packet = _sip_packet(
        b"INVITE sip:100@example.test SIP/2.0\r\n"
        b"Call-ID: fs-headers\r\n"
        b"From: Anonymous <sip:anonymous@anonymous.invalid>;tag=caller\r\n"
        b"P-Asserted-Identity: <sip:5511999999999@carrier.test>\r\n"
        b"X-Carrier-Route: premium\r\n"
        b"CSeq: 1 INVITE\r\n\r\n"
    )

    message = parse_sip_message(packet)

    assert message.headers["from"].startswith("Anonymous")
    assert message.headers["p-asserted-identity"] == "<sip:5511999999999@carrier.test>"
    assert message.headers["x-carrier-route"] == "premium"
    assert message.request_uri == "sip:100@example.test"


def test_freeswitch_profile_flags_anonymous_sendonly_initial_invite():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: fs-callcenter-risk\r\n"
        b"From: Anonymous <sip:anonymous@anonymous.invalid>;tag=caller\r\n"
        b"CSeq: 1 INVITE\r\n"
        b"Content-Type: application/sdp\r\n\r\n"
        b"v=0\r\n"
        b"c=IN IP4 198.51.100.10\r\n"
        b"m=audio 4000 RTP/AVP 0\r\n"
        b"a=sendonly\r\n"
    )

    result = analyze_pcap([packet], _settings())
    findings = [
        finding
        for finding in result["findings"]
        if finding.type == "freeswitch_callcenter_input_risk"
    ]

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].source_ip == "198.51.100.10"
    assert findings[0].destination_ip == "10.0.0.20"
    assert any(item.startswith("Dialog-Key: ") for item in findings[0].evidence)
    assert "SDP direction: sendonly" in findings[0].evidence
    assert "Asserted identity available: no" in findings[0].evidence
    assert any("developer.signalwire.com/freeswitch" in item["url"] for item in findings[0].references)


def test_generic_profile_does_not_emit_freeswitch_findings():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: generic-call\r\n"
        b"From: <sip:anonymous@anonymous.invalid>;tag=caller\r\n"
        b"CSeq: 1 INVITE\r\n\r\n"
        b"v=0\r\nm=audio 4000 RTP/AVP 0\r\na=sendonly\r\n"
    )

    result = analyze_pcap([packet])

    assert not any(finding.type.startswith("freeswitch_") for finding in result["findings"])


def test_freeswitch_profile_only_checks_invites_addressed_to_configured_system():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: another-system\r\n"
        b"From: <sip:anonymous@anonymous.invalid>;tag=caller\r\n"
        b"CSeq: 1 INVITE\r\n\r\n"
        b"v=0\r\nm=audio 4000 RTP/AVP 0\r\na=sendonly\r\n",
        destination="10.0.0.30",
    )

    result = analyze_pcap([packet], _settings())

    assert not any(finding.type.startswith("freeswitch_") for finding in result["findings"])


def test_freeswitch_profile_does_not_treat_sendonly_reinvite_as_initial_offer_risk():
    initial = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: normal-hold\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"CSeq: 1 INVITE\r\n\r\n"
        b"v=0\r\nm=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n",
        timestamp=1.0,
    )
    hold = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: normal-hold\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"CSeq: 2 INVITE\r\n\r\n"
        b"v=0\r\nm=audio 4000 RTP/AVP 0\r\na=sendonly\r\n",
        timestamp=2.0,
    )

    result = analyze_pcap([initial, hold], _settings())

    assert not any(
        finding.type in {
            "freeswitch_callcenter_input_risk",
            "freeswitch_unidirectional_initial_offer",
        }
        for finding in result["findings"]
    )


def test_freeswitch_profile_reports_custom_invite_headers_as_dialplan_inputs():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: custom-input\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"CSeq: 1 INVITE\r\n"
        b"X-Carrier-Route: premium\r\n"
        b"X-Customer-ID: 42\r\n\r\n"
        b"v=0\r\nm=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n"
    )

    result = analyze_pcap([packet], _settings())
    finding = next(
        finding
        for finding in result["findings"]
        if finding.type == "freeswitch_custom_header_input"
    )

    assert finding.severity == "low"
    assert "Custom SIP headers: X-Carrier-Route, X-Customer-Id" in finding.evidence
    assert "sip_h_" in finding.description


def test_freeswitch_profile_flags_sendonly_offer_with_identified_caller():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: one-way-offer\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"CSeq: 1 INVITE\r\n\r\n"
        b"v=0\r\nm=audio 4000 RTP/AVP 0\r\na=sendonly\r\n"
    )

    result = analyze_pcap([packet], _settings())
    finding = next(
        finding
        for finding in result["findings"]
        if finding.type == "freeswitch_unidirectional_initial_offer"
    )

    assert finding.severity == "medium"
    assert "SDP direction: sendonly" in finding.evidence


def test_freeswitch_profile_flags_anonymous_identity_without_asserted_identity():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: anonymous-only\r\n"
        b"From: <sip:anonymous@anonymous.invalid>;tag=caller\r\n"
        b"CSeq: 1 INVITE\r\n\r\n"
        b"v=0\r\nm=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n"
    )

    result = analyze_pcap([packet], _settings())
    finding = next(
        finding
        for finding in result["findings"]
        if finding.type == "freeswitch_anonymous_caller_identity"
    )

    assert finding.severity == "medium"
    assert "Affected variables: caller_id_number and sip_from_user" in finding.evidence


def test_freeswitch_profile_accepts_target_networks():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: cidr-target\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"CSeq: 1 INVITE\r\n\r\n"
        b"v=0\r\nm=audio 0 RTP/AVP 0\r\na=inactive\r\n"
    )

    result = analyze_pcap([packet], _settings("10.0.0.0/24"))

    assert any(
        finding.type == "freeswitch_inactive_initial_offer"
        for finding in result["findings"]
    )
    assert result["analysis_profile"] == {
        "target_platform": "freeswitch",
        "target_platform_ips": "10.0.0.0/24",
    }


def test_freeswitch_profile_maps_request_uri_and_reports_routing_mismatch():
    packet = _sip_packet(
        b"INVITE sip:5000@pbx.example.test SIP/2.0\r\n"
        b"Call-ID: routing-mismatch\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"To: <sip:6000@pbx.example.test>\r\n"
        b"CSeq: 1 INVITE\r\n\r\n"
        b"v=0\r\nc=IN IP4 198.51.100.10\r\nm=audio 4000 RTP/AVP 0\r\n"
    )

    result = analyze_pcap([packet], _settings())
    finding = next(
        finding
        for finding in result["findings"]
        if finding.type == "freeswitch_routing_target_mismatch"
    )

    assert finding.severity == "low"
    assert "destination_number: 5000" in finding.evidence
    assert "sip_to_user: 6000" in finding.evidence


def test_freeswitch_profile_accepts_preferred_identity_for_anonymous_caller():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: preferred-identity\r\n"
        b"From: Anonymous <sip:anonymous@anonymous.invalid>;tag=caller\r\n"
        b"P-Preferred-Identity: <sip:5511999999999@carrier.test>\r\n"
        b"Privacy: id\r\n"
        b"CSeq: 1 INVITE\r\n\r\n"
    )

    result = analyze_pcap([packet], _settings())
    finding = next(
        finding
        for finding in result["findings"]
        if finding.type == "freeswitch_anonymous_caller_identity"
    )

    assert finding.severity == "medium"
    assert "Identity header: P-Preferred-Identity" in finding.evidence
    assert "Identity trust: preferred, not asserted" in finding.evidence
    assert "Privacy: id" in finding.evidence


def test_freeswitch_profile_flags_session_timer_below_rfc_minimum():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: short-session-timer\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"Session-Expires: 60;refresher=uac\r\n"
        b"Min-SE: 60\r\n"
        b"CSeq: 1 INVITE\r\n\r\n"
    )

    result = analyze_pcap([packet], _settings())
    finding = next(
        finding
        for finding in result["findings"]
        if finding.type == "freeswitch_session_timer_risk"
    )

    assert finding.severity == "medium"
    assert "Session-Expires: 60 seconds" in finding.evidence
    assert "RFC 4028 minimum: 90 seconds" in finding.evidence


def test_freeswitch_profile_flags_missing_dtmf_transport_for_interactive_call():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: no-dtmf-method\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"Allow: INVITE, ACK, BYE, OPTIONS\r\n"
        b"CSeq: 1 INVITE\r\n"
        b"Content-Type: application/sdp\r\n\r\n"
        b"v=0\r\nc=IN IP4 198.51.100.10\r\nm=audio 4000 RTP/AVP 0\r\n"
        b"a=rtpmap:0 PCMU/8000\r\n"
    )

    result = analyze_pcap([packet], _settings())
    finding = next(
        finding
        for finding in result["findings"]
        if finding.type == "freeswitch_dtmf_negotiation_risk"
    )

    assert finding.severity == "medium"
    assert "telephone-event offered: no" in finding.evidence
    assert "SIP INFO allowed: no" in finding.evidence


def test_freeswitch_profile_does_not_flag_dtmf_when_telephone_event_is_offered():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: rfc4733-dtmf\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"Allow: INVITE, ACK, BYE, OPTIONS\r\n"
        b"CSeq: 1 INVITE\r\n"
        b"Content-Type: application/sdp\r\n\r\n"
        b"v=0\r\nc=IN IP4 198.51.100.10\r\nm=audio 4000 RTP/AVP 0 101\r\n"
        b"a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
    )

    result = analyze_pcap([packet], _settings())

    assert not any(
        finding.type == "freeswitch_dtmf_negotiation_risk"
        for finding in result["findings"]
    )


def test_freeswitch_profile_flags_unspecified_active_media_address():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: unusable-media-address\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"CSeq: 1 INVITE\r\n"
        b"Content-Type: application/sdp\r\n\r\n"
        b"v=0\r\nc=IN IP4 0.0.0.0\r\nm=audio 4000 RTP/AVP 0\r\na=sendrecv\r\n"
    )

    result = analyze_pcap([packet], _settings())
    finding = next(
        finding
        for finding in result["findings"]
        if finding.type == "freeswitch_unusable_media_address"
    )

    assert finding.severity == "high"
    assert "remote_media_ip: 0.0.0.0" in finding.evidence
    assert "remote_media_port: 4000" in finding.evidence


def test_freeswitch_profile_accepts_rfc_minimum_session_timer():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: valid-session-timer\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"Session-Expires: 90;refresher=uac\r\n"
        b"Min-SE: 90\r\n"
        b"CSeq: 1 INVITE\r\n\r\n"
    )

    result = analyze_pcap([packet], _settings())

    assert not any(
        finding.type == "freeswitch_session_timer_risk"
        for finding in result["findings"]
    )


def test_freeswitch_profile_does_not_assume_info_is_unavailable_without_allow_header():
    packet = _sip_packet(
        b"INVITE sip:queue@example.test SIP/2.0\r\n"
        b"Call-ID: unspecified-dtmf-capability\r\n"
        b"From: <sip:5511999999999@carrier.test>;tag=caller\r\n"
        b"CSeq: 1 INVITE\r\n"
        b"Content-Type: application/sdp\r\n\r\n"
        b"v=0\r\nc=IN IP4 198.51.100.10\r\nm=audio 4000 RTP/AVP 0\r\n"
    )

    result = analyze_pcap([packet], _settings())

    assert not any(
        finding.type == "freeswitch_dtmf_negotiation_risk"
        for finding in result["findings"]
    )
