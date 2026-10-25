from ipaddress import ip_address, ip_network

from ciper.findings import Finding


def detect_freeswitch_compatibility(flows, target_ips=""):
    findings = []
    seen_invites = set()

    for flow in flows.values():
        invite = _get_initial_invite(flow)
        if invite is None or not _matches_target(invite.destination_ip, target_ips):
            continue

        invite_key = (
            invite.call_id,
            invite.source_ip,
            invite.destination_ip,
            invite.cseq_number,
        )
        if invite_key in seen_invites:
            continue
        seen_invites.add(invite_key)

        headers = invite.headers
        from_header = headers.get("from", "")
        identity_header, identity_value, identity_asserted = _identity_header(headers)
        anonymous = _is_anonymous_identity(from_header)
        audio_media = [media for media in invite.sdp_media if media.media_type == "audio"]
        risky_media = [
            media
            for media in audio_media
            if media.port == 0 or media.direction in {"sendonly", "recvonly", "inactive"}
        ]

        if anonymous and risky_media:
            findings.append(
                _combined_callcenter_risk(
                    flow,
                    invite,
                    risky_media,
                    identity_header,
                    identity_value,
                    identity_asserted,
                )
            )
        else:
            if risky_media:
                findings.append(_media_offer_risk(flow, invite, risky_media))
            if anonymous:
                findings.append(
                    _anonymous_identity_risk(
                        flow,
                        invite,
                        identity_header,
                        identity_value,
                        identity_asserted,
                    )
                )

        for detector in (
            _routing_target_mismatch,
            _session_timer_risk,
            _dtmf_negotiation_risk,
            _unusable_media_address,
        ):
            finding = detector(flow, invite)
            if finding is not None:
                findings.append(finding)

        custom_headers = sorted(name for name in headers if name.startswith("x-"))
        if custom_headers:
            findings.append(_custom_header_input(flow, invite, custom_headers))

    return findings


def _get_initial_invite(flow):
    invites = [
        message
        for message in flow.messages
        if message.is_request and message.method == "INVITE"
    ]
    return min(invites, key=lambda message: message.packet_time, default=None)


def _matches_target(destination_ip, configured_targets):
    targets = [
        value.strip()
        for value in configured_targets.replace(";", ",").split(",")
        if value.strip()
    ]
    if not targets:
        return True

    try:
        destination = ip_address(destination_ip)
    except ValueError:
        return destination_ip in targets

    for target in targets:
        try:
            if "/" in target and destination in ip_network(target, strict=False):
                return True
            if destination == ip_address(target):
                return True
        except ValueError:
            if destination_ip == target:
                return True
    return False


def _is_anonymous_identity(value):
    normalized = value.lower()
    return any(
        token in normalized
        for token in (
            "sip:anonymous@",
            "sips:anonymous@",
            "anonymous.invalid",
            "sip:restricted@",
        )
    )


def _identity_header(headers):
    for header, display_name, asserted in (
        ("p-asserted-identity", "P-Asserted-Identity", True),
        ("remote-party-id", "Remote-Party-ID", True),
        ("p-preferred-identity", "P-Preferred-Identity", False),
    ):
        if headers.get(header):
            return display_name, headers[header], asserted
    return None, None, False


def _sip_uri_user(value):
    if not value:
        return None

    candidate = value.strip()
    if "<" in candidate and ">" in candidate:
        candidate = candidate.split("<", 1)[1].split(">", 1)[0].strip()

    lowered = candidate.lower()
    scheme_position = next(
        (lowered.find(scheme) for scheme in ("sips:", "sip:", "tel:") if scheme in lowered),
        -1,
    )
    if scheme_position < 0:
        return None

    user = candidate[scheme_position:].split(":", 1)[1]
    user = user.split("@", 1)[0].split(";", 1)[0].split("?", 1)[0].strip()
    return user or None


def _parse_timer_seconds(value):
    if not value:
        return None
    seconds = value.split(";", 1)[0].strip()
    return int(seconds) if seconds.isdigit() else None


def _address_is_unspecified(value):
    if not value:
        return True
    try:
        return ip_address(value.split("/", 1)[0]).is_unspecified
    except ValueError:
        return False


def _base_evidence(flow, invite):
    return [
        f"Call-ID: {flow.call_id}",
        f"Dialog-Key: {flow.dialog_key}",
        f"Initial INVITE: {invite.start_line}",
        f"Packet path: {invite.source_ip}:{invite.source_port} -> {invite.destination_ip}:{invite.destination_port}",
    ]


def _media_evidence(media):
    return [
        f"SDP direction: {item.direction}"
        for item in media
    ] + [
        f"SDP audio endpoint: {item.connection_address or 'not informed'}:{item.port}"
        for item in media
    ]


def _identity_evidence(invite, identity_header, identity_value, identity_asserted):
    privacy = invite.headers.get("privacy", "not present")
    if identity_header == "P-Preferred-Identity":
        identity_trust = "preferred, not asserted"
    elif identity_header == "Remote-Party-ID":
        identity_trust = "legacy asserted header; validate the trusted peer"
    elif identity_header:
        identity_trust = "asserted header; validate the trusted peer"
    else:
        identity_trust = "no supplemental identity"
    return [
        f"From: {invite.headers.get('from', 'not present')}",
        f"Asserted identity available: {'yes' if identity_value and identity_asserted else 'no'}",
        f"Identity header: {identity_header or 'not present'}",
        f"Identity value: {identity_value or 'not present'}",
        f"Identity trust: {identity_trust}",
        f"Privacy: {privacy}",
        f"sip_cid_type: {'rpid' if identity_header == 'Remote-Party-ID' else 'pid' if identity_value else 'not set'}",
    ]


def _combined_callcenter_risk(
    flow,
    invite,
    media,
    identity_header,
    identity_value,
    identity_asserted,
):
    return Finding(
        type="freeswitch_callcenter_input_risk",
        severity="medium" if identity_asserted else "high",
        confidence=0.95,
        source_ip=invite.source_ip,
        destination_ip=invite.destination_ip,
        description=(
            "The initial INVITE combines anonymous caller identity with restricted audio direction. "
            "This standards-compliant input can break assumptions in interactive FreeSWITCH dialplans "
            "and mod_callcenter flows that expect an identified caller and bidirectional media."
        ),
        evidence=[
            *_base_evidence(flow, invite),
            *_identity_evidence(invite, identity_header, identity_value, identity_asserted),
            *_media_evidence(media),
            "Affected area: inbound dialplan, caller identity and mod_callcenter media",
        ],
        recommendation=(
            "Validate the carrier offer before transferring the call to mod_callcenter. Restore caller "
            "identity only from a trusted P-Asserted-Identity or legacy Remote-Party-ID. Treat "
            "P-Preferred-Identity as a preference, not an assertion, and confirm whether the initial "
            "one-way SDP direction is intentional."
        ),
    )


def _media_offer_risk(flow, invite, media):
    inactive = any(item.port == 0 or item.direction == "inactive" for item in media)
    return Finding(
        type=(
            "freeswitch_inactive_initial_offer"
            if inactive
            else "freeswitch_unidirectional_initial_offer"
        ),
        severity="high" if inactive else "medium",
        confidence=0.95,
        source_ip=invite.source_ip,
        destination_ip=invite.destination_ip,
        description=(
            "The initial INVITE offers inactive audio. FreeSWITCH cannot establish interactive media "
            "for this stream."
            if inactive
            else "The initial INVITE offers one-way audio. This is valid SDP, but FreeSWITCH applications "
            "that expect bidirectional media, including call-center flows, may not behave as intended."
        ),
        evidence=[
            *_base_evidence(flow, invite),
            *_media_evidence(media),
            "Affected area: media negotiation and interactive applications",
        ],
        recommendation=(
            "Confirm with the carrier whether the initial media direction is intentional. Review the "
            "Sofia profile hold behavior and do not route the call to an interactive queue until both "
            "media directions are expected."
        ),
    )


def _anonymous_identity_risk(
    flow,
    invite,
    identity_header,
    identity_value,
    identity_asserted,
):
    return Finding(
        type="freeswitch_anonymous_caller_identity",
        severity="low" if identity_asserted else "medium",
        confidence=0.95,
        source_ip=invite.source_ip,
        destination_ip=invite.destination_ip,
        description=(
            "The inbound INVITE presents an anonymous From identity. FreeSWITCH derives caller_id_number "
            "from that header unless trusted identity data is handled explicitly in the dialplan."
        ),
        evidence=[
            *_base_evidence(flow, invite),
            *_identity_evidence(invite, identity_header, identity_value, identity_asserted),
            "Affected variables: caller_id_number and sip_from_user",
        ],
        recommendation=(
            "Validate identity headers at the trusted carrier boundary. If policy permits, set caller ID "
            "from sip_p_asserted_identity or sip_remote_party_id before routing to applications that "
            "depend on it. Access P-Preferred-Identity through sip_h_P-Preferred-Identity and do not "
            "treat it as asserted or expose an identity protected by Privacy: id."
        ),
    )


def _routing_target_mismatch(flow, invite):
    destination_number = _sip_uri_user(invite.request_uri)
    sip_to_user = _sip_uri_user(invite.headers.get("to"))
    if not destination_number or not sip_to_user or destination_number == sip_to_user:
        return None

    return Finding(
        type="freeswitch_routing_target_mismatch",
        severity="low",
        confidence=0.90,
        source_ip=invite.source_ip,
        destination_ip=invite.destination_ip,
        description=(
            "The Request-URI user differs from the To user. FreeSWITCH routes the call using "
            "destination_number from the Request-URI, so an SBC rewrite can select a different "
            "dialplan extension than the visible called identity."
        ),
        evidence=[
            *_base_evidence(flow, invite),
            f"sip_req_uri: {invite.request_uri}",
            f"destination_number: {destination_number}",
            f"sip_to_user: {sip_to_user}",
            "Assessment: this may be an intentional carrier or SBC rewrite",
        ],
        recommendation=(
            "Confirm that the Request-URI rewrite is expected and that the selected FreeSWITCH context "
            "contains the resulting destination_number before sending the call to a queue or application."
        ),
    )


def _session_timer_risk(flow, invite):
    session_expires = _parse_timer_seconds(invite.headers.get("session-expires"))
    min_se = _parse_timer_seconds(invite.headers.get("min-se"))
    invalid_values = [value for value in (session_expires, min_se) if value is not None and value < 90]
    if not invalid_values:
        return None

    evidence = [*_base_evidence(flow, invite)]
    if session_expires is not None:
        evidence.append(f"Session-Expires: {session_expires} seconds")
    if min_se is not None:
        evidence.append(f"Min-SE: {min_se} seconds")
    evidence.append("RFC 4028 minimum: 90 seconds")

    return Finding(
        type="freeswitch_session_timer_risk",
        severity="medium",
        confidence=0.98,
        source_ip=invite.source_ip,
        destination_ip=invite.destination_ip,
        description=(
            "The INVITE proposes a SIP session timer below the RFC 4028 minimum. FreeSWITCH may "
            "normalize or reject the interval, causing setup or refresh interoperability failures."
        ),
        evidence=evidence,
        recommendation=(
            "Configure the peer to use at least 90 seconds and align the Sofia profile enable-timer, "
            "session-timeout, and minimum-session-expires settings with the carrier policy."
        ),
    )


def _dtmf_negotiation_risk(flow, invite):
    active_audio = [
        media
        for media in invite.sdp_media
        if media.media_type == "audio" and media.port > 0 and media.direction != "inactive"
    ]
    allow_header = invite.headers.get("allow")
    if not active_audio or not allow_header:
        return None

    telephone_event = any(
        codec.lower() == "telephone-event"
        for media in active_audio
        for codec in media.codecs.values()
    )
    allowed_methods = {method.strip().upper() for method in allow_header.split(",")}
    info_allowed = "INFO" in allowed_methods
    if telephone_event or info_allowed:
        return None

    codecs = sorted(
        {
            codec
            for media in active_audio
            for codec in media.codecs.values()
            if codec.lower() != "telephone-event"
        }
    )
    return Finding(
        type="freeswitch_dtmf_negotiation_risk",
        severity="medium",
        confidence=0.88,
        source_ip=invite.source_ip,
        destination_ip=invite.destination_ip,
        description=(
            "The audio offer has no RFC 4733 telephone-event payload and the peer's Allow header "
            "does not advertise SIP INFO. DTMF used by IVRs and call-center applications may fail "
            "unless in-band detection is explicitly enabled."
        ),
        evidence=[
            *_base_evidence(flow, invite),
            "telephone-event offered: no",
            "SIP INFO allowed: no",
            f"Allow: {allow_header}",
            f"Audio codecs: {', '.join(codecs) if codecs else 'payload mapping not informed'}",
            "Affected variables: rtp_2833_recv_payload and rtp_info_when_no_2833",
        ],
        recommendation=(
            "Ask the peer to offer RFC 4733 telephone-event or support SIP INFO. If only in-band "
            "DTMF is available, enable and validate start_dtmf in the relevant FreeSWITCH dialplan."
        ),
    )


def _unusable_media_address(flow, invite):
    invalid_media = [
        media
        for media in invite.sdp_media
        if media.media_type == "audio"
        and media.port > 0
        and media.direction != "inactive"
        and _address_is_unspecified(media.connection_address)
    ]
    if not invalid_media:
        return None

    evidence = [*_base_evidence(flow, invite)]
    for media in invalid_media:
        evidence.extend(
            (
                f"remote_media_ip: {media.connection_address or 'not informed'}",
                f"remote_media_port: {media.port}",
                f"SDP direction: {media.direction}",
            )
        )

    return Finding(
        type="freeswitch_unusable_media_address",
        severity="high",
        confidence=0.98,
        source_ip=invite.source_ip,
        destination_ip=invite.destination_ip,
        description=(
            "The initial active audio offer does not provide a usable remote RTP address. "
            "FreeSWITCH cannot derive a reachable remote_media_ip for this stream."
        ),
        evidence=evidence,
        recommendation=(
            "Correct the peer or SBC SDP so the c= line contains a reachable media address. "
            "Review NAT rewriting and the Sofia profile ext-rtp-ip configuration before routing "
            "the call to an interactive application."
        ),
    )


def _custom_header_input(flow, invite, custom_headers):
    display_names = ["-".join(part.capitalize() for part in name.split("-")) for name in custom_headers]
    return Finding(
        type="freeswitch_custom_header_input",
        severity="low",
        confidence=0.95,
        source_ip=invite.source_ip,
        destination_ip=invite.destination_ip,
        description=(
            "The inbound INVITE contains custom SIP headers that FreeSWITCH can expose as sip_h_ channel "
            "variables and copy to bridged legs. They are inputs to validate, not an error by themselves."
        ),
        evidence=[
            *_base_evidence(flow, invite),
            f"Custom SIP headers: {', '.join(display_names)}",
            *[
                f"sip_h_{display_name}: {invite.headers[header][:160]}"
                for header, display_name in zip(custom_headers, display_names)
            ],
            "Affected area: dialplan variables and bridged-leg header propagation",
        ],
        recommendation=(
            "Treat custom SIP headers as untrusted input. Validate values before using them in routing or "
            "modules, and disable sip_copy_custom_headers when propagation to the B-leg is not required."
        ),
    )
