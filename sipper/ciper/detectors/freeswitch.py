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
            "O INVITE inicial combina chamador anonimo com direcao de audio restrita. Essa entrada, valida pelos padroes, pode quebrar premissas de dialplans interativos e fluxos do mod_callcenter que esperam chamador identificado e midia bidirecional."
        ),
        evidence=[
            *_base_evidence(flow, invite),
            *_identity_evidence(invite, identity_header, identity_value, identity_asserted),
            *_media_evidence(media),
            "Affected area: inbound dialplan, caller identity and mod_callcenter media",
        ],
        recommendation=(
            "Valide a oferta da operadora antes de transferir a chamada ao mod_callcenter. Restaure a identidade do chamador apenas a partir de um P-Asserted-Identity confiavel ou do Remote-Party-ID legado. Trate P-Preferred-Identity como preferencia, nao assercao, e confirme se a direcao SDP unidirecional inicial e intencional."
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
            "O INVITE inicial oferece audio inativo. O FreeSWITCH nao consegue estabelecer midia interativa para este stream."
            if inactive
            else "O INVITE inicial oferece audio em uma via. O SDP e valido, mas aplicacoes do FreeSWITCH "
            "que esperam midia bidirecional, incluindo call centers, podem nao se comportar como esperado."
        ),
        evidence=[
            *_base_evidence(flow, invite),
            *_media_evidence(media),
            "Affected area: media negotiation and interactive applications",
        ],
        recommendation=(
            "Confirme com a operadora se a direcao inicial da midia e intencional. Revise o comportamento de hold do perfil Sofia e nao envie a chamada a uma fila interativa ate que as duas direcoes de midia sejam esperadas."
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
            "O INVITE recebido apresenta identidade From anonima. O FreeSWITCH deriva o caller_id_number desse header, a menos que dados de identidade confiaveis sejam tratados explicitamente no dialplan."
        ),
        evidence=[
            *_base_evidence(flow, invite),
            *_identity_evidence(invite, identity_header, identity_value, identity_asserted),
            "Affected variables: caller_id_number and sip_from_user",
        ],
        recommendation=(
            "Valide os headers de identidade na fronteira confiavel com a operadora. Se a politica permitir, defina o caller ID a partir de sip_p_asserted_identity ou sip_remote_party_id antes de rotear para aplicacoes que dependem dele. Acesse P-Preferred-Identity via sip_h_P-Preferred-Identity, sem trata-lo como assertado nem expor identidade protegida por Privacy: id."
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
            "O usuario da Request-URI difere do usuario do To. O FreeSWITCH roteia pelo destination_number da Request-URI, entao uma reescrita no SBC pode selecionar uma extensao do dialplan diferente da identidade chamada visivel."
        ),
        evidence=[
            *_base_evidence(flow, invite),
            f"sip_req_uri: {invite.request_uri}",
            f"destination_number: {destination_number}",
            f"sip_to_user: {sip_to_user}",
            "Assessment: this may be an intentional carrier or SBC rewrite",
        ],
        recommendation=(
            "Confirme que a reescrita da Request-URI e esperada e que o contexto do FreeSWITCH contem o destination_number resultante antes de enviar a chamada a uma fila ou aplicacao."
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
            "O INVITE propoe um session timer abaixo do minimo da RFC 4028. O FreeSWITCH pode normalizar ou rejeitar o intervalo, causando falhas de interoperabilidade no estabelecimento ou no refresh."
        ),
        evidence=evidence,
        recommendation=(
            "Configure o peer para usar pelo menos 90 segundos e alinhe enable-timer, session-timeout e minimum-session-expires do perfil Sofia com a politica da operadora."
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
            "A oferta de audio nao tem payload telephone-event (RFC 4733) e o header Allow do peer nao anuncia SIP INFO. O DTMF usado por URAs e call centers pode falhar, a menos que a deteccao in-band esteja habilitada."
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
            "Peca ao peer para oferecer telephone-event (RFC 4733) ou suportar SIP INFO. Se so houver DTMF in-band, habilite e valide start_dtmf no dialplan do FreeSWITCH."
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
            "A oferta inicial de audio ativo nao fornece um endereco RTP remoto utilizavel. O FreeSWITCH nao consegue derivar um remote_media_ip alcancavel para este stream."
        ),
        evidence=evidence,
        recommendation=(
            "Corrija o SDP do peer ou do SBC para que a linha c= contenha um endereco de midia alcancavel. Revise a reescrita de NAT e o ext-rtp-ip do perfil Sofia antes de rotear a chamada para uma aplicacao interativa."
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
            "O INVITE recebido contem headers SIP personalizados que o FreeSWITCH pode expor como variaveis sip_h_ e copiar para as pernas em bridge. Sao entradas a validar, nao um erro por si so."
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
            "Trate headers SIP personalizados como entrada nao confiavel. Valide os valores antes de usa-los em roteamento ou modulos e desabilite sip_copy_custom_headers quando a propagacao para a perna B nao for necessaria."
        ),
    )
