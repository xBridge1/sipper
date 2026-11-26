"""Offer/answer, NAT, registration and platform-profile checks for SIP.

These checks compare two messages (offer and answer, request and challenge)
or a message with the configured FreeSWITCH profile, which single-message
hygiene checks cannot do.
"""

from ciper.text import is_ascii_digits
from ipaddress import ip_address, ip_network

from ciper.findings import Finding
from ciper.rtp import RTP_PAYLOAD_TYPE_NAMES

AUXILIARY = {"telephone-event", "cn", "comfort-noise"}
VALID_ANSWER_DIRECTIONS = {
    "sendrecv": {"sendrecv", "sendonly", "recvonly", "inactive"},
    "sendonly": {"recvonly", "inactive"},
    "recvonly": {"sendonly", "inactive"},
    "inactive": {"inactive"},
}
SIP_TLS_PORTS = {5061}
_CGNAT = ip_network("100.64.0.0/10")
# NAT bindings for UDP commonly expire after 30-120 s; a REGISTER refresh
# slower than this behind NAT loses inbound calls between refreshes.
NAT_REGISTER_MAX_EXPIRES = 600


def _evidence(flow):
    return [f"Call-ID: {flow.call_id}", f"Dialog-Key: {flow.dialog_key}"]


def _codec_names(media):
    names = {}
    for payload_type in media.payload_types:
        name = media.codecs.get(payload_type) or RTP_PAYLOAD_TYPE_NAMES.get(payload_type)
        if name:
            names[payload_type] = name.split("/", 1)[0].lower()
    return names


def _audio(message):
    return [media for media in message.sdp_media if media.media_type == "audio"]


def _offer_answer_pairs(flow):
    """(offer, answer) message pairs for each INVITE transaction."""
    pairs = []
    for invite in flow.messages:
        if not invite.is_request or invite.method != "INVITE":
            continue
        responses = [
            message
            for message in flow.messages
            if not message.is_request
            and message.cseq_method in {None, "INVITE"}
            and (invite.cseq_number is None or message.cseq_number == invite.cseq_number)
            and message.packet_time >= invite.packet_time
            and message.sdp_media
            and message.status_code
            and message.status_code < 300
        ]
        if invite.sdp_media:
            if responses:
                pairs.append((invite, responses[0]))
            continue
        # Late offer: the 200 OK carries the offer and the ACK the answer.
        offer = next((message for message in responses if 200 <= message.status_code < 300), None)
        if offer is None:
            continue
        ack = next(
            (
                message
                for message in flow.messages
                if message.is_request and message.method == "ACK" and message.sdp_media
                and message.packet_time >= offer.packet_time
            ),
            None,
        )
        if ack is not None:
            pairs.append((offer, ack))
    return pairs


def detect_sdp_offer_answer(flows):
    findings = []
    for flow in flows.values():
        seen = set()
        for offer, answer in _offer_answer_pairs(flow):
            for finding in _compare_offer_answer(flow, offer, answer):
                if finding.type not in seen:
                    seen.add(finding.type)
                    findings.append(finding)
    return findings


def _compare_offer_answer(flow, offer, answer):
    findings = []
    base = [
        *_evidence(flow),
        f"Offer: {offer.start_line} (from {offer.source_ip})",
        f"Answer: {answer.start_line} (from {answer.source_ip})",
    ]
    if len(offer.sdp_media) != len(answer.sdp_media):
        findings.append(
            Finding(
                type="sip_sdp_answer_media_count",
                severity="high",
                confidence=0.9,
                source_ip=answer.source_ip,
                destination_ip=answer.destination_ip,
                description=(
                    f"A resposta SDP tem {len(answer.sdp_media)} linha(s) m= e a oferta tinha {len(offer.sdp_media)}. "
                    "A RFC 3264 exige o mesmo numero e ordem; o outro lado pode rejeitar a resposta ou associar a midia errada."
                ),
                evidence=[*base, f"Offer m-lines: {len(offer.sdp_media)}", f"Answer m-lines: {len(answer.sdp_media)}"],
                recommendation="Corrija o lado que gerou a resposta: cada m= da oferta precisa de um m= correspondente (porta 0 para recusar).",
                culprit_ip=answer.source_ip,
            )
        )

    for offered, answered in zip(_audio(offer), _audio(answer)):
        offered_names = _codec_names(offered)
        answered_names = _codec_names(answered)
        offered_audio = {name for name in offered_names.values() if name not in AUXILIARY}
        answered_audio = {name for name in answered_names.values() if name not in AUXILIARY}
        line = f"m=audio {answered.port} {answered.protocol} {' '.join(str(item) for item in answered.payload_types)}"
        if answered.port > 0 and answered.direction != "inactive" and not answered_audio:
            findings.append(
                Finding(
                    type="sip_sdp_no_common_codec",
                    severity="high",
                    confidence=0.9,
                    source_ip=answer.source_ip,
                    destination_ip=answer.destination_ip,
                    description=(
                        "A resposta SDP aceitou o audio sem nenhum codec de voz em comum (so DTMF/CN ou lista vazia). "
                        "A chamada completa, mas nao ha como transportar voz: silencio total."
                    ),
                    evidence=[*base, f"Offered codecs: {', '.join(sorted(offered_audio)) or '-'}", f"Answer: {line}"],
                    recommendation=(
                        "Alinhe as listas de codecs dos dois lados (no FreeSWITCH: inbound/outbound-codec-prefs). "
                        "Se nao houver codec comum, o correto e responder 488."
                    ),
                    culprit_ip=answer.source_ip,
                    offending_lines=[line],
                )
            )
        not_offered = sorted(answered_audio - offered_audio)
        if not_offered and offered_audio:
            findings.append(
                Finding(
                    type="sip_sdp_answer_codec_not_offered",
                    severity="medium",
                    confidence=0.85,
                    source_ip=answer.source_ip,
                    destination_ip=answer.destination_ip,
                    description=(
                        f"A resposta SDP escolheu codec(s) que nao estavam na oferta ({', '.join(not_offered)}). "
                        "Quem ofertou pode descartar a midia ou transcodificar errado."
                    ),
                    evidence=[
                        *base,
                        f"Offered codecs: {', '.join(sorted(offered_audio))}",
                        f"Answered codecs: {', '.join(sorted(answered_audio))}",
                    ],
                    recommendation="Corrija o lado que respondeu: a resposta deve ser um subconjunto dos codecs ofertados.",
                    culprit_ip=answer.source_ip,
                    offending_lines=[line],
                )
            )
        offered_dtmf = {pt for pt, name in offered_names.items() if name == "telephone-event"}
        answered_dtmf = {pt for pt, name in answered_names.items() if name == "telephone-event"}
        if offered_dtmf and not answered_dtmf and answered.port > 0:
            findings.append(
                Finding(
                    type="sip_sdp_dtmf_not_negotiated",
                    severity="medium",
                    confidence=0.85,
                    source_ip=answer.source_ip,
                    destination_ip=answer.destination_ip,
                    description=(
                        "A oferta tinha telephone-event (DTMF RFC 4733) e a resposta o removeu. Os digitos so passam "
                        "in-band ou por SIP INFO: URAs e menus podem nao reconhecer as teclas."
                    ),
                    evidence=[*base, f"Offered telephone-event PT: {sorted(offered_dtmf)}", "Answered telephone-event: none"],
                    recommendation=(
                        "Habilite RFC 2833/4733 no lado que respondeu, ou configure deteccao in-band (start_dtmf) / "
                        "rtp_info_when_no_2833 no FreeSWITCH."
                    ),
                    culprit_ip=answer.source_ip,
                )
            )
        elif offered_dtmf and answered_dtmf and not offered_dtmf & answered_dtmf:
            findings.append(
                Finding(
                    type="sip_sdp_dtmf_payload_mismatch",
                    severity="low",
                    confidence=0.75,
                    source_ip=answer.source_ip,
                    destination_ip=answer.destination_ip,
                    description=(
                        f"Oferta e resposta usam payload types diferentes para telephone-event ({sorted(offered_dtmf)} x "
                        f"{sorted(answered_dtmf)}). E permitido, mas gateways que ignoram a assimetria descartam os digitos."
                    ),
                    evidence=[*base, f"Offered telephone-event PT: {sorted(offered_dtmf)}", f"Answered telephone-event PT: {sorted(answered_dtmf)}"],
                    recommendation="Se o DTMF falhar, alinhe o payload (ex.: 101) nos dois lados; no FreeSWITCH, veja rtp_2833_send_payload/recv_payload.",
                    culprit_ip=answer.source_ip,
                )
            )
        valid = VALID_ANSWER_DIRECTIONS.get(offered.direction, set())
        if answered.port > 0 and valid and answered.direction not in valid:
            findings.append(
                Finding(
                    type="sip_sdp_direction_mismatch",
                    severity="medium",
                    confidence=0.9,
                    source_ip=answer.source_ip,
                    destination_ip=answer.destination_ip,
                    description=(
                        f"A oferta foi '{offered.direction}' e a resposta '{answered.direction}', combinacao invalida pela "
                        "RFC 3264. Um dos lados vai enviar audio que o outro nao espera: audio em uma via ou mudo apos hold."
                    ),
                    evidence=[*base, f"Offer direction: {offered.direction}", f"Answer direction: {answered.direction}"],
                    recommendation=(
                        "Corrija o lado que respondeu: a sendonly responde-se recvonly/inactive, a recvonly responde-se "
                        "sendonly/inactive. Comum em hold/retomada mal implementados."
                    ),
                    culprit_ip=answer.source_ip,
                )
            )
    return findings


def _is_private(value):
    try:
        address = ip_address(value)
    except (ValueError, TypeError):
        return False
    return (address.is_private or (address.version == 4 and address in _CGNAT)) and not address.is_loopback


def _is_public(value):
    try:
        return ip_address(value).is_global
    except (ValueError, TypeError):
        return False


def _contact_host(contact):
    if not contact:
        return None
    candidate = contact
    if "<" in candidate and ">" in candidate:
        candidate = candidate.split("<", 1)[1].split(">", 1)[0]
    if ":" not in candidate:
        return None
    rest = candidate.split(":", 1)[1]
    host = rest.split("@", 1)[-1].split(";", 1)[0]
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.split(":", 1)[0]


def detect_sip_signaling_nat(flows):
    """Contact with a private address sent from a public address."""
    findings = []
    for flow in flows.values():
        for message in flow.messages:
            host = _contact_host(message.contact)
            if not host or not _is_public(message.source_ip) or not _is_private(host):
                continue
            is_answer = not message.is_request
            findings.append(
                Finding(
                    type="sip_contact_private_address",
                    severity="high" if is_answer and message.cseq_method == "INVITE" else "medium",
                    confidence=0.85,
                    source_ip=message.source_ip,
                    destination_ip=message.destination_ip,
                    description=(
                        f"O Contact anuncia o IP privado {host}, mas a mensagem veio do IP publico {message.source_ip}. "
                        "Requisicoes seguintes (ACK, BYE, re-INVITE, chamadas de entrada) vao para um endereco "
                        "inalcancavel: chamadas caem em ~32 s ou nao tocam."
                    ),
                    evidence=[
                        *_evidence(flow),
                        f"Message: {message.start_line}",
                        f"Contact: {message.contact}",
                        f"Signaling source: {message.source_ip}:{message.source_port}",
                    ],
                    recommendation=(
                        "Habilite NAT traversal: no FreeSWITCH, aggressive-nat-detection / NDLB-force-rport e "
                        "NDLB-received-in-nat-reg-contact no perfil Sofia; no endpoint, STUN/IP externo; ou desative "
                        "ALG SIP defeituoso no roteador."
                    ),
                    culprit_ip=message.source_ip,
                    offending_lines=[f"Contact: {message.contact}"],
                )
            )
            break
    return findings


class _Registration:
    """All messages sharing a REGISTER Call-ID (responses carry a To-tag and
    land in another dialog key)."""

    def __init__(self, call_id):
        self.call_id = call_id
        self.dialog_key = call_id
        self.messages = []


def detect_sip_register_issues(flows):
    findings = []
    registrations = {}
    for flow in flows.values():
        for message in flow.messages:
            if message.method == "REGISTER" or message.cseq_method == "REGISTER":
                registrations.setdefault(message.call_id, _Registration(message.call_id)).messages.append(message)
    for flow in registrations.values():
        flow.messages.sort(key=lambda message: message.packet_time)
        registers = [message for message in flow.messages if message.is_request and message.method == "REGISTER"]
        if not registers:
            continue
        rejected = []
        for request in registers:
            if not (request.headers.get("authorization") or request.headers.get("proxy-authorization")):
                continue
            response = next(
                (
                    message
                    for message in flow.messages
                    if not message.is_request
                    and message.cseq_method == "REGISTER"
                    and message.cseq_number == request.cseq_number
                    and message.status_code in {401, 403, 407}
                ),
                None,
            )
            if response is not None:
                rejected.append((request, response))
        if rejected:
            request, response = rejected[-1]
            user = _contact_user(request.headers.get("to")) or "-"
            findings.append(
                Finding(
                    type="sip_register_auth_rejected",
                    severity="high",
                    confidence=0.93,
                    source_ip=request.source_ip,
                    destination_ip=request.destination_ip,
                    description=(
                        f"O REGISTER foi enviado com credenciais e o registrar respondeu {response.status_code} "
                        f"{response.reason_phrase or ''} {len(rejected)} vez(es). Usuario, senha ou realm estao errados "
                        "(ou o usuario nao existe/esta bloqueado)."
                    ).replace("  ", " "),
                    evidence=[
                        *_evidence(flow),
                        f"User: {user}",
                        f"Authenticated attempts rejected: {len(rejected)}",
                        f"Response: {response.status_code} {response.reason_phrase or ''}".strip(),
                    ],
                    recommendation=(
                        f"Confira a senha e o usuario de autenticacao de '{user}' no endpoint e no diretorio do FreeSWITCH "
                        "(directory/*.xml). Muitas tentativas podem disparar bloqueio (fail2ban)."
                    ),
                    culprit_ip=request.source_ip,
                )
            )
        last = registers[-1]
        expires = _register_expires(last)
        host = _contact_host(last.contact)
        if expires and expires > NAT_REGISTER_MAX_EXPIRES and host and _is_private(host) and _is_public(last.source_ip):
            findings.append(
                Finding(
                    type="sip_register_expires_nat",
                    severity="medium",
                    confidence=0.8,
                    source_ip=last.source_ip,
                    destination_ip=last.destination_ip,
                    description=(
                        f"O endpoint esta atras de NAT e pede registro por {expires} s. O mapeamento NAT de UDP costuma "
                        "expirar em 30-120 s: entre um REGISTER e outro, chamadas de entrada nao chegam ao ramal."
                    ),
                    evidence=[*_evidence(flow), f"Expires: {expires}", f"Contact: {last.contact}"],
                    recommendation=(
                        "Reduza o intervalo de registro do endpoint (60-120 s) ou habilite keepalive (OPTIONS/CRLF); no "
                        "FreeSWITCH, nat-options-ping ou registro forcado com expires curto."
                    ),
                    culprit_ip=last.source_ip,
                )
            )
    return findings


def _contact_user(value):
    if not value:
        return None
    candidate = value.split("<", 1)[-1].split(">", 1)[0]
    if ":" not in candidate:
        return None
    return candidate.split(":", 1)[1].split("@", 1)[0] or None


def _register_expires(message):
    contact = message.contact or ""
    for parameter in contact.split(";")[1:]:
        name, _sep, value = parameter.partition("=")
        if name.strip().lower() == "expires" and is_ascii_digits(value.strip()):
            return int(value.strip())
    value = message.headers.get("expires", "").strip()
    return int(value) if is_ascii_digits(value) else None


def detect_sip_tls_signaling(tls_flows, sip_flows):
    """SIP over TLS cannot be read from a capture: say so instead of staying silent."""
    findings = []
    decoded_hosts = {
        frozenset((message.source_ip, message.destination_ip))
        for flow in sip_flows.values()
        for message in flow.messages
    }
    seen = set()
    for flow in tls_flows.values():
        if flow.destination_port not in SIP_TLS_PORTS and flow.source_port not in SIP_TLS_PORTS:
            continue
        pair = frozenset((flow.source_ip, flow.destination_ip))
        if pair in decoded_hosts or pair in seen:
            continue
        seen.add(pair)
        findings.append(
            Finding(
                type="sip_tls_signaling",
                severity="low",
                confidence=0.9,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description=(
                    "Ha sinalizacao SIP sobre TLS (porta 5061) entre estes hosts. Ela e cifrada: chamadas, erros e "
                    "headers desse trecho nao aparecem na analise."
                ),
                evidence=[
                    f"TLS session: {flow.source_ip}:{flow.source_port} -> {flow.destination_ip}:{flow.destination_port}",
                    f"SNI: {', '.join(sorted(flow.server_names)) or '-'}",
                ],
                recommendation=(
                    "Para analisar este trecho, capture no proprio FreeSWITCH com 'sofia global siptrace on' / "
                    "'sofia profile <perfil> siptrace on', use temporariamente UDP/TCP em laboratorio, ou exporte as "
                    "chaves TLS do endpoint se ele suportar."
                ),
            )
        )
    return findings


def detect_freeswitch_profile_mismatch(flows, settings, target_matcher):
    """Predict FreeSWITCH rejections from the configured profile.

    ``target_matcher(ip)`` tells whether an IP is the monitored FreeSWITCH.
    """
    codecs = {item.strip().lower() for item in (settings.freeswitch_codecs or "").split(",") if item.strip()}
    codecs = {item.split("@", 1)[0].split("/", 1)[0] for item in codecs}
    findings = []
    for flow in flows.values():
        invite = next((message for message in flow.messages if message.is_request and message.method == "INVITE"), None)
        if invite is None or not target_matcher(invite.destination_ip):
            continue
        response = next(
            (
                message
                for message in flow.messages
                if not message.is_request and message.cseq_method in {None, "INVITE"} and message.status_code >= 300
            ),
            None,
        )
        status = f"{response.status_code} {response.reason_phrase or ''}".strip() if response else None
        audio = [media for media in invite.sdp_media if media.media_type == "audio" and media.port > 0]
        base = [*_evidence(flow), f"Initial INVITE: {invite.start_line}"]
        if codecs and audio:
            offered = {name for media in audio for name in _codec_names(media).values() if name not in AUXILIARY}
            if offered and not offered & codecs:
                findings.append(
                    Finding(
                        type="freeswitch_codec_mismatch",
                        severity="high",
                        confidence=0.97 if response is not None and response.status_code == 488 else 0.85,
                        source_ip=invite.source_ip,
                        destination_ip=invite.destination_ip,
                        description=(
                            f"Nenhum codec ofertado ({', '.join(sorted(offered))}) esta na lista configurada do FreeSWITCH "
                            f"({', '.join(sorted(codecs))}). O FreeSWITCH recusa com 488 Not Acceptable Here (INCOMPATIBLE_DESTINATION)."
                        ),
                        evidence=[*base, f"Offered codecs: {', '.join(sorted(offered))}", f"FreeSWITCH codecs: {', '.join(sorted(codecs))}"]
                        + ([f"Peer response: {status}"] if status else []),
                        recommendation="Inclua um codec do peer em inbound-codec-prefs do perfil Sofia, ou peca ao peer para ofertar um codec aceito.",
                        culprit_ip=invite.source_ip,
                        confirmed_by=status if response is not None and response.status_code == 488 else None,
                    )
                )
        require = {tag.strip().lower() for value in invite.header_values.get("require", []) for tag in value.split(",")}
        missing = []
        if "100rel" in require and not settings.freeswitch_100rel:
            missing.append(("100rel", "enable-100rel"))
        if "timer" in require and not settings.freeswitch_session_timer:
            missing.append(("timer", "enable-timer"))
        if missing:
            findings.append(
                Finding(
                    type="freeswitch_profile_extension_disabled",
                    severity="high",
                    confidence=0.95 if response is not None and response.status_code == 420 else 0.85,
                    source_ip=invite.source_ip,
                    destination_ip=invite.destination_ip,
                    description=(
                        f"O INVITE exige {', '.join(tag for tag, _ in missing)} e o perfil configurado nao tem "
                        f"{', '.join(option for _, option in missing)} habilitado: o FreeSWITCH responde 420 Bad Extension."
                    ),
                    evidence=[*base, f"Require: {', '.join(sorted(require))}"] + ([f"Peer response: {status}"] if status else []),
                    recommendation=f"Habilite {', '.join(option for _, option in missing)} no perfil Sofia ou remova o Require na origem.",
                    culprit_ip=invite.source_ip,
                    confirmed_by=status if response is not None and response.status_code == 420 else None,
                )
            )
        secure = [media for media in audio if "SAVP" in media.protocol.upper()]
        if secure and not settings.freeswitch_srtp:
            findings.append(
                Finding(
                    type="freeswitch_srtp_disabled",
                    severity="high",
                    confidence=0.95 if response is not None and response.status_code == 488 else 0.8,
                    source_ip=invite.source_ip,
                    destination_ip=invite.destination_ip,
                    description=(
                        f"O INVITE oferece audio somente seguro ({secure[0].protocol}) e o perfil configurado nao usa SRTP: "
                        "o FreeSWITCH recusa com 488."
                    ),
                    evidence=[*base, f"Media profile: {secure[0].protocol}"] + ([f"Peer response: {status}"] if status else []),
                    recommendation="Habilite rtp_secure_media no FreeSWITCH para este peer ou desative SRTP obrigatorio no endpoint.",
                    culprit_ip=invite.source_ip,
                    confirmed_by=status if response is not None and response.status_code == 488 else None,
                )
            )
    return findings
