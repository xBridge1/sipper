"""SIP message hygiene: header content that breaks parsers, PBXs and FreeSWITCH.

Every check looks at one message and reports the exact header line that holds
the problem. When the peer answered that request with a rejection that such a
defect produces (400, 415, 420, 483, 488...), the finding is marked as
confirmed: the capture then shows cause and effect, not just a risk.
"""

from ciper.text import is_ascii_digits
import re
from ipaddress import ip_address, ip_network

from ciper.findings import Finding
from ciper.sip_status import MESSAGE_REJECTION_CODES


# Headers that may appear only once (RFC 3261 section 7.3.1 and 20). A second
# copy makes sofia-sip flag the message as erroneous and answer 400.
SINGLETON_HEADERS = (
    "call-id",
    "cseq",
    "from",
    "to",
    "content-length",
    "content-type",
    "max-forwards",
    "expires",
    "session-expires",
    "min-se",
)
REQUEST_MANDATORY_HEADERS = ("via", "from", "to", "cseq")
RESPONSE_MANDATORY_HEADERS = ("via", "from", "to", "cseq")
NAME_ADDR_HEADERS = (
    "from",
    "to",
    "contact",
    "p-asserted-identity",
    "p-preferred-identity",
    "remote-party-id",
    "refer-to",
    "referred-by",
    "diversion",
)
IDENTITY_HEADERS = {"from", "to", "p-asserted-identity", "p-preferred-identity", "remote-party-id", "contact"}
# Option tags mod_sofia implements. 100rel only works with enable-100rel.
FREESWITCH_SUPPORTED_REQUIRE = {"timer", "100rel", "replaces", "path", "norefersub", "outbound", "gruu"}
DIALOG_CREATING_METHODS = {"INVITE", "SUBSCRIBE", "REFER", "NOTIFY"}
INITIAL_REQUEST_METHODS = {"INVITE", "REGISTER", "OPTIONS", "SUBSCRIBE", "MESSAGE", "PUBLISH", "REFER", "NOTIFY", "INFO"}
STRUCTURAL_TYPES = {
    "sip_header_control_characters",
    "sip_header_duplicate_singleton",
    "sip_header_missing_mandatory",
    "sip_header_cseq_mismatch",
    "sip_header_malformed_address",
    "sip_header_invalid_name",
    "sip_header_invalid_version",
    "sip_request_uri_invalid",
    "sip_sdp_malformed",
}

_DISPLAY_NAMES = {
    "call-id": "Call-ID",
    "cseq": "CSeq",
    "www-authenticate": "WWW-Authenticate",
    "p-asserted-identity": "P-Asserted-Identity",
    "p-preferred-identity": "P-Preferred-Identity",
    "remote-party-id": "Remote-Party-ID",
    "min-se": "Min-SE",
    "mime-version": "MIME-Version",
}
_VARIABLE_PATTERN = re.compile(r"\$\$?\{")
_BAD_ESCAPE_PATTERN = re.compile(r"%(?![0-9A-Fa-f]{2})")
# Characters that must be escaped in the user part of a SIP URI.
_URI_USER_FORBIDDEN = set(' "<>#{}|\\^[]`')
_SECURE_PROFILES = ("RTP/SAVP", "RTP/SAVPF", "UDP/TLS/RTP/SAVP", "UDP/TLS/RTP/SAVPF")


def header_display_name(name):
    if name in _DISPLAY_NAMES:
        return _DISPLAY_NAMES[name]
    return "-".join(part.capitalize() for part in name.split("-"))


def detect_sip_header_hygiene(flows, freeswitch_profile=False, target_ips=""):
    aggregated = {}

    for flow in flows.values():
        check_require = freeswitch_profile or any(
            not message.is_request and message.status_code in {420, 421} for message in flow.messages
        )
        for message in flow.messages:
            if not _matches_target(message, target_ips):
                continue
            for issue in _message_issues(message, check_require):
                key = (issue["type"], flow.dialog_key, message.source_ip, message.destination_ip)
                entry = aggregated.get(key)
                if entry is None:
                    aggregated[key] = {
                        "flow": flow,
                        "message": message,
                        "issue": issue,
                        "count": 1,
                        "confirmation": _confirmation(flow, message),
                    }
                    continue
                entry["count"] += 1
                if entry["confirmation"] is None:
                    confirmation = _confirmation(flow, message)
                    if confirmation is not None:
                        entry.update(message=message, issue=issue, confirmation=confirmation)

    return [_build_finding(entry) for entry in aggregated.values()]


def _matches_target(message, configured_targets):
    targets = [value.strip() for value in (configured_targets or "").replace(";", ",").split(",") if value.strip()]
    if not targets:
        return True
    for address in (message.source_ip, message.destination_ip):
        for target in targets:
            try:
                if "/" in target and ip_address(address) in ip_network(target, strict=False):
                    return True
                if ip_address(address) == ip_address(target):
                    return True
            except ValueError:
                if address == target:
                    return True
    return False


def _confirmation(flow, message):
    """The response proving the peer reacted to this request.

    Returns ``("rejected", response)`` for a rejection a message defect
    typically causes, ``("accepted", response)`` for a 2xx, or None.
    """
    if not message.is_request or message.method in {"ACK", "CANCEL"}:
        return None
    accepted = None
    for response in flow.messages:
        if response.is_request or response.packet_time < message.packet_time:
            continue
        if message.cseq_number is not None and response.cseq_number != message.cseq_number:
            continue
        if response.cseq_method not in {None, message.method}:
            continue
        if response.status_code in MESSAGE_REJECTION_CODES or response.status_code == 500:
            return ("rejected", response)
        if 200 <= response.status_code < 300 and accepted is None:
            accepted = ("accepted", response)
    return accepted


def _build_finding(entry):
    flow = entry["flow"]
    message = entry["message"]
    issue = entry["issue"]
    confirmation = entry["confirmation"]
    severity = issue["severity"]
    confidence = issue["confidence"]
    confirmed_by = None
    evidence = [
        f"Call-ID: {flow.call_id}",
        f"Dialog-Key: {flow.dialog_key}",
        f"Message: {message.start_line}",
        f"Sender: {message.source_ip}:{message.source_port}",
        f"Receiver: {message.destination_ip}:{message.destination_port}",
        *issue["evidence"],
    ]
    if entry["count"] > 1:
        evidence.append(f"Messages affected: {entry['count']}")

    description = issue["description"]
    if confirmation is not None:
        outcome, response = confirmation
        status = f"{response.status_code} {response.reason_phrase or ''}".strip()
        if outcome == "rejected":
            severity = "high"
            confidence = max(confidence, 0.97)
            confirmed_by = status
            evidence.append(f"Peer response: {status} (from {response.source_ip})")
            description += f" O destino rejeitou esta requisicao com {status}, o que confirma o impacto."
        else:
            evidence.append(f"Peer response: {status} (from {response.source_ip})")
            if issue["type"] in STRUCTURAL_TYPES and severity == "high":
                severity = "medium"
            description += " O destino aceitou a requisicao; o risco esta no processamento posterior (dialplan, CDR, aplicacoes) ou em outro salto."

    return Finding(
        type=issue["type"],
        severity=severity,
        confidence=confidence,
        source_ip=message.source_ip,
        destination_ip=message.destination_ip,
        description=description,
        evidence=evidence,
        recommendation=issue["recommendation"],
        culprit_ip=message.source_ip,
        confirmed_by=confirmed_by,
        offending_lines=issue.get("lines", []),
    )


def _issue(type_, severity, confidence, description, recommendation, evidence=(), lines=()):
    return {
        "type": type_,
        "severity": severity,
        "confidence": confidence,
        "description": description,
        "recommendation": recommendation,
        "evidence": list(evidence),
        "lines": [_visible(line) for line in lines][:6],
    }


def _visible(text, limit=240):
    """Show control characters and cut very long lines for display."""
    shown = "".join(
        f"\\x{ord(character):02X}" if ord(character) < 0x20 and character != "\t" or ord(character) == 0x7F else character
        for character in text
    )
    return shown if len(shown) <= limit else shown[:limit] + "..."


def _header_lines(message, name):
    return [f"{header_display_name(name)}: {value}" for value in message.header_values.get(name, [])]


def _message_issues(message, check_require):
    issues = []
    for check in (
        _check_control_characters,
        _check_encoding,
        _check_duplicates,
        _check_mandatory,
        _check_contact,
        _check_cseq,
        _check_max_forwards,
        _check_variable_injection,
        _check_name_addr,
        _check_request_uri,
        _check_content_headers,
        _check_line_format,
        _check_from_tag,
        _check_version,
        _check_sdp,
    ):
        issues.extend(check(message))
    if check_require:
        issues.extend(_check_require(message))
    return issues


def _check_control_characters(message):
    if not message.control_char_headers:
        return []
    names = [header_display_name(name) for name in message.control_char_headers]
    lines = [line for name in message.control_char_headers for line in _header_lines(message, name)]
    return [
        _issue(
            "sip_header_control_characters",
            "high",
            0.95,
            "Headers SIP contem caracteres de controle (NUL, CR/LF soltos ou outros bytes abaixo de 0x20). "
            "Parsers como o sofia-sip do FreeSWITCH tratam a mensagem como malformada e respondem 400 ou a descartam.",
            "Corrija o equipamento que gera o header. Caracteres de controle normalmente vem de concatenacao de "
            "strings sem sanitizacao (ex.: nome do chamador lido de banco ou CRM).",
            [f"Headers: {', '.join(names)}"],
            lines,
        )
    ]


def _check_encoding(message):
    issues = []
    if message.invalid_utf8_headers:
        names = [header_display_name(name) for name in message.invalid_utf8_headers]
        identity = any(name in IDENTITY_HEADERS for name in message.invalid_utf8_headers)
        lines = [line for name in message.invalid_utf8_headers for line in _header_lines(message, name)]
        issues.append(
            _issue(
                "sip_header_invalid_encoding",
                "high" if identity else "medium",
                0.95,
                "Headers SIP contem bytes que nao sao UTF-8 valido (tipicamente Latin-1/ISO-8859-1 em nomes com acento). "
                "SIP exige UTF-8. No FreeSWITCH o valor vira caller_id_name/sip_from_display e pode quebrar eventos ESL e JSON, "
                "CDR em banco (PostgreSQL rejeita UTF-8 invalido), mod_callcenter e a perna B do bridge.",
                "Configure o PABX/SBC de origem para enviar UTF-8, ou normalize o nome no SBC. Como contorno no FreeSWITCH, "
                "sobrescreva effective_caller_id_name no dialplan antes de bridge e de gravar CDR.",
                [f"Headers: {', '.join(names)}", "Encoding: not valid UTF-8 (probably Latin-1)"],
                lines,
            )
        )
    identity_non_ascii = [name for name in message.non_ascii_headers if name in IDENTITY_HEADERS]
    if identity_non_ascii:
        issues.append(
            _issue(
                "sip_header_non_ascii",
                "low",
                0.80,
                "Headers de identidade contem caracteres UTF-8 nao ASCII (acentos, emojis). E valido em SIP, mas gateways "
                "TDM, operadoras e bancos com encoding legado podem truncar ou rejeitar o nome do chamador.",
                "Se houver falha apenas em chamadas com nomes acentuados, normalize o display name para ASCII no SBC ou no dialplan.",
                [f"Headers: {', '.join(header_display_name(name) for name in identity_non_ascii)}"],
                [line for name in identity_non_ascii for line in _header_lines(message, name)],
            )
        )
    return issues


def _check_duplicates(message):
    duplicated = [name for name in SINGLETON_HEADERS if len(message.header_values.get(name, [])) > 1]
    if not duplicated:
        return []
    conflicting = [name for name in duplicated if len(set(message.header_values[name])) > 1]
    return [
        _issue(
            "sip_header_duplicate_singleton",
            "high",
            0.95,
            "Um header que so pode aparecer uma vez esta repetido na mensagem. O sofia-sip (FreeSWITCH) marca a "
            "mensagem como erronea e responde 400 Bad Request; outros elementos escolhem uma das copias de forma imprevisivel."
            + (" As copias tem valores diferentes." if conflicting else ""),
            "Identifique o elemento que adiciona o header pela segunda vez (geralmente SBC, B2BUA ou script de manipulacao "
            "de headers) e remova a duplicata.",
            [f"Duplicated headers: {', '.join(header_display_name(name) for name in duplicated)}"],
            [line for name in duplicated for line in _header_lines(message, name)],
        )
    ]


def _check_mandatory(message):
    required = REQUEST_MANDATORY_HEADERS if message.is_request else RESPONSE_MANDATORY_HEADERS
    missing = [name for name in required if not message.header_values.get(name)]
    if message.is_request and not message.header_values.get("max-forwards"):
        missing_max_forwards = True
    else:
        missing_max_forwards = False
    issues = []
    if missing:
        issues.append(
            _issue(
                "sip_header_missing_mandatory",
                "high",
                0.90,
                "A mensagem nao tem headers obrigatorios do SIP. Sem Via/From/To/CSeq o destino nao consegue casar "
                "transacoes nem responder, e o FreeSWITCH rejeita a requisicao com 400.",
                "Corrija o gerador da mensagem ou o intermediario que remove headers (ALG SIP, firewall, SBC).",
                [f"Missing headers: {', '.join(header_display_name(name) for name in missing)}"],
            )
        )
    if missing_max_forwards and message.header_values.get("via"):
        issues.append(
            _issue(
                "sip_header_missing_max_forwards",
                "low",
                0.85,
                "A requisicao nao tem Max-Forwards, obrigatorio pela RFC 3261. Sem ele loops de roteamento nao sao interrompidos.",
                "Configure o endpoint/SBC para enviar Max-Forwards: 70.",
                ["Missing headers: Max-Forwards"],
            )
        )
    return issues


def _check_contact(message):
    if message.contact:
        return []
    if message.is_request and message.method in DIALOG_CREATING_METHODS and message.method != "NOTIFY":
        target = f"requisicao {message.method}"
    elif (
        not message.is_request
        and message.cseq_method == "INVITE"
        and message.status_code is not None
        and 200 <= message.status_code < 300
    ):
        target = "resposta 2xx ao INVITE"
    else:
        return []
    return [
        _issue(
            "sip_header_missing_contact",
            "high",
            0.92,
            f"A {target} nao tem header Contact. Sem ele o outro lado nao sabe para onde enviar ACK, BYE e re-INVITE: "
            "o FreeSWITCH pode rejeitar a chamada ou a chamada cai/fica presa ao encerrar.",
            "Corrija o endpoint ou SBC para incluir Contact com um endereco alcancavel (respeitando NAT).",
            ["Missing headers: Contact"],
        )
    ]


def _check_cseq(message):
    if not message.is_request:
        return []
    raw = message.headers.get("cseq")
    if not raw:
        return []
    if message.cseq_number is None or message.cseq_method is None:
        return [
            _issue(
                "sip_header_cseq_mismatch",
                "high",
                0.95,
                "O header CSeq nao segue o formato 'numero METODO'. O destino nao consegue associar respostas a transacao.",
                "Corrija o gerador da mensagem para enviar CSeq no formato '1 INVITE'.",
                [f"CSeq: {raw}"],
                [f"CSeq: {raw}"],
            )
        ]
    if message.cseq_method != (message.method or "").upper():
        return [
            _issue(
                "sip_header_cseq_mismatch",
                "high",
                0.95,
                f"O metodo do CSeq ({message.cseq_method}) e diferente do metodo da requisicao ({message.method}). "
                "A RFC 3261 exige que sejam iguais; o sofia-sip responde 400.",
                "Corrija o elemento que monta ou reescreve o CSeq (comum em B2BUAs e scripts de SBC).",
                [f"CSeq: {raw}", f"Request method: {message.method}"],
                [message.start_line, f"CSeq: {raw}"],
            )
        ]
    return []


def _check_max_forwards(message):
    if not message.is_request:
        return []
    raw = message.headers.get("max-forwards")
    if raw is None:
        return []
    value = raw.strip()
    if not is_ascii_digits(value):
        return [
            _issue(
                "sip_header_max_forwards",
                "high",
                0.95,
                "O Max-Forwards nao e um numero inteiro. O destino rejeita a requisicao como malformada.",
                "Envie Max-Forwards como inteiro entre 0 e 255 (padrao 70).",
                [f"Max-Forwards: {raw}"],
                [f"Max-Forwards: {raw}"],
            )
        ]
    hops = int(value)
    if hops == 0 and message.method not in {"OPTIONS"}:
        return [
            _issue(
                "sip_header_max_forwards",
                "high",
                0.95,
                "A requisicao chegou com Max-Forwards 0: qualquer proxy ou o FreeSWITCH responde 483 Too Many Hops. "
                "Indica loop de roteamento ou valor inicial baixo.",
                "Procure loop entre proxies/SBC/FreeSWITCH (ex.: gateway apontando para o proprio servidor) e confira o valor inicial enviado.",
                [f"Max-Forwards: {hops}"],
                [f"Max-Forwards: {raw}"],
            )
        ]
    if hops <= 5:
        return [
            _issue(
                "sip_header_max_forwards",
                "medium",
                0.80,
                f"A requisicao chegou com Max-Forwards {hops}, muito abaixo do padrao 70. Ela ja passou por muitos saltos "
                "(possivel loop) e pode ser rejeitada com 483 no proximo encaminhamento.",
                "Revise o caminho de roteamento; um valor tao baixo costuma indicar loop entre servidores.",
                [f"Max-Forwards: {hops}"],
                [f"Max-Forwards: {raw}"],
            )
        ]
    return []


def _check_variable_injection(message):
    suspicious = []
    for name, values in message.header_values.items():
        for value in values:
            if _VARIABLE_PATTERN.search(value):
                suspicious.append(f"{header_display_name(name)}: {value}")
    if message.request_uri and _VARIABLE_PATTERN.search(message.request_uri):
        suspicious.insert(0, message.start_line)
    if not suspicious:
        return []
    return [
        _issue(
            "sip_header_variable_injection",
            "high",
            0.90,
            "Um header SIP contem a sintaxe de expansao de variaveis do FreeSWITCH (${...} ou $${...}). Se o valor "
            "for usado no dialplan (sip_h_*, caller_id_name, destination_number), o FreeSWITCH pode expandir a "
            "variavel ou executar uma API embutida. Trate como tentativa de injecao ou bug grave de origem.",
            "Bloqueie '$' e '{' nos headers na borda (SBC/ACL) e nunca interpole sip_h_* ou caller ID diretamente em "
            "acoes do dialplan. Confira se a origem e confiavel.",
            ["Pattern: ${...}"],
            suspicious,
        )
    ]


def _check_name_addr(message):
    malformed = []
    risky = []
    for name in NAME_ADDR_HEADERS:
        for value in message.header_values.get(name, []):
            line = f"{header_display_name(name)}: {value}"
            unescaped_quotes = len(re.findall(r'(?<!\\)"', value))
            if unescaped_quotes % 2 or value.count("<") != value.count(">"):
                malformed.append(line)
                continue
            if "<" in value:
                display = value.split("<", 1)[0].strip()
                if display and not (display.startswith('"') and display.endswith('"')):
                    if any(character in display for character in ',;:@?"\\'):
                        risky.append(line)
    issues = []
    if malformed:
        issues.append(
            _issue(
                "sip_header_malformed_address",
                "high",
                0.93,
                "Headers de endereco (From/To/Contact/identidade) tem aspas ou '<>' desbalanceados. O parser nao "
                "consegue extrair a URI: o FreeSWITCH responde 400 ou extrai usuario/tag errados.",
                "Corrija a montagem do display name na origem; nomes com aspas internas precisam ser escapados (\\\").",
                [f"Malformed headers: {len(malformed)}"],
                malformed,
            )
        )
    if risky:
        issues.append(
            _issue(
                "sip_header_malformed_address",
                "medium",
                0.80,
                "Display name sem aspas contem caracteres especiais (, ; : @ ?). Pela gramatica SIP eles exigem aspas; "
                "em Contact a virgula separa enderecos e o FreeSWITCH pode interpretar dois contatos ou uma URI errada.",
                "Coloque o display name entre aspas na origem (ex.: \"Silva, Joao\" <sip:...>).",
                [f"Unquoted display names: {len(risky)}"],
                risky,
            )
        )
    return issues


def _check_request_uri(message):
    if not message.is_request or not message.request_uri:
        return []
    uri = message.request_uri
    problems = []
    if any(character.isspace() for character in uri):
        problems.append("contains whitespace")
    scheme = uri.split(":", 1)[0].lower() if ":" in uri else ""
    if scheme not in {"sip", "sips", "tel"}:
        problems.append(f"unsupported scheme '{scheme or '-'}'")
    user = _uri_user(uri)
    if user:
        forbidden = sorted({character for character in user if character in _URI_USER_FORBIDDEN or ord(character) > 126})
        if forbidden:
            problems.append(f"unescaped characters in user part: {' '.join(forbidden)}")
        if _BAD_ESCAPE_PATTERN.search(user):
            problems.append("invalid % escape in user part")
    if not problems:
        return []
    severe = any(problem.startswith(("contains", "unsupported")) for problem in problems)
    return [
        _issue(
            "sip_request_uri_invalid",
            "high" if severe else "medium",
            0.90,
            "A Request-URI tem formato invalido. O FreeSWITCH usa o usuario da Request-URI como destination_number: "
            "caracteres nao escapados (#, espaco, acento) podem gerar 400/416, truncar o numero ou fazer o dialplan "
            "nao casar nenhuma extensao (404/NO_ROUTE_DESTINATION).",
            "Escape caracteres especiais (# vira %23) ou normalize o numero no SBC antes de enviar ao FreeSWITCH.",
            [f"Request-URI: {uri}", *(f"Problem: {problem}" for problem in problems)],
            [message.start_line],
        )
    ]


def _uri_user(uri):
    if ":" not in uri:
        return None
    rest = uri.split(":", 1)[1]
    if "@" not in rest:
        return rest.split(";", 1)[0] if uri.lower().startswith("tel:") else None
    return rest.split("@", 1)[0].split(";", 1)[0]


def _check_content_headers(message):
    issues = []
    encoding = message.headers.get("content-encoding", "").strip()
    if encoding and encoding.lower() != "identity":
        issues.append(
            _issue(
                "sip_header_content_encoding",
                "medium",
                0.85,
                f"O corpo foi enviado com Content-Encoding '{encoding}'. O FreeSWITCH nao descomprime o SDP e "
                "responde 415 ou nao encontra a oferta de midia.",
                "Desabilite a compressao do corpo SIP na origem.",
                [f"Content-Encoding: {encoding}"],
                [f"Content-Encoding: {encoding}"],
            )
        )
    has_body = bool(message.body_text.strip())
    if has_body and not message.headers.get("content-type"):
        issues.append(
            _issue(
                "sip_header_missing_content_type",
                "high",
                0.90,
                "A mensagem tem corpo mas nao tem Content-Type. O destino nao sabe que o corpo e SDP e ignora a oferta "
                "(chamada sem audio) ou responde 400/415.",
                "Inclua 'Content-Type: application/sdp' quando houver SDP.",
                ["Missing headers: Content-Type"],
            )
        )
    if message.transport == "TCP" and "content-length" not in message.header_values:
        issues.append(
            _issue(
                "sip_header_tcp_missing_content_length",
                "high",
                0.90,
                "Mensagem SIP sobre TCP sem Content-Length. Em TCP ele e obrigatorio para delimitar mensagens: o destino "
                "junta o corpo com a proxima mensagem ou trava aguardando dados.",
                "Corrija a pilha SIP da origem para sempre enviar Content-Length em TCP/TLS.",
                ["Missing headers: Content-Length", "Transport: TCP"],
            )
        )
    return issues


def _check_line_format(message):
    issues = []
    if message.invalid_header_names:
        issues.append(
            _issue(
                "sip_header_invalid_name",
                "medium",
                0.90,
                "Nomes de header contem caracteres invalidos (espaco, acento, '/' ou outros fora da gramatica token). "
                "Parsers estritos rejeitam a mensagem; o FreeSWITCH pode ignorar o header ou responder 400.",
                "Corrija o nome do header na origem (headers personalizados devem usar apenas letras, numeros e '-').",
                [f"Invalid header names: {', '.join(message.invalid_header_names[:5])}"],
                message.invalid_header_names[:5],
            )
        )
    if message.bare_lf_lines:
        issues.append(
            _issue(
                "sip_header_bare_lf",
                "medium",
                0.85,
                "Linhas de header terminam apenas com LF em vez de CRLF. A RFC 3261 exige CRLF; parsers estritos, ALGs "
                "e alguns SBCs cortam a mensagem ou nao encontram o fim dos headers.",
                "Corrija o gerador da mensagem para usar CRLF (\\r\\n) em todas as linhas.",
                [f"LF-only lines: {message.bare_lf_lines}"],
            )
        )
    if message.folded_lines:
        issues.append(
            _issue(
                "sip_header_folding",
                "low",
                0.80,
                "A mensagem usa continuacao de header em varias linhas (line folding). E legado e varios elementos de "
                "rede nao tratam corretamente.",
                "Envie cada header em uma unica linha.",
                [f"Folded lines: {message.folded_lines}"],
            )
        )
    return issues


def _check_from_tag(message):
    if not message.is_request or message.method not in INITIAL_REQUEST_METHODS:
        return []
    from_header = message.headers.get("from")
    if not from_header or message.from_tag:
        return []
    return [
        _issue(
            "sip_header_missing_from_tag",
            "medium",
            0.88,
            "O header From nao tem o parametro tag, obrigatorio na RFC 3261. Sem ele o dialogo nao pode ser "
            "identificado e BYE/re-INVITE podem ser respondidos com 481.",
            "Atualize ou configure o endpoint para gerar From-tag (pilhas RFC 2543 antigas omitem).",
            [f"From: {from_header}"],
            [f"From: {from_header}"],
        )
    ]


def _check_version(message):
    if message.sip_version.upper() == "SIP/2.0":
        return []
    return [
        _issue(
            "sip_header_invalid_version",
            "high",
            0.95,
            f"A start-line usa a versao '{message.sip_version}' em vez de SIP/2.0. O destino responde 505 ou descarta a mensagem.",
            "Corrija a start-line na origem.",
            [f"SIP version: {message.sip_version}"],
            [message.start_line],
        )
    ]


def _check_sdp(message):
    content_type = message.headers.get("content-type", "").lower()
    body = message.body_text
    if "application/sdp" not in content_type or not body.strip() or "multipart" in content_type:
        return []
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    issues = []
    present = {line[0] for line in lines if len(line) > 1 and line[1] == "="}
    missing = [field for field in ("v", "o", "s", "t") if field not in present]
    invalid_lines = [line for line in lines if len(line) < 2 or line[1] != "=" or not line[0].isalpha()]
    has_connection = "c" in present
    audio = [media for media in message.sdp_media if media.media_type == "audio" and media.port > 0]
    problems = []
    if missing:
        problems.append(f"missing {', '.join(f'{field}=' for field in missing)}")
    if invalid_lines:
        problems.append(f"invalid lines: {len(invalid_lines)}")
    if audio and not has_connection:
        problems.append("no c= line")
    if "m" not in present:
        problems.append("no m= line")
    if problems:
        issues.append(
            _issue(
                "sip_sdp_malformed",
                "high",
                0.90,
                "O SDP esta incompleto ou malformado. O FreeSWITCH nao consegue interpretar a oferta e responde "
                "488 Not Acceptable Here (INCOMPATIBLE_DESTINATION) ou estabelece a chamada sem audio.",
                "Corrija o gerador do SDP: v=, o=, s=, t=, c= e m= sao obrigatorios (RFC 4566).",
                [f"SDP problem: {problem}" for problem in problems],
                invalid_lines[:4],
            )
        )
    for media in audio:
        dynamic = [payload for payload in media.payload_types if 96 <= payload <= 127 and payload not in media.codecs]
        if dynamic:
            issues.append(
                _issue(
                    "sip_sdp_dynamic_payload_without_rtpmap",
                    "medium",
                    0.90,
                    "O SDP oferece payload types dinamicos (96-127) sem a linha a=rtpmap correspondente. O FreeSWITCH "
                    "nao sabe qual codec eles representam e pode recusar a oferta (488) ou ignorar o DTMF RFC 2833.",
                    "Inclua a=rtpmap para cada payload type dinamico (ex.: a=rtpmap:101 telephone-event/8000).",
                    [f"Payload types without rtpmap: {dynamic}"],
                    [f"m={media.media_type} {media.port} {media.protocol} {' '.join(str(item) for item in media.payload_types)}"],
                )
            )
        if media.protocol.upper() in _SECURE_PROFILES:
            issues.append(
                _issue(
                    "sip_sdp_secure_transport",
                    "low",
                    0.75,
                    f"A oferta de audio usa o perfil seguro {media.protocol} (SRTP/DTLS). Se o perfil Sofia do FreeSWITCH "
                    "nao tiver SRTP/DTLS habilitado, a chamada e recusada com 488.",
                    "Confirme rtp_secure_media no FreeSWITCH ou desabilite SRTP obrigatorio no endpoint.",
                    [f"Media profile: {media.protocol}"],
                    [f"m={media.media_type} {media.port} {media.protocol} {' '.join(str(item) for item in media.payload_types)}"],
                )
            )
    return issues


def _check_require(message):
    if not message.is_request:
        return []
    raw = ", ".join(message.header_values.get("require", []))
    if not raw:
        return []
    tags = [tag.strip().lower() for tag in raw.split(",") if tag.strip()]
    unsupported = [tag for tag in tags if tag not in FREESWITCH_SUPPORTED_REQUIRE]
    issues = []
    if unsupported:
        issues.append(
            _issue(
                "sip_header_require_unsupported",
                "medium",
                0.80,
                "A requisicao exige (Require) extensoes que o FreeSWITCH nao implementa. Ele responde 420 Bad Extension "
                "e a chamada falha.",
                "Remova o option-tag do Require na origem/SBC ou mova-o para Supported.",
                [f"Require: {raw}", f"Unsupported option tags: {', '.join(unsupported)}"],
                [f"Require: {raw}"],
            )
        )
    elif "100rel" in tags:
        issues.append(
            _issue(
                "sip_header_require_unsupported",
                "low",
                0.70,
                "A requisicao exige 100rel (PRACK). O FreeSWITCH so aceita com enable-100rel=true no perfil Sofia; "
                "caso contrario responde 420.",
                "Habilite enable-100rel no perfil Sofia ou mova 100rel de Require para Supported na origem.",
                [f"Require: {raw}"],
                [f"Require: {raw}"],
            )
        )
    return issues
