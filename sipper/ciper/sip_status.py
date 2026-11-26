"""What a final SIP response says about who caused a call failure.

Each entry tells the diagnosis engine:

- ``meaning``: plain-language meaning of the code;
- ``blame``: which side the evidence points at:
  ``requester`` (the side that sent the request did something wrong),
  ``responder`` (the side that answered refused, failed or lacks config),
  ``negotiation`` (both sides: offer and capabilities do not match),
  ``downstream`` (the responder is relaying a failure from further ahead),
  ``user`` (a normal call outcome, such as busy or declined, not a fault);
- ``explanation``: why that side is the probable culprit;
- ``action``: the next concrete check;
- ``freeswitch``: the hangup causes FreeSWITCH usually maps to the code,
  so the analyst can match the capture with ``fs_cli`` and CDR output.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class SIPStatusInfo:
    code: int
    meaning: str
    blame: str
    explanation: str
    action: str
    freeswitch: str = ""

    @property
    def is_fault(self):
        return self.blame != "user"


_STATUS = {
    400: SIPStatusInfo(
        400,
        "Requisicao malformada",
        "requester",
        "O destino nao conseguiu interpretar a mensagem: header obrigatorio ausente, duplicado ou com sintaxe invalida.",
        "Inspecione os headers da requisicao que recebeu o 400. O reason phrase costuma indicar o header problematico.",
    ),
    401: SIPStatusInfo(
        401,
        "Autenticacao exigida",
        "requester",
        "O registrar/servidor pediu credenciais e a requisicao autenticada nao foi aceita.",
        "Confira usuario, senha e realm configurados no endpoint ou gateway.",
    ),
    402: SIPStatusInfo(402, "Pagamento exigido", "responder", "O provedor recusou por politica comercial ou credito.", "Verifique creditos ou contrato com o provedor."),
    403: SIPStatusInfo(
        403,
        "Proibido",
        "responder",
        "O destino entendeu a requisicao e recusou por politica: ACL, autenticacao falha, numero bloqueado ou origem nao autorizada.",
        "Revise ACL, credenciais e regras de permissao do destino. No FreeSWITCH, confira apply-inbound-acl e auth-calls do perfil Sofia.",
        "CALL_REJECTED quando gerado por politica",
    ),
    404: SIPStatusInfo(
        404,
        "Destino nao encontrado",
        "responder",
        "O destino nao encontrou rota ou usuario para o numero pedido.",
        "Confira se o numero discado existe e se o dialplan/roteamento do destino tem uma regra que o atende.",
        "NO_ROUTE_DESTINATION ou UNALLOCATED_NUMBER",
    ),
    405: SIPStatusInfo(405, "Metodo nao permitido", "requester", "O destino nao aceita este metodo SIP.", "Use um metodo listado no header Allow da resposta."),
    406: SIPStatusInfo(406, "Nao aceitavel", "negotiation", "O destino nao consegue gerar uma resposta no formato aceito pela origem.", "Revise os headers Accept da requisicao."),
    407: SIPStatusInfo(
        407,
        "Autenticacao de proxy exigida",
        "requester",
        "O proxy pediu credenciais e a requisicao autenticada nao foi aceita.",
        "Confira usuario, senha e realm do proxy.",
    ),
    408: SIPStatusInfo(
        408,
        "Tempo esgotado",
        "downstream",
        "O destino nao obteve resposta a tempo do proximo salto ou do usuario chamado.",
        "Verifique o proximo salto depois de quem respondeu: gateway, ramal ou operadora sem resposta.",
        "NO_USER_RESPONSE ou RECOVERY_ON_TIMER_EXPIRE",
    ),
    410: SIPStatusInfo(410, "Destino nao existe mais", "responder", "O numero ou usuario foi desativado no destino.", "Atualize o numero de destino."),
    413: SIPStatusInfo(
        413,
        "Mensagem grande demais",
        "requester",
        "O corpo ou a mensagem excede o limite aceito pelo destino.",
        "Reduza headers e SDP ou use transporte TCP.",
    ),
    414: SIPStatusInfo(414, "Request-URI grande demais", "requester", "A Request-URI excede o limite do destino.", "Encurte a Request-URI e seus parametros."),
    415: SIPStatusInfo(
        415,
        "Tipo de corpo nao suportado",
        "requester",
        "O destino nao entende o Content-Type ou Content-Encoding do corpo enviado.",
        "Envie o SDP como application/sdp sem compressao (Content-Encoding).",
    ),
    416: SIPStatusInfo(416, "Esquema de URI nao suportado", "requester", "O destino nao trata o esquema da Request-URI (ex.: tel:, sips:).", "Use sip: ou habilite o esquema no destino."),
    420: SIPStatusInfo(
        420,
        "Extensao nao suportada",
        "negotiation",
        "A requisicao exige (Require) uma extensao SIP que o destino nao implementa ou nao tem habilitada.",
        "Veja o header Unsupported da resposta e remova o option-tag do Require, ou habilite a extensao (ex.: enable-100rel no FreeSWITCH).",
    ),
    421: SIPStatusInfo(421, "Extensao exigida", "negotiation", "O destino exige uma extensao que a origem nao ofereceu.", "Veja o header Require da resposta e habilite a extensao na origem."),
    422: SIPStatusInfo(
        422,
        "Session timer curto demais",
        "negotiation",
        "O Session-Expires proposto e menor que o Min-SE aceito pelo destino.",
        "Aumente Session-Expires na origem ou reduza minimum-session-expires no destino.",
    ),
    423: SIPStatusInfo(423, "Intervalo curto demais", "requester", "O Expires do REGISTER e menor que o minimo aceito.", "Use o valor do header Min-Expires da resposta."),
    480: SIPStatusInfo(
        480,
        "Temporariamente indisponivel",
        "user",
        "O usuario chamado nao esta disponivel (nao registrado, nao atendeu ou em DND). Normalmente nao e falha de rede.",
        "Confirme se o ramal/usuario estava registrado e disponivel no momento da chamada.",
        "NO_ANSWER, USER_NOT_REGISTERED ou SUBSCRIBER_ABSENT",
    ),
    481: SIPStatusInfo(
        481,
        "Dialogo/transacao inexistente",
        "requester",
        "A requisicao referencia um dialogo que o destino nao conhece: tags, Call-ID ou CSeq divergentes, ou o dialogo ja foi encerrado.",
        "Compare Call-ID, From-tag e To-tag com o dialogo original; procure SBC/ALG reescrevendo headers.",
    ),
    482: SIPStatusInfo(482, "Loop detectado", "responder", "A requisicao voltou para um servidor por onde ja havia passado.", "Revise o roteamento entre os proxies; ha uma rota circular."),
    483: SIPStatusInfo(
        483,
        "Saltos demais",
        "requester",
        "O Max-Forwards chegou a zero: loop de roteamento ou valor inicial baixo demais.",
        "Revise loops de roteamento e o Max-Forwards enviado pela origem (o padrao e 70).",
    ),
    484: SIPStatusInfo(
        484,
        "Endereco incompleto",
        "requester",
        "O numero discado esta incompleto ou fora do formato esperado pelo destino.",
        "Confira o formato do numero (E.164, prefixos) na Request-URI.",
        "INVALID_NUMBER_FORMAT",
    ),
    485: SIPStatusInfo(485, "Destino ambiguo", "requester", "O destino corresponde a mais de um usuario.", "Use um endereco mais especifico."),
    486: SIPStatusInfo(486, "Ocupado", "user", "O usuario chamado estava ocupado. E um resultado normal da chamada.", "Nenhuma acao tecnica, salvo se o ramal deveria estar livre.", "USER_BUSY"),
    487: SIPStatusInfo(
        487,
        "Requisicao terminada",
        "user",
        "O INVITE foi encerrado por um CANCEL (o chamador desistiu ou o fork foi atendido em outro ponto).",
        "Normal apos CANCEL. Se o cancelamento foi inesperado, investigue o tempo ate o toque.",
        "ORIGINATOR_CANCEL",
    ),
    488: SIPStatusInfo(
        488,
        "Midia nao aceitavel",
        "negotiation",
        "A oferta SDP nao tem codec, transporte (RTP/SAVP, DTLS) ou atributo compativel com o destino.",
        "Compare os codecs do SDP com a lista aceita pelo destino (no FreeSWITCH: inbound-codec-prefs / absolute_codec_string) e o perfil de transporte RTP/SRTP.",
        "INCOMPATIBLE_DESTINATION",
    ),
    489: SIPStatusInfo(489, "Evento nao suportado", "negotiation", "O destino nao suporta o pacote de eventos pedido.", "Revise o header Event do SUBSCRIBE/NOTIFY."),
    491: SIPStatusInfo(491, "Requisicao pendente", "negotiation", "Dois re-INVITEs cruzaram ao mesmo tempo (glare).", "Normal se ocorrer pouco; os lados devem repetir apos um intervalo aleatorio."),
    493: SIPStatusInfo(493, "Nao decifravel", "negotiation", "O destino nao conseguiu decifrar o corpo S/MIME.", "Revise a configuracao de criptografia do corpo."),
    500: SIPStatusInfo(
        500,
        "Erro interno do servidor",
        "responder",
        "O destino encontrou um erro interno ao processar a requisicao.",
        "Verifique os logs do servidor que respondeu no horario da chamada.",
    ),
    501: SIPStatusInfo(501, "Nao implementado", "responder", "O destino nao implementa o metodo pedido.", "Use um metodo suportado pelo destino."),
    502: SIPStatusInfo(
        502,
        "Gateway invalido",
        "downstream",
        "O destino recebeu uma resposta invalida do proximo salto (gateway ou operadora).",
        "Investigue o proximo salto depois do servidor que respondeu.",
        "DESTINATION_OUT_OF_ORDER ou NETWORK_OUT_OF_ORDER",
    ),
    503: SIPStatusInfo(
        503,
        "Servico indisponivel",
        "responder",
        "O destino esta sobrecarregado, em manutencao ou sem rota/gateway disponivel para completar a chamada.",
        "Verifique carga, limites de sessao (max-sessions/sessions-per-second) e o estado dos gateways de saida do destino.",
        "NORMAL_TEMPORARY_FAILURE ou NORMAL_CIRCUIT_CONGESTION",
    ),
    504: SIPStatusInfo(
        504,
        "Tempo esgotado no gateway",
        "downstream",
        "O destino nao recebeu resposta a tempo do proximo salto.",
        "Verifique o alcance do proximo salto e consultas DNS do servidor que respondeu.",
        "RECOVERY_ON_TIMER_EXPIRE",
    ),
    505: SIPStatusInfo(505, "Versao SIP nao suportada", "requester", "A requisicao usa versao SIP diferente de SIP/2.0.", "Corrija a versao na start-line."),
    513: SIPStatusInfo(
        513,
        "Mensagem grande demais",
        "requester",
        "A mensagem excede o tamanho que o destino aceita (geralmente via UDP).",
        "Reduza headers e SDP ou mude para TCP.",
    ),
    580: SIPStatusInfo(580, "Falha de precondicao", "negotiation", "As precondicoes de QoS exigidas nao puderam ser atendidas.", "Desabilite preconditions ou alinhe o suporte nos dois lados."),
    600: SIPStatusInfo(600, "Ocupado em todos os pontos", "user", "O usuario esta ocupado em todos os dispositivos.", "Nenhuma acao tecnica.", "USER_BUSY"),
    603: SIPStatusInfo(603, "Recusada", "user", "O usuario chamado recusou a chamada.", "Nenhuma acao tecnica, salvo se a recusa foi automatica (DND, regra de bloqueio).", "CALL_REJECTED"),
    604: SIPStatusInfo(604, "Nao existe em lugar nenhum", "responder", "O destino afirma que o numero nao existe.", "Confira o numero discado.", "UNALLOCATED_NUMBER"),
    606: SIPStatusInfo(606, "Nao aceitavel", "negotiation", "Nenhuma parte da oferta e aceitavel para o usuario chamado.", "Revise codecs e tipos de midia ofertados."),
}

_CLASS_DEFAULTS = {
    4: SIPStatusInfo(0, "Erro do cliente", "requester", "O destino recusou a requisicao por um problema nela.", "Leia o reason phrase e os headers da resposta."),
    5: SIPStatusInfo(0, "Erro do servidor", "responder", "O servidor que respondeu falhou ao processar uma requisicao valida.", "Verifique os logs do servidor que respondeu."),
    6: SIPStatusInfo(0, "Falha global", "user", "O usuario chamado recusou a chamada em todos os pontos.", "Confirme com o usuario chamado."),
}


def sip_status_info(code):
    if code is None:
        return None
    info = _STATUS.get(code)
    if info is not None:
        return info
    default = _CLASS_DEFAULTS.get(code // 100)
    if default is None:
        return None
    return SIPStatusInfo(code, default.meaning, default.blame, default.explanation, default.action)


# Codes that are normal call outcomes, never technical failures.
USER_OUTCOME_CODES = frozenset(code for code, info in _STATUS.items() if info.blame == "user")

# Codes a message-level defect (bad header, bad SDP) typically produces.
MESSAGE_REJECTION_CODES = frozenset({400, 413, 414, 415, 416, 420, 421, 422, 483, 484, 488, 505, 513, 606})
