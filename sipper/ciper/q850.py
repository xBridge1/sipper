"""ITU-T Q.850 release causes carried in the SIP ``Reason`` header.

FreeSWITCH, SBCs and carriers add ``Reason: Q.850;cause=NN;text="..."`` to
BYE, CANCEL and final responses. The cause often says more than the SIP
status code (a 503 may hide "no circuit available" or "network out of
order"), so it is used to sharpen the probable culprit.

``blame`` uses the same vocabulary as ``ciper.sip_status``: ``user`` for
normal outcomes, ``requester``, ``responder``, ``downstream`` (network
beyond the responder) and ``negotiation``.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Q850Cause:
    cause: int
    name: str
    meaning: str
    blame: str
    freeswitch: str


_CAUSES = {
    1: Q850Cause(1, "Unallocated number", "Numero inexistente", "requester", "UNALLOCATED_NUMBER"),
    2: Q850Cause(2, "No route to network", "Sem rota para a rede de destino", "responder", "NO_ROUTE_TRANSIT_NET"),
    3: Q850Cause(3, "No route to destination", "Sem rota para o destino", "responder", "NO_ROUTE_DESTINATION"),
    6: Q850Cause(6, "Channel unacceptable", "Canal inaceitavel", "downstream", "CHANNEL_UNACCEPTABLE"),
    16: Q850Cause(16, "Normal call clearing", "Encerramento normal (alguem desligou)", "user", "NORMAL_CLEARING"),
    17: Q850Cause(17, "User busy", "Usuario ocupado", "user", "USER_BUSY"),
    18: Q850Cause(18, "No user responding", "Usuario nao respondeu (sem resposta do terminal)", "downstream", "NO_USER_RESPONSE"),
    19: Q850Cause(19, "No answer from user", "Tocou e ninguem atendeu", "user", "NO_ANSWER"),
    20: Q850Cause(20, "Subscriber absent", "Assinante ausente (nao registrado/desligado)", "user", "SUBSCRIBER_ABSENT"),
    21: Q850Cause(21, "Call rejected", "Chamada rejeitada pelo destino", "user", "CALL_REJECTED"),
    22: Q850Cause(22, "Number changed", "Numero alterado", "requester", "NUMBER_CHANGED"),
    27: Q850Cause(27, "Destination out of order", "Destino fora de servico/inalcancavel", "downstream", "DESTINATION_OUT_OF_ORDER"),
    28: Q850Cause(28, "Invalid number format", "Formato de numero invalido", "requester", "INVALID_NUMBER_FORMAT"),
    29: Q850Cause(29, "Facility rejected", "Facilidade rejeitada", "responder", "FACILITY_REJECTED"),
    31: Q850Cause(31, "Normal, unspecified", "Normal, nao especificado", "user", "NORMAL_UNSPECIFIED"),
    34: Q850Cause(34, "No circuit/channel available", "Sem circuito/canal disponivel (congestionamento)", "responder", "NORMAL_CIRCUIT_CONGESTION"),
    38: Q850Cause(38, "Network out of order", "Rede fora de servico", "downstream", "NETWORK_OUT_OF_ORDER"),
    41: Q850Cause(41, "Temporary failure", "Falha temporaria", "responder", "NORMAL_TEMPORARY_FAILURE"),
    42: Q850Cause(42, "Switching equipment congestion", "Congestionamento no equipamento", "responder", "SWITCH_CONGESTION"),
    44: Q850Cause(44, "Requested channel not available", "Canal solicitado indisponivel", "responder", "REQUESTED_CHAN_UNAVAIL"),
    47: Q850Cause(47, "Resource unavailable", "Recurso indisponivel", "responder", "RESOURCE_UNAVAILABLE"),
    50: Q850Cause(50, "Facility not subscribed", "Servico nao contratado", "responder", "FACILITY_NOT_SUBSCRIBED"),
    52: Q850Cause(52, "Outgoing calls barred", "Chamadas de saida bloqueadas", "responder", "OUTGOING_CALL_BARRED"),
    54: Q850Cause(54, "Incoming calls barred", "Chamadas de entrada bloqueadas", "responder", "INCOMING_CALL_BARRED"),
    57: Q850Cause(57, "Bearer capability not authorized", "Capacidade de portadora nao autorizada", "responder", "BEARERCAPABILITY_NOTAUTH"),
    58: Q850Cause(58, "Bearer capability not available", "Capacidade de portadora indisponivel", "negotiation", "BEARERCAPABILITY_NOTAVAIL"),
    63: Q850Cause(63, "Service not available", "Servico indisponivel", "responder", "SERVICE_UNAVAILABLE"),
    65: Q850Cause(65, "Bearer capability not implemented", "Capacidade de portadora nao implementada", "negotiation", "BEARERCAPABILITY_NOTIMPL"),
    79: Q850Cause(79, "Service not implemented", "Servico nao implementado", "responder", "SERVICE_NOT_IMPLEMENTED"),
    81: Q850Cause(81, "Invalid call reference", "Referencia de chamada invalida", "requester", "INVALID_CALL_REFERENCE"),
    88: Q850Cause(88, "Incompatible destination", "Destino incompativel (codec/midia)", "negotiation", "INCOMPATIBLE_DESTINATION"),
    95: Q850Cause(95, "Invalid message", "Mensagem invalida", "requester", "INVALID_MSG_UNSPECIFIED"),
    96: Q850Cause(96, "Mandatory IE missing", "Informacao obrigatoria ausente", "requester", "MANDATORY_IE_MISSING"),
    97: Q850Cause(97, "Message type non-existent", "Tipo de mensagem inexistente", "requester", "MESSAGE_TYPE_NONEXIST"),
    100: Q850Cause(100, "Invalid IE contents", "Conteudo de informacao invalido", "requester", "INVALID_IE_CONTENTS"),
    102: Q850Cause(102, "Recovery on timer expiry", "Timeout aguardando resposta", "downstream", "RECOVERY_ON_TIMER_EXPIRE"),
    111: Q850Cause(111, "Protocol error", "Erro de protocolo", "requester", "PROTOCOL_ERROR"),
    127: Q850Cause(127, "Interworking, unspecified", "Erro de interconexao nao especificado (outra rede)", "downstream", "INTERWORKING"),
}

_REASON_PATTERN = re.compile(r"Q\.850\s*;([^,]*)", re.IGNORECASE)
_CAUSE_PATTERN = re.compile(r"cause\s*=\s*(\d+)", re.IGNORECASE)
_TEXT_PATTERN = re.compile(r'text\s*=\s*"([^"]*)"', re.IGNORECASE)


def q850_cause(cause):
    if cause is None:
        return None
    known = _CAUSES.get(cause)
    if known is not None:
        return known
    return Q850Cause(cause, f"Cause {cause}", f"Causa Q.850 {cause}", "downstream", "")


def parse_q850_reason(value):
    """Return (Q850Cause, text) from a Reason header value, or (None, None)."""
    if not value:
        return None, None
    match = _REASON_PATTERN.search(value)
    if not match:
        return None, None
    params = match.group(1)
    cause_match = _CAUSE_PATTERN.search(params)
    if not cause_match:
        return None, None
    text_match = _TEXT_PATTERN.search(params)
    return q850_cause(int(cause_match.group(1))), (text_match.group(1) if text_match else None)


def message_q850(message):
    """Q.850 cause of a SIP message (any Reason header value), or (None, None)."""
    for value in message.header_values.get("reason", []):
        cause, text = parse_q850_reason(value)
        if cause is not None:
            return cause, text
    return None, None
