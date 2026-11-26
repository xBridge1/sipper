"""Plain-text summaries ready to paste into a ticket or an e-mail to a carrier."""

from ciper.labels import state_label, verdict_status_label


def _verdict_block(verdict):
    lines = [
        f"Veredito: {verdict_status_label(verdict.get('status')).upper()} - {verdict.get('headline', '-')}",
    ]
    if verdict.get("status") != "ok":
        lines.append(
            f"Provavel culpado: {verdict.get('culprit', '-')} "
            f"(confianca {verdict.get('confidence_label', '-')}, {float(verdict.get('confidence') or 0):.0%})"
        )
    if verdict.get("confirmed_by"):
        lines.append(f"Confirmado pela resposta: {verdict['confirmed_by']}")
    if verdict.get("propagated_from"):
        lines.append(f"Causa originada na perna B: Call-ID {verdict['propagated_from']}")
    reasons = verdict.get("reasons") or []
    if reasons:
        lines.append("")
        lines.append("Evidencias:")
        lines.extend(f"  - {item}" for item in reasons)
    offending = verdict.get("offending_lines") or []
    if offending:
        lines.append("")
        lines.append("Linha(s) com problema na mensagem SIP:")
        lines.extend(f"  {item}" for item in offending)
    actions = verdict.get("actions") or []
    if actions:
        lines.append("")
        lines.append("Proximos passos:")
        lines.extend(f"  {index}. {item}" for index, item in enumerate(actions, start=1))
    return lines


def build_capture_ticket(diagnosis, source_name="", capture_point=None):
    lines = ["SIPPER - Resumo do diagnostico"]
    if source_name:
        lines.append(f"Arquivo: {source_name}")
    if capture_point and capture_point.get("ip"):
        how = "detectado" if capture_point.get("auto") else "informado"
        lines.append(f"Ponto de captura: {capture_point['ip']} ({how})")
    calls = diagnosis.get("calls") or {}
    if calls.get("total"):
        lines.append(
            f"Chamadas: {calls['total']} | falha {calls.get('fail', 0)} | degradada {calls.get('degraded', 0)} | "
            f"risco {calls.get('risk', 0)} | normal {calls.get('user', 0)} | ok {calls.get('ok', 0)}"
        )
    lines.append("")
    lines.extend(_verdict_block(diagnosis))
    breakdown = diagnosis.get("breakdown") or []
    if len(breakdown) > 1:
        lines.append("")
        lines.append("Causas por chamada:")
        lines.extend(f"  - {item['title']}: {item['calls']} chamada(s) - {item.get('culprit') or '-'}" for item in breakdown)
    if diagnosis.get("worst_call_id"):
        lines.append("")
        lines.append(f"Chamada de referencia: Call-ID {diagnosis['worst_call_id']}")
    return "\n".join(lines)


def build_call_ticket(call, source_name=""):
    lines = ["SIPPER - Resumo da chamada"]
    if source_name:
        lines.append(f"Arquivo: {source_name}")
    lines.append(f"Call-ID: {call.get('call_id', '-')}")
    lines.append(f"Origem -> destino: {call.get('source_ip', '-')} -> {call.get('destination_ip', '-')}")
    lines.append(
        f"Sinalizacao: {state_label(call.get('signaling_state'))} | Midia: {state_label(call.get('media_state'))}"
    )
    hangup = call.get("hangup")
    if hangup:
        cause = f", Q.850 {hangup['q850']}" if hangup.get("q850") else ""
        lines.append(f"Encerrada por: {hangup['by']} ({hangup['side']}, {hangup['method']}{cause})")
    legs = call.get("legs")
    if legs:
        peers = ", ".join(peer["call_id"] for peer in legs.get("peers", []))
        lines.append(f"Perna {legs['role']} via {legs['b2bua_ip']}; perna(s) relacionada(s): {peers}")
    lines.append("")
    lines.extend(_verdict_block(call.get("verdict") or {}))
    return "\n".join(lines)
