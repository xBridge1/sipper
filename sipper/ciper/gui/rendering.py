"""HTML renderers for call, finding and verdict detail panels.

Mixin of ``SipperWindow``; split out of ``ciper/gui/app.py``.
"""

from ciper.gui.evidence import build_finding_evidence_context
from ciper.labels import finding_title, severity_label, state_label, verdict_status_label
from ciper.gui.theme import THEMES
from ciper.gui.widgets import VERDICT_TONES
from ciper.voip_quality import (
    jitter_observation,
    mos_observation,
    packet_loss_observation,
    quality_reference_note,
)


class HtmlRenderingMixin:
    def _render_call_text(self, widget, call):
        if call is None:
            widget.setPlainText("Nenhuma chamada detectada.")
            return
        palette = THEMES[self.current_theme]
        evidence = call.get("key_evidence_display") or call["key_evidence"] or ["Sem evidencias resumidas."]
        rtp_metrics = call["rtp_metrics"]
        loss_observation = packet_loss_observation(rtp_metrics["loss_percent"])
        jitter_observation_text = jitter_observation(
            rtp_metrics["average_jitter"],
            rtp_metrics["max_jitter"],
        )
        timings = call.get("signaling_timings", {})
        quality_metrics = call.get("media_quality_metrics", {})
        operations = call.get("signaling_operations", {})
        mos = quality_metrics.get("mos_estimate")
        mos_text = mos_observation(mos) if mos is not None else "MOS indisponivel: nao houve RTP correlacionado."
        operation_items = [
            f"re-INVITE: {operations.get('reinvites', 0)}",
            f"hold: {operations.get('holds', 0)}",
            f"resume: {operations.get('resumes', 0)}",
            f"TRANSFER: {operations.get('transfers', 0)}",
            f"OPTIONS: {operations.get('options', 0)}",
        ]
        direction_lines = [
            f"{direction}: {metric['packet_count']} pacotes, {metric['loss_percent']:.2f}% de perda, jitter max {metric['max_jitter'] * 1000:.1f} ms"
            for direction, metric in rtp_metrics.get("directions", {}).items()
        ]
        direction_html = "".join(
            f"<li style='margin-bottom:4px;'>{self._escape_html(line)}</li>" for line in direction_lines
        ) or "<li>Sem direcoes RTP correlacionadas.</li>"
        evidence_html = "".join(
            f"<li style='margin-bottom:4px;'>{self._escape_html(item)}</li>" for item in evidence
        )
        widget.setHtml(
            f"""
            <div style="font-family:'Segoe UI'; color:{palette['text']};">
                <div style="font-size:20px; font-weight:700; margin-bottom:8px;">{self._escape_html(call['call_id'])}</div>
                <div style="margin-bottom:12px;">
                    {self._chip_html(state_label(call['signaling_state']), self._signal_color(call['signaling_state'], palette), palette)}
                    &nbsp;
                    {self._chip_html(state_label(call['media_state']), self._media_color(call['media_state'], palette), palette)}
                    &nbsp;
                    {self._chip_html('Severidade ' + severity_label(call['severity']), self._severity_color(call['severity'], palette), palette)}
                </div>
                {self._verdict_html(call.get('verdict') or {}, palette)}
                {self._call_extras_html(call)}
                <div style="margin-bottom:8px;"><b>Origem:</b> {self._escape_html(call['source_ip'])}</div>
                <div style="margin-bottom:8px;"><b>Destino:</b> {self._escape_html(call['destination_ip'])}</div>
                <div style="margin-bottom:8px;"><b>Midia negociada:</b> {self._escape_html(state_label(call['media_direction']))}</div>
                <div style="margin-bottom:8px;"><b>Qualidade de midia:</b> {self._escape_html(state_label(call.get('media_quality', 'unknown')))}</div>
                <div style="margin-bottom:8px;"><b>Problema principal:</b> {self._escape_html(finding_title(call['primary_issue']) if call['primary_issue'] else 'Nenhum')}</div>
                <div style="margin-bottom:8px;"><b>Codecs:</b> {self._escape_html(', '.join(call['codec_guesses']) or '-')}</div>
                <div style="margin-bottom:8px;"><b>Duracao:</b> {self._format_duration(call['duration'])}</div>
                <div style="margin-bottom:8px;"><b>INVITE para 100/180/200/ACK:</b> {self._format_optional_duration(timings.get('invite_to_trying'))} / {self._format_optional_duration(timings.get('invite_to_ringing'))} / {self._format_optional_duration(timings.get('invite_to_ok'))} / {self._format_optional_duration(timings.get('invite_to_ack'))}</div>
                <div style="margin-bottom:8px;"><b>Streams RTP:</b> {call['rtp_stream_count']}</div>
                <div style="margin-bottom:8px;"><b>Pacotes RTP:</b> {rtp_metrics['packet_count']}</div>
                <div style="margin-bottom:8px;"><b>Perda de pacotes:</b> {rtp_metrics['loss_percent']:.2f}% ({rtp_metrics['lost_packets']})</div>
                <div style="margin-bottom:8px;"><b>Jitter maximo (RFC 3550):</b> {rtp_metrics['max_jitter'] * 1000:.1f} ms</div>
                <div style="margin-bottom:8px;"><b>Pior variacao entre pacotes:</b> {rtp_metrics.get('peak_transit_variation', 0.0) * 1000:.1f} ms</div>
                <div style="margin-bottom:8px;"><b>RTT (RTCP):</b> {self._format_optional_duration(rtp_metrics.get('rtt'))}</div>
                <div style="margin-bottom:8px;"><b>Pausas por silencio (VAD):</b> {rtp_metrics.get('silence_periods', 0)}</div>
                <div style="margin-bottom:8px;"><b>Fora de ordem:</b> {rtp_metrics['out_of_order_packets']}</div>
                <div style="margin-bottom:14px;"><b>SSRC:</b> {self._escape_html(', '.join(str(ssrc) for ssrc in rtp_metrics['ssrcs']) or '-')}</div>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Interpretacao de qualidade</div>
                <div style="margin-bottom:14px; padding:10px 12px; border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};">
                    <div style="margin-bottom:6px;"><b>{self._escape_html(mos_text)}</b></div>
                    <div style="margin-bottom:6px;">{self._escape_html(loss_observation)}</div>
                    <div style="margin-bottom:6px;">{self._escape_html(jitter_observation_text)}</div>
                    <div style="color:{palette['muted']};">{self._escape_html(quality_reference_note())}</div>
                </div>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Operacoes SIP</div>
                <div style="margin-bottom:14px; padding:10px 12px; border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};">
                    {self._escape_html(' | '.join(operation_items))}
                </div>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">RTP por direcao</div>
                <ul style="margin-top:0; margin-bottom:14px; padding-left:18px;">{direction_html}</ul>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Evidencias</div>
                <ul style="margin-top:0; margin-bottom:14px; padding-left:18px;">{evidence_html}</ul>
                <div style="font-size:11pt; font-weight:600; margin-bottom:6px;">Acao recomendada</div>
                <div style="padding:10px 12px; border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};">
                    {self._escape_html(call["recommended_action"] or "Sem recomendacao.")}
                </div>
            </div>
            """
        )

    def _build_sip_flow_html(self, flow):
        palette = THEMES[self.current_theme]
        rows = []

        for message in flow.messages:
            if message.is_request:
                direction = f"{message.source_ip}:{message.source_port} &#8594; {message.destination_ip}:{message.destination_port}"
                kind = self._escape_html(message.method or "REQUEST")
                direction_color = palette["accent"]
            else:
                direction = f"{message.destination_ip}:{message.destination_port} &#8592; {message.source_ip}:{message.source_port}"
                kind = self._escape_html(f"{message.status_code} {message.reason_phrase or ''}".strip())
                direction_color = palette["info"]

            rows.append(
                f"""
                <tr>
                    <td style="padding:10px 12px; border-bottom:1px solid {palette['border']}; color:{palette['muted']};">
                        {message.packet_time:.3f}
                    </td>
                    <td style="padding:10px 12px; border-bottom:1px solid {palette['border']};">
                        <span style="background:{direction_color}; color:{palette['text']}; padding:5px 8px; border-radius:10px; font-weight:600;">
                            {direction}
                        </span>
                    </td>
                    <td style="padding:10px 12px; border-bottom:1px solid {palette['border']}; color:{palette['text']};">
                        {kind}
                    </td>
                    <td style="padding:10px 12px; border-bottom:1px solid {palette['border']}; color:{palette['muted']};">
                        {self._escape_html(message.start_line)}
                    </td>
                </tr>
                """
            )

        return (
            f"""
            <div style="font-family:'Segoe UI'; color:{palette['text']};">
                <div style="font-size:22px; font-weight:700; margin-bottom:6px;">{self._escape_html(flow.call_id)}</div>
                <div style="margin-bottom:16px; color:{palette['muted']};">
                    {self._escape_html(flow.source_ip)} &#8644; {self._escape_html(flow.destination_ip)}
                </div>
                <div style="margin-bottom:16px; padding:12px 14px; border:1px solid {palette['border']}; border-radius:12px; background:{palette['surface']};">
                    <b>Resumo:</b> INVITE={flow.invites} | RESP={flow.responses} | 2xx={flow.success_responses} | ACK={flow.acknowledgements} | BYE={flow.byes} | CANCEL={flow.cancels}
                </div>
                <table style="width:100%; border-collapse:collapse; background:{palette['surface']}; border:1px solid {palette['border']}; border-radius:12px;">
                    <thead>
                        <tr>
                            <th style="text-align:left; padding:10px 12px; border-bottom:1px solid {palette['border']};">Tempo</th>
                            <th style="text-align:left; padding:10px 12px; border-bottom:1px solid {palette['border']};">Fluxo</th>
                            <th style="text-align:left; padding:10px 12px; border-bottom:1px solid {palette['border']};">Mensagem</th>
                            <th style="text-align:left; padding:10px 12px; border-bottom:1px solid {palette['border']};">Start-Line</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows) or f"<tr><td colspan='4' style='padding:14px;'>Sem mensagens SIP.</td></tr>"}
                    </tbody>
                </table>
            </div>
            """
        )

    def _render_diagnostic_detail(self, finding):
        if finding is None:
            self.diagnostic_detail_text.setPlainText("Selecione um incidente para ver as evidencias.")
            return
        self._render_finding_text(self.diagnostic_detail_text, finding)

    def _box_html(self, content, palette, accent=None):
        border = f"border-left:4px solid {accent};" if accent else ""
        return (
            f"<div style=\"margin-bottom:14px; padding:10px 12px; border:1px solid {palette['border']}; {border}"
            f" border-radius:10px; background:{palette['surface']};\">{content}</div>"
        )

    def _section_title(self, text):
        return f"<div style='font-size:11pt; font-weight:600; margin-bottom:6px;'>{self._escape_html(text)}</div>"

    def _code_html(self, lines, palette):
        if not lines:
            return ""
        code = "<br>".join(self._escape_html(line) for line in lines)
        return (
            self._section_title("Linha(s) com problema na mensagem")
            + f"<div style=\"margin-bottom:14px; padding:8px 10px; font-family:Consolas; font-size:9pt;"
            f" background:{palette['panel_alt']}; border:1px solid {palette['border']}; border-radius:8px;\">{code}</div>"
        )

    def _call_extras_html(self, call):
        rows = []
        hangup = call.get("hangup")
        if hangup:
            cause = f" | Q.850 {hangup['q850']}" if hangup.get("q850") else ""
            after = f" | apos {hangup['after_answer']:.1f} s de conversa" if hangup.get("after_answer") is not None else ""
            rows.append(f"<b>Encerrada por:</b> {self._escape_html(hangup['by'])} ({hangup['side']}, {hangup['method']}){self._escape_html(cause)}{after}")
        legs = call.get("legs")
        if legs:
            peers = ", ".join(peer["call_id"] for peer in legs.get("peers", []))
            rows.append(
                f"<b>Perna {legs['role']}</b> via {self._escape_html(legs['b2bua_ip'])} | relacionada(s): {self._escape_html(peers)}"
            )
        dtmf = call.get("dtmf") or {}
        digits = "; ".join(f"{direction}: {value}" for direction, value in (dtmf.get("rfc4733") or {}).items())
        if dtmf.get("sip_info"):
            digits = (digits + "; " if digits else "") + f"SIP INFO: {dtmf['sip_info']}"
        if digits:
            rows.append(f"<b>DTMF:</b> {self._escape_html(digits)}")
        if dtmf.get("silent_percent") is not None:
            rows.append(f"<b>Silencio no audio G.711:</b> {dtmf['silent_percent']:.0f}% dos pacotes")
        return "".join(f"<div style='margin-bottom:8px;'>{row}</div>" for row in rows)

    def _verdict_html(self, verdict, palette):
        """Compact verdict block for the call detail panels."""
        if not verdict or not verdict.get("status"):
            return ""
        tone = palette.get(VERDICT_TONES.get(verdict["status"], "muted"), palette["muted"])
        reasons = "".join(
            f"<li style='margin-bottom:3px;'>{self._escape_html(item)}</li>" for item in verdict.get("reasons", [])[:4]
        )
        actions = verdict.get("actions") or []
        culprit = (
            f"<div style='margin-top:6px;'><b>Provavel culpado:</b> "
            f"<span style='color:{tone}; font-weight:700;'>{self._escape_html(verdict.get('culprit') or '-')}</span></div>"
            if verdict["status"] != "ok"
            else ""
        )
        confirmed = (
            f"<div style='margin-top:4px;'><b>Confirmado por:</b> {self._escape_html(verdict['confirmed_by'])}</div>"
            if verdict.get("confirmed_by")
            else ""
        )
        content = (
            f"<div style='font-size:12pt; font-weight:700;'>{self._escape_html(verdict.get('headline', ''))}</div>"
            f"{culprit}{confirmed}"
            f"<div style='margin-top:4px; color:{palette['muted']};'>Status: {self._escape_html(verdict_status_label(verdict['status']))}"
            f" | Confianca: {self._escape_html(verdict.get('confidence_label', '-'))} ({float(verdict.get('confidence') or 0):.0%})</div>"
            + (f"<ol style='margin:6px 0 0 0;'>{reasons}</ol>" if reasons and verdict["status"] != "ok" else "")
            + (
                f"<div style='margin-top:6px;'><b>Proximo passo:</b> {self._escape_html(actions[0])}</div>"
                if actions
                else ""
            )
        )
        return self._section_title("Veredito da chamada") + self._box_html(content, palette, tone) + self._code_html(
            verdict.get("offending_lines") or [], palette
        )

    def _render_finding_text(self, widget, finding):
        if finding is None:
            widget.setPlainText("Nenhum finding selecionado.")
            return
        palette = THEMES[self.current_theme]
        severity = self._display_severity(finding)
        tone = self._severity_color(severity, palette)
        evidence = finding.get("evidence_display") or finding.get("evidence", [])
        technical_context = build_finding_evidence_context(self.last_engine_result, finding)
        evidence_html = "".join(
            f"<li style='margin-bottom:4px;'>{self._escape_html(item)}</li>"
            for item in evidence
        ) or "<li>Sem evidencias adicionais.</li>"
        technical_context_html = "".join(
            f"<li style='margin-bottom:4px;'>{self._escape_html(item)}</li>"
            for item in technical_context
        ) or "<li>Sem correlacoes adicionais para este finding.</li>"
        references_html = "".join(
            f"<li style='list-style:none; margin:0 0 10px 0; padding:10px 12px; "
            f"border:1px solid {palette['border']}; border-radius:10px; background:{palette['surface']};'>"
            f"<div style='font-weight:700; margin-bottom:5px;'>{self._escape_html(item['title'])}</div>"
            f"<div style='margin-bottom:5px;'><b>Aplicacao:</b> "
            f"{self._escape_html(item.get('scope', 'Referencia tecnica do protocolo.'))}</div>"
            f"<div style='color:{palette['muted']};'><b>Fonte:</b> "
            f"{self._escape_html(item['url'])}</div></li>"
            for item in finding.get("references", [])
        ) or "<li>Referencia tecnica nao cadastrada.</li>"
        chips = [self._chip_html(severity_label(severity), tone, palette)]
        if finding.get("is_root_cause"):
            chips.append(self._chip_html("Causa raiz", palette["accent"], palette))
        if finding.get("confirmed_by"):
            chips.append(self._chip_html(f"Confirmado: {finding['confirmed_by']}", palette["danger"], palette))
        culprit_box = self._box_html(
            f"<div style='color:{palette['muted']}; font-size:9pt;'>PROVAVEL CULPADO</div>"
            f"<div style='font-size:12pt; font-weight:700; color:{tone}; margin:2px 0 6px 0;'>"
            f"{self._escape_html(finding.get('culprit') or finding.get('responsibility', 'Em investigacao'))}</div>"
            f"<div>{self._escape_html(finding.get('responsibility_reason', 'Sem atribuicao conclusiva.'))}</div>"
            f"<div style='margin-top:6px; color:{palette['muted']};'>Confianca da atribuicao: "
            f"{self._escape_html(severity_label(finding.get('responsibility_confidence', 'low')))}"
            f" | Camada: {self._escape_html(finding.get('category', 'Correlacao'))}</div>",
            palette,
            tone,
        )
        chips_html = "&nbsp;".join(chips)
        path = f"{finding['type']} | {finding['source']} -> {finding['destination']}"
        widget.setHtml(
            f"""
            <div style="font-family:'Segoe UI'; color:{palette['text']};">
                <div style="font-size:18px; font-weight:700; margin-bottom:2px;">{self._escape_html(self._finding_title(finding))}</div>
                <div style="color:{palette['muted']}; font-family:Consolas; margin-bottom:8px;">{self._escape_html(path)}</div>
                <div style="margin-bottom:12px;">{chips_html}</div>
                {culprit_box}
                {self._section_title("O que aconteceu")}
                {self._box_html(self._escape_html(finding["description"] or "-"), palette)}
                {self._code_html(finding.get("offending_lines") or [], palette)}
                {self._section_title("Proxima acao")}
                {self._box_html(self._escape_html(finding["recommendation"] or "Investigue o fluxo entre os endpoints."), palette, palette["success"])}
                {self._section_title("Evidencias")}
                <ul style="margin-top:0; margin-bottom:14px; padding-left:18px;">{evidence_html}</ul>
                {self._section_title("Contexto tecnico capturado")}
                <ul style="margin-top:0; margin-bottom:14px; padding-left:18px;">{technical_context_html}</ul>
                {self._section_title("Referencias tecnicas")}
                <ul style="margin:0 0 14px 0; padding:0;">{references_html}</ul>
            </div>
            """
        )

    def _severity_color(self, severity, palette):
        return {
            "high": palette["danger"],
            "medium": palette["warning"],
            "low": palette["low"],
            "info": palette["muted"],
        }.get(severity, palette["muted"])

    def _signal_color(self, state, palette):
        return {
            "established": palette["success"],
            "completed": palette["success"],
            "terminated": palette["success"],
            "ringing": palette["warning"],
            "setup_incomplete": palette["warning"],
            "missing_ack": palette["warning"],
            "no_response": palette["warning"],
            "incomplete": palette["warning"],
            "failed": palette["danger"],
            "cancelled": palette["danger"],
            "unknown": palette["muted"],
        }.get(state, palette["accent"])

    def _media_color(self, state, palette):
        return {
            "ok": palette["success"],
            "media_present": palette["success"],
            "degraded_media": palette["warning"],
            "one_way_media": palette["danger"],
            "silent_media": palette["danger"],
            "no_media": palette["danger"],
            "inactive_media": palette["muted"],
        }.get(state, palette["accent"])

    def _chip_html(self, label, color, palette):
        return (
            f"<span style=\"background:{color}; color:{palette['text']}; "
            f"padding:5px 9px; border-radius:10px; font-size:9pt; font-weight:600;\">"
            f"{self._escape_html(label)}</span>"
        )

    def _escape_html(self, text):
        value = str(text)
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
