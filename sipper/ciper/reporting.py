import csv
import html
import json
from pathlib import Path

from PySide6.QtCore import QMarginsF
from PySide6.QtGui import QPageSize, QPdfWriter, QTextDocument

from ciper.labels import display_severity, finding_title, severity_label, state_label, verdict_status_label


def build_report_payload(viewmodel, source_pcap, capture_duration):
    return {
        "source_pcap": source_pcap,
        "capture_duration_seconds": capture_duration,
        "diagnosis": viewmodel.get("diagnosis", {}),
        "capture_point": viewmodel.get("capture_point", {}),
        "overview": viewmodel["overview"],
        "protocols": viewmodel["protocols"],
        "severity_counts": viewmodel["severity_counts"],
        "calls": viewmodel["calls"],
        # Chart series are a GUI concern and would bloat the export.
        "rtp_streams": [
            {key: value for key, value in stream.items() if key != "timeline"}
            for stream in viewmodel["rtp_streams"]
        ],
        "findings": viewmodel["findings"],
    }


def export_json(payload, destination):
    Path(destination).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def export_csv(payload, destination):
    fieldnames = [
        "record_type",
        "id",
        "title",
        "severity",
        "source",
        "destination",
        "state",
        "media_state",
        "media_quality",
        "description",
        "recommendation",
        "packet_count",
        "loss_percent",
        "jitter_ms",
        "codec",
        "verdict",
        "probable_culprit",
        "confidence",
    ]

    with Path(destination).open("w", encoding="utf-8", newline="") as file_handle:
        writer = csv.DictWriter(file_handle, fieldnames=fieldnames)
        writer.writeheader()

        for call in payload["calls"]:
            writer.writerow(
                {
                    "record_type": "call",
                    "id": call["call_id"],
                    "severity": call["severity"],
                    "source": call["source_ip"],
                    "destination": call["destination_ip"],
                    "state": call["signaling_state"],
                    "media_state": call["media_state"],
                    "media_quality": call.get("media_quality", "unknown"),
                    "title": finding_title(call["primary_issue"]) if call["primary_issue"] else "",
                    "description": call["primary_issue"] or "",
                    "recommendation": call["recommended_action"],
                    "packet_count": call["rtp_metrics"]["packet_count"],
                    "loss_percent": f"{call['rtp_metrics']['loss_percent']:.2f}",
                    "jitter_ms": f"{call['rtp_metrics']['max_jitter'] * 1000:.2f}",
                    "codec": ", ".join(call["codec_guesses"]),
                    "verdict": (call.get("verdict") or {}).get("headline", ""),
                    "probable_culprit": (call.get("verdict") or {}).get("culprit", ""),
                    "confidence": (call.get("verdict") or {}).get("confidence_label", ""),
                }
            )

        for finding in payload["findings"]:
            writer.writerow(
                {
                    "record_type": "finding",
                    "id": finding["type"],
                    "title": finding_title(finding["type"]),
                    "severity": finding["severity"],
                    "source": finding["source"],
                    "destination": finding["destination"],
                    "description": finding["description"],
                    "recommendation": finding["recommendation"],
                    "probable_culprit": finding.get("culprit", ""),
                    "verdict": f"confirmado por {finding['confirmed_by']}" if finding.get("confirmed_by") else "",
                }
            )

        for stream in payload["rtp_streams"]:
            writer.writerow(
                {
                    "record_type": "rtp_stream",
                    "id": f"0x{stream['ssrc']:08X}",
                    "source": stream["source"],
                    "destination": stream["destination"],
                    "packet_count": stream["packet_count"],
                    "loss_percent": f"{stream['loss_percent']:.2f}",
                    "jitter_ms": f"{stream['max_jitter'] * 1000:.2f}",
                    "codec": ", ".join(stream["codec_guesses"]),
                }
            )


def export_pdf(payload, destination):
    writer = QPdfWriter(str(destination))
    writer.setPageSize(QPageSize(QPageSize.A4))
    writer.setPageMargins(QMarginsF(14, 14, 14, 14))
    document = QTextDocument()
    document.setHtml(build_report_html(payload))
    document.print_(writer)


def build_report_html(payload):
    overview = payload["overview"]
    finding_rows = "".join(
        "<tr>"
        f"<td>{_escape(severity_label(display_severity(finding['type'], finding['severity'])))}</td>"
        f"<td>{_escape(finding_title(finding['type']))}<br><small>{_escape(finding['type'])}</small></td>"
        f"<td>{_escape(finding['source'])}</td>"
        f"<td>{_escape(finding['destination'])}</td>"
        f"<td><b>Culpado:</b> {_escape(finding.get('culprit') or finding.get('responsibility', '-'))}<br>"
        f"{_escape(finding['description'])}"
        + "".join(f"<br><small>{_escape(item)}</small>" for item in finding.get("evidence_display", [])[:4])
        + "</td>"
        "</tr>"
        for finding in payload["findings"]
    ) or "<tr><td colspan='5'>Nenhum finding detectado.</td></tr>"
    diagnosis = payload.get("diagnosis") or {}
    verdict_html = _verdict_section(diagnosis)
    capture = payload.get("capture_point") or {}
    if capture.get("ip"):
        verdict_html += (
            f"<p><b>Ponto de captura:</b> {_escape(capture['ip'])} "
            f"({'detectado automaticamente' if capture.get('auto') else 'configurado'})</p>"
        )
    call_rows = "".join(
        "<tr>"
        f"<td>{_escape(call['call_id'])}</td>"
        f"<td>{_escape(call['source_ip'])}</td>"
        f"<td>{_escape(call['destination_ip'])}</td>"
        f"<td>{_escape(state_label(call['signaling_state']))}</td>"
        f"<td>{_escape(state_label(call['media_state']))}</td>"
        f"<td>{_escape(state_label(call.get('media_quality', 'unknown')))}</td>"
        f"<td>{call['rtp_metrics']['loss_percent']:.2f}%</td>"
        f"<td>{_escape((call.get('verdict') or {}).get('headline', '-'))}"
        f"<br><small>Culpado: {_escape((call.get('verdict') or {}).get('culprit', '-'))}</small></td>"
        "</tr>"
        for call in payload["calls"]
    ) or "<tr><td colspan='8'>Nenhuma chamada SIP detectada.</td></tr>"

    return f"""
        <html>
            <head>
                <style>
                    body {{ font-family: 'Segoe UI'; color: #17212B; }}
                    h1 {{ color: #B1121C; }}
                    h2 {{ margin-top: 24px; color: #17212B; }}
                    table {{ width: 100%; border-collapse: collapse; font-size: 9pt; }}
                    th {{ background: #17212B; color: white; text-align: left; }}
                    th, td {{ border: 1px solid #CBD5DF; padding: 6px; }}
                    .summary {{ background: #F3F6F8; padding: 12px; }}
                    .verdict {{ border: 1px solid #CBD5DF; border-left: 6px solid #B1121C; padding: 10px 14px; margin-top: 14px; }}
                    .verdict h2 {{ margin-top: 0; }}
                    code {{ font-family: Consolas; background: #F3F6F8; }}
                </style>
            </head>
            <body>
                <h1>SIPPER - Relatorio de Analise</h1>
                <p><b>Arquivo:</b> {_escape(payload['source_pcap'])}</p>
                <div class="summary">
                    <b>Pacotes:</b> {overview['packet_count']} &nbsp;&nbsp;
                    <b>Chamadas:</b> {overview['call_count']} &nbsp;&nbsp;
                    <b>Findings:</b> {overview['finding_count']}
                </div>
                {verdict_html}
                <h2>Chamadas SIP</h2>
                <table>
                    <tr><th>Call-ID</th><th>Origem</th><th>Destino</th><th>SIP</th><th>Midia</th><th>Qualidade</th><th>Loss</th><th>Veredito</th></tr>
                    {call_rows}
                </table>
                <h2>Findings</h2>
                <table>
                    <tr><th>Severidade</th><th>Tipo</th><th>Origem</th><th>Destino</th><th>Descricao</th></tr>
                    {finding_rows}
                </table>
            </body>
        </html>
    """


def _verdict_section(diagnosis):
    if not diagnosis:
        return ""
    reasons = "".join(f"<li>{_escape(item)}</li>" for item in diagnosis.get("reasons", []))
    actions = "".join(f"<li>{_escape(item)}</li>" for item in diagnosis.get("actions", []))
    lines = "<br>".join(_escape(line) for line in diagnosis.get("offending_lines", []))
    confirmed = (
        f"<p><b>Confirmado pela resposta:</b> {_escape(diagnosis['confirmed_by'])}</p>"
        if diagnosis.get("confirmed_by")
        else ""
    )
    return (
        "<div class='verdict'>"
        f"<h2>Veredito: {_escape(verdict_status_label(diagnosis.get('status')))}</h2>"
        f"<p><b>{_escape(diagnosis.get('headline', ''))}</b></p>"
        f"<p><b>Provavel culpado:</b> {_escape(diagnosis.get('culprit', '-'))} "
        f"(confianca {_escape(diagnosis.get('confidence_label', '-'))})</p>"
        f"{confirmed}"
        + (f"<p><b>Por que</b></p><ol>{reasons}</ol>" if reasons else "")
        + (f"<p><b>Linha(s) com problema</b></p><p><code>{lines}</code></p>" if lines else "")
        + (f"<p><b>O que fazer agora</b></p><ol>{actions}</ol>" if actions else "")
        + "</div>"
    )


def _escape(value):
    return html.escape(str(value))
