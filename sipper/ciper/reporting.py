import csv
import html
import json
from pathlib import Path

from PySide6.QtCore import QMarginsF
from PySide6.QtGui import QPageSize, QPdfWriter, QTextDocument


def build_report_payload(viewmodel, source_pcap, capture_duration):
    return {
        "source_pcap": source_pcap,
        "capture_duration_seconds": capture_duration,
        "overview": viewmodel["overview"],
        "protocols": viewmodel["protocols"],
        "severity_counts": viewmodel["severity_counts"],
        "calls": viewmodel["calls"],
        "rtp_streams": viewmodel["rtp_streams"],
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
                    "description": call["primary_issue"] or "",
                    "recommendation": call["recommended_action"],
                    "packet_count": call["rtp_metrics"]["packet_count"],
                    "loss_percent": f"{call['rtp_metrics']['loss_percent']:.2f}",
                    "jitter_ms": f"{call['rtp_metrics']['max_jitter'] * 1000:.2f}",
                    "codec": ", ".join(call["codec_guesses"]),
                }
            )

        for finding in payload["findings"]:
            writer.writerow(
                {
                    "record_type": "finding",
                    "id": finding["type"],
                    "severity": finding["severity"],
                    "source": finding["source"],
                    "destination": finding["destination"],
                    "description": finding["description"],
                    "recommendation": finding["recommendation"],
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
        f"<td>{_escape(finding['severity'].upper())}</td>"
        f"<td>{_escape(finding['type'])}</td>"
        f"<td>{_escape(finding['source'])}</td>"
        f"<td>{_escape(finding['destination'])}</td>"
        f"<td>{_escape(finding['description'])}</td>"
        "</tr>"
        for finding in payload["findings"]
    ) or "<tr><td colspan='5'>Nenhum finding detectado.</td></tr>"
    call_rows = "".join(
        "<tr>"
        f"<td>{_escape(call['call_id'])}</td>"
        f"<td>{_escape(call['source_ip'])}</td>"
        f"<td>{_escape(call['destination_ip'])}</td>"
        f"<td>{_escape(call['signaling_state'])}</td>"
        f"<td>{_escape(call['media_state'])}</td>"
        f"<td>{_escape(call.get('media_quality', 'unknown'))}</td>"
        f"<td>{call['rtp_metrics']['loss_percent']:.2f}%</td>"
        "</tr>"
        for call in payload["calls"]
    ) or "<tr><td colspan='7'>Nenhuma chamada SIP detectada.</td></tr>"

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
                <h2>Chamadas SIP</h2>
                <table>
                    <tr><th>Call-ID</th><th>Origem</th><th>Destino</th><th>SIP</th><th>Midia</th><th>Qualidade</th><th>Loss</th></tr>
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


def _escape(value):
    return html.escape(str(value))
