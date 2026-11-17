from ciper.findings import Finding
from ciper.voip_quality import LOSS_HIGH_QUALITY_PERCENT, LOSS_TARGET_PERCENT

# ITU-T G.114: one-way delay above 150 ms starts to hurt conversation, so a
# round trip above 300 ms is worth flagging and above 600 ms is severe.
RTCP_RTT_MEDIUM_SECONDS = 0.300
RTCP_RTT_HIGH_SECONDS = 0.600


def detect_rtcp_reported_loss(reports, high_loss_percent=LOSS_HIGH_QUALITY_PERCENT):
    findings = []
    for report in reports.values():
        loss_percent = report.max_fraction_lost * 100
        if loss_percent < LOSS_TARGET_PERCENT and report.cumulative_lost <= 0:
            continue
        if loss_percent <= 0:
            continue
        findings.append(
            Finding(
                type="rtcp_reported_loss",
                severity="high" if loss_percent >= high_loss_percent else "medium",
                confidence=0.90,
                # The reporter is the receiver of the media; the media flows
                # from the report's destination to the reporter.
                source_ip=report.receiver_ip,
                destination_ip=report.reporter_ip,
                description="O receptor da midia reportou perda de pacotes via RTCP.",
                evidence=[
                    f"SSRC: {report.source_ssrc}",
                    f"Reported by: {report.reporter_ip}",
                    f"Max fraction lost: {loss_percent:.2f}%",
                    f"Cumulative lost: {report.cumulative_lost}",
                    f"RTCP reports: {report.report_count}",
                ],
                recommendation=(
                    "A perda foi medida pelo receptor, depois do ponto de captura se ela nao aparece no RTP capturado. "
                    "Verifique o trecho de rede entre a captura e o receptor, QoS e links de acesso."
                ),
            )
        )
    return findings


def detect_rtcp_reported_jitter(reports, threshold=0.04):
    findings = []
    for report in reports.values():
        if report.max_jitter <= threshold:
            continue
        findings.append(
            Finding(
                type="rtcp_reported_jitter",
                severity="high" if report.max_jitter > threshold * 2 else "medium",
                confidence=0.85,
                source_ip=report.receiver_ip,
                destination_ip=report.reporter_ip,
                description="O receptor da midia reportou jitter alto via RTCP.",
                evidence=[
                    f"SSRC: {report.source_ssrc}",
                    f"Reported by: {report.reporter_ip}",
                    f"Reported jitter: {report.max_jitter * 1000:.1f} ms",
                    f"RTCP reports: {report.report_count}",
                ],
                recommendation="Verifique filas, Wi-Fi e enlaces congestionados no caminho ate o receptor.",
            )
        )
    return findings


def detect_rtcp_high_rtt(reports):
    findings = []
    for report in reports.values():
        rtt = report.max_rtt
        if rtt is None or rtt < RTCP_RTT_MEDIUM_SECONDS:
            continue
        findings.append(
            Finding(
                type="rtcp_high_rtt",
                severity="high" if rtt >= RTCP_RTT_HIGH_SECONDS else "medium",
                confidence=0.80,
                source_ip=report.receiver_ip,
                destination_ip=report.reporter_ip,
                description="O RTT medido pelo RTCP esta alto e pode causar eco e conversa atropelada.",
                evidence=[
                    f"SSRC: {report.source_ssrc}",
                    f"Max RTT: {rtt * 1000:.0f} ms",
                    f"Average RTT: {report.average_rtt * 1000:.0f} ms",
                    f"RTCP reports: {report.report_count}",
                ],
                recommendation=(
                    "Verifique rotas longas, VPNs, transcodificacao e jitter buffers grandes. "
                    "A ITU-T G.114 recomenda ate 150 ms de atraso em cada sentido."
                ),
            )
        )
    return findings
