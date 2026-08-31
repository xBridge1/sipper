from collections import Counter


def build_dashboard_viewmodel(packet_analysis, engine_result):
    findings = engine_result["findings"]
    call_summaries = engine_result.get("call_summaries", [])
    protocol_items = _build_protocol_items(packet_analysis["protocols"])
    severity_counts = Counter(finding.severity for finding in findings)

    return {
        "overview": {
            "packet_count": sum(packet_analysis["protocols"].values()),
            "protocol_count": len(protocol_items),
            "finding_count": len(findings),
            "call_count": len(call_summaries),
        },
        "protocols": protocol_items,
        "findings": [
            {
                "type": finding.type,
                "severity": finding.severity,
                "source": finding.source_ip,
                "destination": finding.destination_ip,
                "description": finding.description,
                "recommendation": finding.recommendation,
            }
            for finding in findings
        ],
        "severity_counts": {
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
        },
        "calls": [
            {
                "call_id": summary["call_id"],
                "signaling_state": summary["signaling_state"],
                "media_state": summary["media_state"],
                "severity": summary["severity"],
                "primary_issue": summary["primary_issue"],
                "codec_guesses": summary["codec_guesses"],
                "key_evidence": summary.get("key_evidence", []),
                "recommended_action": summary["recommended_action"],
                "source_ip": summary["source_ip"],
                "destination_ip": summary["destination_ip"],
                "rtp_stream_count": summary.get("rtp_stream_count", 0),
            }
            for summary in call_summaries
        ],
    }


def _build_protocol_items(protocol_counter):
    total = sum(protocol_counter.values())
    items = []

    for name, count in protocol_counter.items():
        share = 0.0

        if total:
            share = count / total

        items.append(
            {
                "name": name,
                "count": count,
                "share": share,
            }
        )

    items.sort(key=lambda item: item["count"], reverse=True)
    return items
