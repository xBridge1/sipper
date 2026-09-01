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
                "media_direction": summary.get("media_direction", "unknown"),
                "severity": summary["severity"],
                "primary_issue": summary["primary_issue"],
                "codec_guesses": summary["codec_guesses"],
                "key_evidence": summary.get("key_evidence", []),
                "recommended_action": summary["recommended_action"],
                "source_ip": summary["source_ip"],
                "destination_ip": summary["destination_ip"],
                "rtp_stream_count": summary.get("rtp_stream_count", 0),
                "start_time": summary.get("start_time"),
                "end_time": summary.get("end_time"),
                "duration": summary.get("duration", 0.0),
                "rtp_metrics": summary.get(
                    "rtp_metrics",
                    {
                        "packet_count": 0,
                        "lost_packets": 0,
                        "loss_percent": 0.0,
                        "out_of_order_packets": 0,
                        "interruptions": 0,
                        "average_jitter": 0.0,
                        "max_jitter": 0.0,
                        "ssrcs": [],
                    },
                ),
            }
            for summary in call_summaries
        ],
        "rtp_streams": _build_rtp_stream_items(
            engine_result.get("rtp_streams", {}),
            call_summaries,
        ),
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


def _build_rtp_stream_items(rtp_streams, call_summaries):
    codecs_by_ssrc = {}
    call_id_by_ssrc = {}

    for summary in call_summaries:
        for ssrc in summary.get("rtp_metrics", {}).get("ssrcs", []):
            codecs_by_ssrc[ssrc] = summary.get("codec_guesses", [])
            call_id_by_ssrc[ssrc] = summary["call_id"]

    items = []

    for stream in rtp_streams.values():
        expected_packets = stream.packet_count + stream.lost_packets
        items.append(
            {
                "source": f"{stream.source_ip}:{stream.source_port}",
                "destination": f"{stream.destination_ip}:{stream.destination_port}",
                "ssrc": stream.ssrc,
                "packet_count": stream.packet_count,
                "lost_packets": stream.lost_packets,
                "loss_percent": (stream.lost_packets / expected_packets * 100) if expected_packets else 0.0,
                "average_jitter": stream.average_jitter,
                "max_jitter": stream.max_jitter,
                "out_of_order_packets": stream.out_of_order_packets,
                "interruptions": stream.interruptions,
                "duration": stream.duration,
                "codec_guesses": codecs_by_ssrc.get(stream.ssrc, stream.codec_guesses),
                "call_id": call_id_by_ssrc.get(stream.ssrc),
            }
        )

    items.sort(key=lambda item: item["packet_count"], reverse=True)
    return items
