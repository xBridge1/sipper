from collections import Counter

from ciper.findings import describe_responsibility


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
                "key": f"{index}:{finding.type}:{finding.source_ip}:{finding.destination_ip}",
                "type": finding.type,
                "severity": finding.severity,
                "source": finding.source_ip,
                "destination": finding.destination_ip,
                "description": finding.description,
                "recommendation": finding.recommendation,
                "evidence": list(getattr(finding, "evidence", [])),
                "references": list(getattr(finding, "references", [])),
                "category": _finding_category(finding.type),
                "responsibility": describe_responsibility(finding)[0],
                "responsibility_confidence": describe_responsibility(finding)[1],
                "responsibility_reason": describe_responsibility(finding)[2],
            }
            for index, finding in enumerate(findings)
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
                "media_quality": summary.get("media_quality", "unknown"),
                "signaling_timeline": summary.get("signaling_timeline", []),
                "signaling_timings": summary.get("signaling_timings", {}),
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
                        "directions": {},
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
                "payload_types": sorted(getattr(stream, "payload_types", set())),
                "call_id": call_id_by_ssrc.get(stream.ssrc),
            }
        )

    items.sort(key=lambda item: item["packet_count"], reverse=True)
    return items


def _finding_category(finding_type):
    if finding_type.startswith("tls_"):
        return "TLS e seguranca"
    if finding_type.startswith("rtp_"):
        return "RTP e midia"
    if finding_type.startswith("sip_"):
        if "header" in finding_type or "fragmentation" in finding_type or "content_length" in finding_type:
            return "SIP, headers e MTU"
        return "SIP e sinalizacao"
    if finding_type.startswith("ip_fragment") or finding_type == "icmp_fragmentation_needed":
        return "Fragmentacao e MTU"
    if finding_type.startswith("tcp_"):
        return "Rede TCP"
    if finding_type.startswith("udp_"):
        return "Rede UDP"
    if finding_type.startswith("icmp_"):
        return "Rede ICMP"
    return "Correlacao"
