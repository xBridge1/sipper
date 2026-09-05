import csv
import json

from ciper.reporting import build_report_payload, export_csv, export_json


def test_report_exports_json_and_csv(tmp_path):
    viewmodel = {
        "overview": {"packet_count": 12, "protocol_count": 2, "finding_count": 1, "call_count": 1},
        "protocols": [{"name": "RTP", "count": 10, "share": 0.83}],
        "severity_counts": {"high": 1, "medium": 0, "low": 0},
        "calls": [
            {
                "call_id": "call-1",
                "severity": "high",
                "source_ip": "10.0.0.1",
                "destination_ip": "10.0.0.2",
                "signaling_state": "established",
                "media_state": "degraded_media",
                "media_quality": "degraded",
                "primary_issue": "rtp_packet_loss",
                "recommended_action": "Check QoS",
                "codec_guesses": ["PCMU"],
                "rtp_metrics": {"packet_count": 10, "loss_percent": 10.0, "max_jitter": 0.02},
            }
        ],
        "rtp_streams": [
            {
                "ssrc": 1234,
                "source": "10.0.0.1:4000",
                "destination": "10.0.0.2:4002",
                "packet_count": 10,
                "loss_percent": 10.0,
                "max_jitter": 0.02,
                "codec_guesses": ["PCMU"],
            }
        ],
        "findings": [
            {
                "type": "rtp_packet_loss",
                "severity": "high",
                "source": "10.0.0.1",
                "destination": "10.0.0.2",
                "description": "Packet loss",
                "recommendation": "Check QoS",
            }
        ],
    }
    payload = build_report_payload(viewmodel, "sample.pcap", 12.5)
    json_path = tmp_path / "report.json"
    csv_path = tmp_path / "report.csv"

    export_json(payload, json_path)
    export_csv(payload, csv_path)

    assert json.loads(json_path.read_text(encoding="utf-8"))["overview"]["packet_count"] == 12
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert [row["record_type"] for row in rows] == ["call", "finding", "rtp_stream"]
    assert rows[0]["media_quality"] == "degraded"
