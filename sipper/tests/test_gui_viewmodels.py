from ciper.gui.viewmodels import build_dashboard_viewmodel


class DummyFinding:
    def __init__(self, type, severity, source_ip, destination_ip, description, recommendation):
        self.type = type
        self.severity = severity
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.description = description
        self.recommendation = recommendation


def test_build_dashboard_viewmodel():
    packet_analysis = {
        "protocols": {"RTP": 10, "SIP": 2, "TCP": 1},
    }
    engine_result = {
        "findings": [
            DummyFinding(
                "sip_call_one_way_audio",
                "high",
                "192.168.1.10",
                "192.168.1.20",
                "Descricao",
                "Recomendacao",
            )
        ],
        "call_summaries": [
            {
                "call_id": "CALL-1",
                "signaling_state": "established",
                "media_state": "one_way_media",
                "severity": "high",
                "primary_issue": "sip_call_one_way_audio",
                "codec_guesses": ["PCMU"],
                "key_evidence": ["Call-ID: CALL-1"],
                "recommended_action": "Recomendacao",
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.20",
                "rtp_stream_count": 1,
            }
        ],
    }

    viewmodel = build_dashboard_viewmodel(packet_analysis, engine_result)

    assert viewmodel["overview"]["packet_count"] == 13
    assert viewmodel["overview"]["call_count"] == 1
    assert viewmodel["severity_counts"]["high"] == 1
    assert viewmodel["calls"][0]["codec_guesses"] == ["PCMU"]
    assert viewmodel["calls"][0]["key_evidence"] == ["Call-ID: CALL-1"]
