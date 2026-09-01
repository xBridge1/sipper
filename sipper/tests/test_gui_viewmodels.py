from ciper.gui.viewmodels import build_dashboard_viewmodel


class DummyFinding:
    def __init__(self, type, severity, source_ip, destination_ip, description, recommendation):
        self.type = type
        self.severity = severity
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.description = description
        self.recommendation = recommendation


class DummyRTPStream:
    source_ip = "192.168.1.10"
    destination_ip = "192.168.1.20"
    source_port = 4000
    destination_port = 4002
    ssrc = 1234
    packet_count = 10
    lost_packets = 1
    average_jitter = 0.01
    max_jitter = 0.02
    out_of_order_packets = 0
    interruptions = 0
    duration = 0.2
    codec_guesses = ["PCMU"]


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


def test_build_dashboard_viewmodel_exposes_rtp_stream_metrics():
    stream = DummyRTPStream()
    packet_analysis = {"protocols": {"RTP": 10}}
    engine_result = {
        "findings": [],
        "call_summaries": [
            {
                "call_id": "CALL-1",
                "signaling_state": "established",
                "media_state": "media_present",
                "severity": "low",
                "primary_issue": None,
                "codec_guesses": ["PCMA"],
                "key_evidence": [],
                "recommended_action": "",
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.20",
                "rtp_stream_count": 1,
                "rtp_metrics": {"ssrcs": [1234]},
            }
        ],
        "rtp_streams": {"stream": stream},
    }

    viewmodel = build_dashboard_viewmodel(packet_analysis, engine_result)

    assert viewmodel["rtp_streams"][0]["loss_percent"] == 100 / 11
    assert viewmodel["rtp_streams"][0]["codec_guesses"] == ["PCMA"]
    assert viewmodel["rtp_streams"][0]["call_id"] == "CALL-1"
