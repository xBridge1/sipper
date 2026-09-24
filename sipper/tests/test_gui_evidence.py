from ciper.gui.evidence import build_finding_evidence_context
from ciper.rtp import RTPPacket, RTPStream
from ciper.sip import SIPFlow, SIPMessage


def test_finding_context_shows_sip_packets_when_call_has_no_rtp():
    message = SIPMessage(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        source_port=5060,
        destination_port=5060,
        is_request=True,
        method="INVITE",
        status_code=None,
        reason_phrase=None,
        call_id="call-no-rtp",
        start_line="INVITE sip:100@pbx.local SIP/2.0",
        header_count=2,
        max_header_length=20,
        is_fragmented=False,
        packet_time=10.0,
        header_text="INVITE sip:100@pbx.local SIP/2.0\r\nCall-ID: call-no-rtp",
    )
    flow = SIPFlow(
        call_id="call-no-rtp",
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        messages=[message],
    )
    finding = {
        "type": "sip_call_established_without_rtp",
        "source": "192.168.1.10",
        "destination": "192.168.1.20",
        "evidence": ["Call-ID: call-no-rtp"],
    }

    context = build_finding_evidence_context(
        {"sip_flows": {flow.call_id: flow}, "rtp_streams": {}, "fragment_groups": {}},
        finding,
    )

    assert any("SIP 10.000: INVITE" in item for item in context)
    assert any("Nenhum pacote RTP" in item for item in context)


def test_finding_context_identifies_path_as_fragmentation_candidate():
    class FragmentGroup:
        source_ip = "192.168.1.10"
        destination_ip = "192.168.1.20"
        identification = 77
        protocol = 17
        source_port = 5060
        destination_port = 5060
        fragments = [(0, 100)]
        is_incomplete = True
        has_overlap = False

    finding = {
        "type": "ip_fragment_incomplete",
        "source": "192.168.1.10",
        "destination": "192.168.1.20",
        "evidence": [],
    }

    context = build_finding_evidence_context(
        {"sip_flows": {}, "rtp_streams": {}, "fragment_groups": {"fragment": FragmentGroup()}},
        finding,
    )

    assert any("IP ID 77" in item for item in context)
    assert any("caminho de rede" in item for item in context)


def test_finding_context_summarizes_only_the_affected_jitter_stream():
    stream = RTPStream(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        source_port=4000,
        destination_port=4002,
        ssrc=1234,
        packets=[
            RTPPacket("10.0.0.1", "10.0.0.2", 4000, 4002, 1, 160, 1234, 8, 0, 160, 1.0),
            RTPPacket("10.0.0.1", "10.0.0.2", 4000, 4002, 2, 320, 1234, 8, 0, 160, 1.02),
            RTPPacket("10.0.0.1", "10.0.0.2", 4000, 4002, 3, 480, 1234, 8, 0, 160, 1.50),
        ],
        packet_count=3,
        max_jitter=0.46,
    )
    finding = {
        "type": "rtp_high_jitter",
        "source": "10.0.0.1",
        "destination": "10.0.0.2",
        "evidence": ["SSRC: 1234"],
    }

    context = build_finding_evidence_context(
        {"sip_flows": {}, "rtp_streams": {"affected": stream}, "fragment_groups": {}},
        finding,
    )

    assert any(item.startswith("IMPACTO:") for item in context)
    assert any(item.startswith("POR QUE E RUIM:") for item in context)
    assert any("PIOR PICO:" in item for item in context)
