from scapy.layers.inet import IP, UDP
from scapy.utils import wrpcap

from ciper.engine import analyze_pcap_file
from tests.test_rtp import make_rtp_packet


def test_voip_regression_pcap_preserves_sip_sdp_and_rtp_correlation(tmp_path):
    file_path = tmp_path / "voip_regression.pcap"
    packets = [
        IP(src="192.168.50.10", dst="192.168.50.20")
        / UDP(sport=5060, dport=5060)
        / (
            b"INVITE sip:200@pbx.local SIP/2.0\r\n"
            b"Call-ID: pcap-regression\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
            b"v=0\r\nc=IN IP4 192.168.50.10\r\nm=audio 4000 RTP/AVP 8\r\n"
        ),
        IP(src="192.168.50.20", dst="192.168.50.10")
        / UDP(sport=5060, dport=5060)
        / (
            b"SIP/2.0 200 OK\r\n"
            b"Call-ID: pcap-regression\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
            b"v=0\r\nc=IN IP4 192.168.50.20\r\nm=audio 4002 RTP/AVP 8\r\n"
        ),
        IP(src="192.168.50.10", dst="192.168.50.20")
        / UDP(sport=5060, dport=5060)
        / b"ACK sip:200@pbx.local SIP/2.0\r\nCall-ID: pcap-regression\r\nCSeq: 1 ACK\r\n\r\n",
        make_rtp_packet("192.168.50.10", "192.168.50.20", 4000, 4002, 100, 160, 1234, payload_type=8),
        make_rtp_packet("192.168.50.20", "192.168.50.10", 4002, 4000, 100, 160, 5678, payload_type=8),
    ]
    for index, packet in enumerate(packets):
        packet.time = 100.0 + (index * 0.02)
    wrpcap(str(file_path), packets)

    result = analyze_pcap_file(str(file_path))
    summary = result["call_summaries"][0]

    assert summary["call_id"] == "pcap-regression"
    assert summary["signaling_state"] == "established"
    assert summary["rtp_stream_count"] == 2
    assert summary["media_quality"] == "good"
    assert summary["codec_guesses"] == ["PCMA"]
