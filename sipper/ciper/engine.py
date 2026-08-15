from ciper.flows import build_tcp_flows, build_icmp_flows
from ciper.udp_flows import build_udp_flows
from ciper.detectors.udp import detect_udp_no_response
from ciper.detectors.icmp import detect_icmp_no_response
from ciper.detectors.tcp import (
    detect_syn_failures,
    detect_slow_handshakes,
    detect_tcp_retransmissions,
    detect_tcp_resets,
)

def analyze_pcap(packets):
    flows = build_tcp_flows(packets)
    udp_flows = build_udp_flows(packets)
    icmp_flows = build_icmp_flows(packets)

    findings = []

    findings.extend(detect_syn_failures(flows))
    findings.extend(detect_slow_handshakes(flows))
    findings.extend(detect_tcp_retransmissions(flows))
    findings.extend(detect_tcp_resets(flows))

    findings.extend(detect_udp_no_response(udp_flows))
    findings.extend(detect_icmp_no_response(icmp_flows))

    return {
        "flows": flows,
        "udp_flows": udp_flows,
        "icmp_flows": icmp_flows,
        "findings": findings,
    }