from ciper.flows import build_tcp_flows
from ciper.detectors.tcp import (
    detect_syn_failures,
    detect_slow_handshakes,
    detect_tcp_retransmissions,
)


def analyze_pcap(packets):
    flows = build_tcp_flows(packets)

    findings = []

    findings.extend(detect_syn_failures(flows))
    findings.extend(detect_slow_handshakes(flows))
    findings.extend(detect_tcp_retransmissions(flows))

    return {
        "flows": flows,
        "findings": findings,
    }