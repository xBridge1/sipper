import sys
import time

from ciper.analyzer import PacketAnalysisAccumulator
from ciper.engine import analyze_pcap_file
from ciper.labels import display_severity, finding_title, severity_label
from ciper.pcap_reader import PcapInputError


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    file_path = argv[0] if argv else input("Caminho do PCAP: ").strip().strip('"')

    accumulator = PacketAnalysisAccumulator()
    started = time.perf_counter()
    try:
        engine_result = analyze_pcap_file(file_path, packet_observer=accumulator.add)
    except PcapInputError as error:
        print(f"Erro: {error}", file=sys.stderr)
        return 1
    elapsed = time.perf_counter() - started
    packet_analysis = accumulator.result()

    print()
    print("=== SIPPER ===")
    print(f"Pacotes encontrados: {engine_result['analysis_stats']['packet_count']}")
    print(f"Tempo de analise: {elapsed:.2f} s")

    print()
    print("=== Protocolos ===")

    for protocol, count in packet_analysis["protocols"].items():
        print(f"{protocol}: {count}")

    print()
    print("=== TCP Flows ===")

    for flow in engine_result["flows"].values():
        print(
            f"{flow.source_ip}:{flow.source_port} -> "
            f"{flow.destination_ip}:{flow.destination_port} "
            f"({flow.packet_count} pacotes)"
        )

    print()
    print("=== UDP Flows ===")

    for flow in engine_result["udp_flows"].values():
        print(
            f"{flow.source_ip}:{flow.source_port} -> "
            f"{flow.destination_ip}:{flow.destination_port} "
            f"({flow.packet_count} pacotes)"
        )

    print()
    print("=== ICMP Flows ===")

    for flow in engine_result["icmp_flows"].values():
        print(
            f"{flow.source_ip} -> "
            f"{flow.destination_ip} "
            f"(requests: {flow.echo_requests}, "
            f"replies: {flow.echo_replies})"
        )

    print()
    print("=== FINDINGS ===")

    if not engine_result["findings"]:
        print("Nenhum problema detectado.")

    for finding in engine_result["findings"]:
        print()
        severity = severity_label(display_severity(finding.type, finding.severity))
        print(f"[{severity.upper()}] {finding_title(finding.type)} ({finding.type})")
        print(
            f"{finding.source_ip} -> "
            f"{finding.destination_ip}"
        )
        print(finding.description)
        print("Evidence:")
        

        for evidence in finding.evidence:
            print(f"  - {evidence}")

        print()
        print("Recommendation:")
        print(f"  {finding.recommendation}")

    return 0


if __name__ == "__main__":
    sys.exit(main())