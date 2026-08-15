from ciper.pcap_reader import read_pcap
from ciper.analyzer import analyze_packets
from ciper.engine import analyze_pcap


def main():
    file_path = input("Caminho do PCAP: ")

    result = read_pcap(file_path)

    packet_analysis = analyze_packets(result["packets"])
    engine_result = analyze_pcap(result["packets"])

    print()
    print("=== SIPPER ===")
    print(f"Pacotes encontrados: {result['packet_count']}")

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
        print(f"[{finding.severity.upper()}] {finding.type}")
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


if __name__ == "__main__":
    main()