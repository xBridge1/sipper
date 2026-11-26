"""Command-line interface: analyze one or more captures without the GUI.

Examples::

    python -m ciper.main captura.pcap
    python -m ciper.main *.pcap --freeswitch 10.0.0.20 --json resultado.json
    python -m ciper.main captura.pcap --json - --fail-on fail      # for scripts/CI
    python -m ciper.main captura.pcap --ticket                      # text for a ticket
"""

import argparse
import json
import sys
import time
from pathlib import Path

from ciper.analyzer import PacketAnalysisAccumulator
from ciper.engine import analyze_pcap_file
from ciper.gui.viewmodels import build_dashboard_viewmodel
from ciper.labels import display_severity, severity_label, verdict_status_label
from ciper.pcap_reader import PcapInputError
from ciper.settings import AnalysisSettings, load_settings
from ciper.ticket import build_capture_ticket

STATUS_ORDER = {"fail": 0, "degraded": 1, "risk": 2, "user": 3, "ok": 4}


def build_parser():
    parser = argparse.ArgumentParser(
        prog="sipper",
        description="SIPPER - diagnostico offline de capturas SIP/RTP com veredito e provavel culpado.",
    )
    parser.add_argument("files", nargs="*", help="arquivos .pcap/.pcapng")
    parser.add_argument("--freeswitch", metavar="IPS", help="ativa o perfil FreeSWITCH para estes IPs/redes")
    parser.add_argument("--capture-point", metavar="IP", help="IP do host onde a captura foi feita")
    parser.add_argument("--fs-codecs", metavar="LISTA", help="codecs aceitos pelo FreeSWITCH, ex.: PCMU,PCMA")
    parser.add_argument("--json", metavar="ARQUIVO", help="grava o resultado em JSON ('-' para a saida padrao)")
    parser.add_argument("--ticket", action="store_true", help="imprime o resumo pronto para chamado")
    parser.add_argument("--details", action="store_true", help="lista todos os findings com evidencias")
    parser.add_argument(
        "--fail-on",
        choices=["fail", "degraded", "risk"],
        help="retorna codigo 2 se alguma captura tiver veredito igual ou pior que este",
    )
    parser.add_argument("--no-user-settings", action="store_true", help="ignora ~/.sipper/settings.json")
    return parser


def _settings(args):
    settings = AnalysisSettings() if args.no_user_settings else load_settings()
    values = {}
    if args.freeswitch:
        values.update(target_platform="freeswitch", target_platform_ips=args.freeswitch)
    if args.capture_point:
        values["capture_point_ip"] = args.capture_point
    if args.fs_codecs:
        values["freeswitch_codecs"] = args.fs_codecs
    if values:
        from dataclasses import replace

        settings = replace(settings, **values)
    return settings


def analyze_file(file_path, settings):
    accumulator = PacketAnalysisAccumulator()
    started = time.perf_counter()
    engine_result = analyze_pcap_file(file_path, settings, packet_observer=accumulator.add)
    elapsed = time.perf_counter() - started
    viewmodel = build_dashboard_viewmodel(accumulator.result(), engine_result)
    return engine_result, viewmodel, elapsed


def build_cli_payload(file_path, viewmodel, elapsed):
    return {
        "file": str(file_path),
        "analysis_seconds": round(elapsed, 3),
        "diagnosis": viewmodel.get("diagnosis", {}),
        "capture_point": viewmodel.get("capture_point", {}),
        "overview": viewmodel["overview"],
        "severity_counts": viewmodel["severity_counts"],
        "calls": [
            {key: value for key, value in call.items() if key not in {"signaling_timeline"}}
            for call in viewmodel["calls"]
        ],
        "findings": viewmodel["findings"],
    }


def print_summary(file_path, viewmodel, elapsed, details=False, out=sys.stdout):
    diagnosis = viewmodel.get("diagnosis") or {}
    overview = viewmodel["overview"]
    print(f"=== {Path(file_path).name} ===", file=out)
    print(
        f"{overview['packet_count']} pacotes | {overview['call_count']} chamadas | analise em {elapsed:.2f} s",
        file=out,
    )
    print(f"Veredito: {verdict_status_label(diagnosis.get('status')).upper()} - {diagnosis.get('headline', '-')}", file=out)
    if diagnosis.get("status") not in {None, "ok"}:
        print(
            f"Provavel culpado: {diagnosis.get('culprit', '-')} (confianca {diagnosis.get('confidence_label', '-')})",
            file=out,
        )
    for action in (diagnosis.get("actions") or [])[:1]:
        print(f"Proximo passo: {action}", file=out)
    calls = [call for call in viewmodel["calls"] if (call.get("verdict") or {}).get("status") not in {None, "ok"}]
    if calls:
        print("Chamadas com problema:", file=out)
        for call in calls:
            verdict = call["verdict"]
            print(f"  [{verdict_status_label(verdict['status'])}] {call['call_id']}: {verdict['headline']}", file=out)
            print(f"      culpado: {verdict.get('culprit', '-')}", file=out)
    if details:
        print("Findings:", file=out)
        for finding in viewmodel["findings"]:
            severity = severity_label(display_severity(finding["type"], finding["severity"]))
            print(f"  [{severity}] {finding['title']} ({finding['type']}) {finding['source']} -> {finding['destination']}", file=out)
            print(f"      {finding['description']}", file=out)
            for item in finding.get("evidence_display", []):
                print(f"        - {item}", file=out)
    print(file=out)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    files = list(args.files)
    if not files:
        if not sys.stdin.isatty():
            parser.error("informe ao menos um arquivo")
        files = [input("Caminho do PCAP: ").strip().strip('"')]
    settings = _settings(args)
    json_to_stdout = args.json == "-"
    text_out = sys.stderr if json_to_stdout else sys.stdout

    payloads = []
    worst = "ok"
    exit_code = 0
    for file_path in files:
        try:
            _engine_result, viewmodel, elapsed = analyze_file(file_path, settings)
        except (PcapInputError, OSError) as error:
            print(f"Erro em {file_path}: {error}", file=sys.stderr)
            exit_code = 1
            continue
        status = (viewmodel.get("diagnosis") or {}).get("status", "ok")
        if STATUS_ORDER.get(status, 9) < STATUS_ORDER.get(worst, 9):
            worst = status
        if args.ticket:
            print(
                build_capture_ticket(viewmodel.get("diagnosis") or {}, Path(file_path).name, viewmodel.get("capture_point")),
                file=text_out,
            )
            print(file=text_out)
        else:
            print_summary(file_path, viewmodel, elapsed, args.details, text_out)
        payloads.append(build_cli_payload(file_path, viewmodel, elapsed))

    if args.json:
        document = payloads[0] if len(payloads) == 1 else {"captures": payloads}
        text = json.dumps(document, ensure_ascii=False, indent=2, default=str)
        if json_to_stdout:
            print(text)
        else:
            Path(args.json).write_text(text, encoding="utf-8")

    if exit_code == 0 and args.fail_on and payloads and STATUS_ORDER.get(worst, 9) <= STATUS_ORDER[args.fail_on]:
        exit_code = 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
