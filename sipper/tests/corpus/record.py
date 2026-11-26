"""Record the current verdict of a capture as the expected result for the corpus.

Use it after you confirmed that SIPPER's verdict for a real capture is right:

    python -m tests.corpus.record caminho/captura.pcap --freeswitch 10.0.0.20

The capture is copied to ``tests/corpus/real/`` (unless it already is inside
``tests/corpus``) next to a ``.expected.json``. From then on, any change that
alters that verdict fails ``tests/test_corpus.py``.

Do not commit captures with customer data you are not allowed to share.
"""

import argparse
import json
import shutil
from dataclasses import replace
from pathlib import Path

from ciper.engine import analyze_pcap_file
from ciper.settings import AnalysisSettings

CORPUS = Path(__file__).resolve().parent


def expected_from_result(result, settings_overrides):
    diagnosis = result["diagnosis"]
    calls = {}
    for summary in result["call_summaries"]:
        verdict = summary.get("verdict") or {}
        calls[summary["call_id"]] = {
            "status": verdict.get("status"),
            "root_type": verdict.get("root_type"),
            "culprit_ip": verdict.get("culprit_ip"),
        }
    return {
        "settings": settings_overrides,
        "diagnosis": {
            "status": diagnosis.get("status"),
            "root_type": diagnosis.get("root_type"),
            "culprit_ip": diagnosis.get("culprit_ip"),
        },
        "calls": calls,
        "present_findings": sorted({finding.type for finding in result["findings"]}),
    }


def analyze(path, overrides):
    return analyze_pcap_file(str(path), replace(AnalysisSettings(), **overrides))


def record(pcap, overrides, destination=None):
    pcap = Path(pcap).resolve()
    if destination is None:
        destination = pcap if CORPUS in pcap.parents else CORPUS / "real" / pcap.name
    destination = Path(destination)
    if destination != pcap:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pcap, destination)
    expected = expected_from_result(analyze(destination, overrides), overrides)
    target = destination.with_suffix(".expected.json")
    target.write_text(json.dumps(expected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("pcap")
    parser.add_argument("--freeswitch", metavar="IPS")
    parser.add_argument("--capture-point", metavar="IP")
    args = parser.parse_args(argv)
    overrides = {}
    if args.freeswitch:
        overrides.update(target_platform="freeswitch", target_platform_ips=args.freeswitch)
    if args.capture_point:
        overrides["capture_point_ip"] = args.capture_point
    print(f"Gravado: {record(args.pcap, overrides)}")


if __name__ == "__main__":
    main()
