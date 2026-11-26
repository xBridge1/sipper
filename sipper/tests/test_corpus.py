"""Regression corpus: every capture must keep the verdict recorded for it.

See ``tests/corpus/README.md``. Only the keys present in the expected file are
compared, so an expectation can be as loose or strict as the case needs.
"""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from ciper.engine import analyze_pcap_file
from ciper.settings import AnalysisSettings

CORPUS = Path(__file__).resolve().parent / "corpus"
CASES = sorted(CORPUS.rglob("*.expected.json"))


def _pcap_for(expected_path, expected):
    if expected.get("pcap"):
        return (expected_path.parent / expected["pcap"]).resolve()
    stem = expected_path.name[: -len(".expected.json")]
    for suffix in (".pcap", ".pcapng"):
        candidate = expected_path.with_name(stem + suffix)
        if candidate.is_file():
            return candidate
    return expected_path.with_name(stem + ".pcap")


def _subset(actual, expected, where):
    for key, value in expected.items():
        assert actual.get(key) == value, f"{where}: {key} = {actual.get(key)!r}, esperado {value!r}"


@pytest.mark.parametrize("expected_path", CASES, ids=[str(path.relative_to(CORPUS)) for path in CASES])
def test_corpus_verdict(expected_path):
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    pcap = _pcap_for(expected_path, expected)
    if not pcap.is_file():
        pytest.skip(f"captura ausente: {pcap}")
    result = analyze_pcap_file(str(pcap), replace(AnalysisSettings(), **expected.get("settings", {})))

    _subset(result["diagnosis"], expected.get("diagnosis", {}), "diagnostico")
    calls = {summary["call_id"]: summary.get("verdict") or {} for summary in result["call_summaries"]}
    for call_id, call_expected in expected.get("calls", {}).items():
        assert call_id in calls, f"chamada {call_id} nao encontrada"
        _subset(calls[call_id], call_expected, f"chamada {call_id}")
    types = {finding.type for finding in result["findings"]}
    for finding_type in expected.get("present_findings", []):
        assert finding_type in types, f"finding esperado ausente: {finding_type}"
    for finding_type in expected.get("absent_findings", []):
        assert finding_type not in types, f"finding inesperado: {finding_type}"


def test_corpus_has_cases():
    assert CASES, "o corpus de regressao esta vazio"
