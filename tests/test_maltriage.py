"""Tests for maltriage. Run with: pytest"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from maltriage.analyzer import analyze, filter_signatures
from maltriage.cli import main
from maltriage.parser import ReportError, parse
from maltriage.report import render_html, render_json, render_markdown

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "report.json")


@pytest.fixture
def result():
    return analyze(parse(SAMPLE))


# --- parsing ---------------------------------------------------------------- #
def test_parses_sample(result):
    assert result.sample.name == "invoice_2026.exe"
    assert result.sample.sha256.startswith("9f2c0e1a")
    assert result.source == "cape"


def test_family_detected(result):
    assert "Ransom.Filecoder" in result.family


def test_iocs_extracted(result):
    assert "paymentgate-decrypt.top" in result.iocs.domains
    assert "185.220.101.44" in result.iocs.ips
    assert any("gate.php" in u for u in result.iocs.urls)
    assert any("Run" in k for k in result.iocs.registry_keys)
    assert any("FileCoder" in m for m in result.iocs.mutexes)
    assert any(d.name == "READ_ME_DECRYPT.txt" for d in result.iocs.dropped)


def test_domains_deduped(result):
    # A domain appears in both `domains` and `dns` + `http`; must appear once.
    assert result.iocs.domains.count("paymentgate-decrypt.top") == 1


def test_processes(result):
    assert any(p.name == "vssadmin.exe" for p in result.processes)


# --- analysis --------------------------------------------------------------- #
def test_verdict_critical(result):
    assert result.verdict == "CRITICAL"
    assert result.score == pytest.approx(9.2)


def test_signatures_sorted_by_severity(result):
    sevs = [s.severity for s in result.signatures]
    assert sevs == sorted(sevs, reverse=True)


def test_mitre_resolved(result):
    ids = {t.id for t in result.techniques}
    assert "T1486" in ids  # Data Encrypted for Impact
    names = {t.id: t.name for t in result.techniques}
    assert names["T1486"] == "Data Encrypted for Impact"
    # Sub-technique keeps its own id but resolves a name.
    assert names.get("T1055.012") == "Process Hollowing"


def test_technique_url(result):
    tech = next(t for t in result.techniques if t.id == "T1547.001")
    assert tech.url == "https://attack.mitre.org/techniques/T1547/001/"


def test_min_severity_filter(result):
    high = filter_signatures(result, 3)
    assert high and all(s.severity >= 3 for s in high)


# --- derived score fallback ------------------------------------------------- #
def test_score_derived_when_absent(tmp_path):
    report = {
        "info": {"id": 1},
        "target": {"file": {"name": "x.bin", "sha256": "ab"}},
        "signatures": [
            {"name": "a", "severity": 3, "ttp": ["T1055"]},
            {"name": "b", "severity": 2},
        ],
    }
    p = tmp_path / "r.json"
    p.write_text(json.dumps(report))
    res = analyze(parse(str(p)))
    assert res.score > 0  # derived from severities (3 + 2)
    assert res.verdict in ("MEDIUM", "HIGH", "CRITICAL")
    assert res.source == "cuckoo"


def test_clean_report(tmp_path):
    report = {"info": {"id": 2, "score": 0}, "target": {"file": {"name": "ok.txt"}}, "signatures": []}
    p = tmp_path / "clean.json"
    p.write_text(json.dumps(report))
    res = analyze(parse(str(p)))
    assert res.verdict == "CLEAN"
    assert res.iocs.is_empty()


# --- error handling --------------------------------------------------------- #
def test_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(ReportError):
        parse(str(p))


def test_not_a_report(tmp_path):
    p = tmp_path / "other.json"
    p.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(ReportError):
        parse(str(p))


# --- reporters -------------------------------------------------------------- #
def test_markdown_output(result):
    md = render_markdown(result)
    assert "# Malware Triage" in md
    assert "CRITICAL" in md
    assert "T1486" in md
    assert "paymentgate-decrypt.top" in md


def test_html_output(result):
    out = render_html(result)
    assert out.startswith("<!doctype html>")
    assert "CRITICAL" in out
    assert "invoice_2026.exe" in out


def test_json_output(result):
    data = json.loads(render_json(result))
    assert data["verdict"] == "CRITICAL"
    assert data["iocs"]["domains"]
    assert data["mitre_attack"][0]["id"].startswith("T")


def test_json_iocs_only(result):
    data = json.loads(render_json(result, iocs_only=True))
    assert "domains" in data
    assert "verdict" not in data


# --- CLI -------------------------------------------------------------------- #
def test_cli_exit_code_on_malicious(capsys):
    rc = main([SAMPLE, "--format", "json"])
    assert rc == 1  # CRITICAL -> non-zero for pipelines


def test_cli_no_fail(capsys):
    rc = main([SAMPLE, "--format", "json", "--no-fail"])
    assert rc == 0


def test_cli_missing_file():
    rc = main(["/nope/nothing.json"])
    assert rc == 2
