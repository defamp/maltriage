"""CSV output preserves IOC structure and the triage exit-code contract."""
import csv
import io
import json
from pathlib import Path

import pytest

from maltriage.analyzer import analyze
from maltriage.cli import main
from maltriage.models import DroppedFile, IOCs, SampleInfo, TriageResult
from maltriage.parser import parse
from maltriage.report import render_iocs_csv, render_json

SAMPLE = str(Path(__file__).parents[1] / 'samples/report.json')
FIELDS = ['type', 'value', 'sha256', 'file_type']


def rows(text):
    return list(csv.DictReader(io.StringIO(text, newline='')))


def test_csv_exports_all_ioc_types_and_dropped_hashes():
    result = analyze(parse(SAMPLE))
    exported = rows(render_iocs_csv(result))
    assert len(exported) == result.iocs.total()
    assert {row['type'] for row in exported} == {'domain', 'ip', 'url', 'registry_key', 'mutex', 'dropped_file'}
    assert any(row['type'] == 'domain' and row['value'] == 'paymentgate-decrypt.top' for row in exported)
    drop = result.iocs.dropped[0]
    assert {'type': 'dropped_file', 'value': drop.name, 'sha256': drop.sha256, 'file_type': drop.type} in exported
    assert all(list(row) == FIELDS for row in exported)


def test_empty_iocs_export_header_only():
    result = TriageResult(sample=SampleInfo())
    assert render_iocs_csv(result) == 'type,value,sha256,file_type\r\n'


def test_unicode_commas_quotes_and_multiline_roundtrip():
    result = TriageResult(sample=SampleInfo(), iocs=IOCs(
        urls=['https://example.test/a?x="a,b"'], mutexes=['café, "雪"\nsecond line'],
        dropped=[DroppedFile('résumé, "雪".exe', 'PE, executable', 'a' * 64)],
    ))
    exported = rows(render_iocs_csv(result))
    assert exported[0]['value'] == result.iocs.urls[0]
    assert exported[1]['value'] == result.iocs.mutexes[0]
    assert exported[2]['value'] == result.iocs.dropped[0].name
    assert exported[2]['file_type'] == 'PE, executable'
    assert exported[2]['sha256'] == 'a' * 64


@pytest.mark.parametrize('value', ['=1+1', '+1+1', '-1+1', '@SUM(A1:A2)', '\t=1', '\r=1', '\n=1', '  =1', ' \t@SUM(A1)'])
def test_formula_prefixes_are_neutralized_in_all_user_controlled_columns(value):
    result = TriageResult(sample=SampleInfo(), iocs=IOCs(
        domains=[value], dropped=[DroppedFile(value, value, value)],
    ))
    exported = rows(render_iocs_csv(result))
    assert exported[0]['value'] == "'" + value
    assert all(exported[1][field] == "'" + value for field in ['value', 'sha256', 'file_type'])
    # Spreadsheet protection must not mutate the underlying result or JSON.
    assert json.loads(render_json(result, iocs_only=True))['domains'] == [value]


def test_missing_dropped_fields_and_non_string_values_do_not_crash():
    result = TriageResult(sample=SampleInfo(), iocs=IOCs(
        dropped=[DroppedFile(name=None, type=None, sha256=None)], ips=[123],
    ))
    exported = rows(render_iocs_csv(result))
    assert exported[0]['value'] == '123'
    assert exported[1] == {'type': 'dropped_file', 'value': '', 'sha256': '', 'file_type': ''}


def test_cli_csv_stdout_exit_code_and_no_extra_rows(capsys):
    assert main([SAMPLE, '-f', 'csv']) == 1
    output = capsys.readouterr()
    assert output.err == ''
    assert len(rows(output.out)) == analyze(parse(SAMPLE)).iocs.total()
    assert output.out.endswith('\n') and not output.out.endswith('\n\n')
    assert main([SAMPLE, '-f', 'csv', '--no-fail', '--iocs-only']) == 0
    assert capsys.readouterr().out == output.out


def test_cli_csv_file_and_signature_filter(tmp_path, capsys):
    dest = tmp_path / 'indicators.csv'
    assert main([SAMPLE, '-f', 'csv', '-o', str(dest), '--min-severity', '99']) == 1
    output = capsys.readouterr()
    assert output.out == '' and 'wrote csv report to' in output.err
    with dest.open(encoding='utf-8', newline='') as f:
        exported = list(csv.DictReader(f))
    assert len(exported) == analyze(parse(SAMPLE)).iocs.total()


def test_cli_csv_clean_and_input_error(tmp_path, capsys):
    clean = tmp_path / 'clean.json'
    clean.write_text(json.dumps({'info': {'score': 0}, 'signatures': []}))
    assert main([str(clean), '-f', 'csv']) == 0
    assert capsys.readouterr().out == 'type,value,sha256,file_type\r\n'
    assert main([str(tmp_path / 'missing.json'), '-f', 'csv', '--no-fail']) == 2
    assert 'file not found' in capsys.readouterr().err


def test_embedded_carriage_return_preserves_a_single_indicator():
    value = 'HKCU\\Software\\first\rsecond'
    result = TriageResult(sample=SampleInfo(), iocs=IOCs(registry_keys=[value]))
    text = render_iocs_csv(result)
    assert text.endswith('\r\n')
    assert len(rows(text)) == 1
    assert rows(text)[0]['value'] == value
