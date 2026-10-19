# Changelog

## v1.1.1 — 2026-10-19

- Use CRLF CSV record separators so embedded carriage returns are quoted correctly on Python 3.8/3.10 as well as newer Python versions.
- Add a regression test for embedded carriage returns; 38 tests pass locally.

## v1.1.0 — 2026-10-19

- Add `--format csv` for offline IOC export, with `type,value,sha256,file_type` columns.
- Include domains, IPs, URLs, registry keys, mutexes and dropped-file names/hashes/types.
- Quote commas, double quotes and multiline values; write UTF-8 output with a header even for empty IOC sets.
- Prefix formula-like cells with an apostrophe for spreadsheet use; preserve raw values in JSON.
- Preserve existing scoring, signature filters, and triage exit codes.
- Expand the test suite from 21 to 37 passing tests.
