"""Parse a CAPE / Cuckoo ``report.json`` into the normalised data model.

Both sandboxes share most of the schema; where they differ we read whichever
key is present. Every access is defensive — a truncated or partial report must
never crash the triage, it just yields fewer indicators.
"""

from __future__ import annotations

import json
from typing import Dict, List

from .models import DroppedFile, IOCs, Process, SampleInfo, Signature, TriageResult
from .utils import as_float, as_int, dedupe


class ReportError(Exception):
    """Raised when the input is not a usable sandbox report."""


def load(path: str) -> Dict:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ReportError(f"not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ReportError("top-level JSON is not an object")
    # A real report always carries at least one of these sections.
    if not any(k in data for k in ("target", "info", "signatures", "behavior", "CAPE")):
        raise ReportError("does not look like a CAPE/Cuckoo report (no known sections)")
    return data


def _sample(data: Dict) -> SampleInfo:
    target = (data.get("target") or {}).get("file") or {}
    return SampleInfo(
        name=target.get("name", "") or (data.get("target") or {}).get("url", ""),
        size=as_int(target.get("size")),
        type=target.get("type", ""),
        md5=target.get("md5", ""),
        sha1=target.get("sha1", ""),
        sha256=target.get("sha256", ""),
    )


def _signatures(data: Dict) -> List[Signature]:
    out: List[Signature] = []
    for sig in data.get("signatures", []) or []:
        if not isinstance(sig, dict):
            continue
        # CAPE puts technique ids under "ttp" (dict or list); normalise to a list.
        raw_ttp = sig.get("ttp") or sig.get("ttps") or []
        if isinstance(raw_ttp, dict):
            ttps = list(raw_ttp.keys())
        elif isinstance(raw_ttp, list):
            ttps = [t.get("ttp", t) if isinstance(t, dict) else t for t in raw_ttp]
        else:
            ttps = [raw_ttp]
        out.append(
            Signature(
                name=sig.get("name", "unknown"),
                description=sig.get("description", ""),
                severity=as_int(sig.get("severity"), 1),
                ttps=[str(t) for t in ttps if t],
            )
        )
    return out


def _network_iocs(data: Dict, iocs: IOCs) -> None:
    net = data.get("network") or {}
    # Domains can appear as a flat list of dicts or strings.
    for dom in net.get("domains", []) or []:
        iocs.domains.append(dom.get("domain", "") if isinstance(dom, dict) else str(dom))
    for q in net.get("dns", []) or []:
        if isinstance(q, dict) and q.get("request"):
            iocs.domains.append(q["request"])
    for host in net.get("hosts", []) or []:
        iocs.ips.append(host.get("ip", "") if isinstance(host, dict) else str(host))
    for conn in (net.get("tcp", []) or []) + (net.get("udp", []) or []):
        if isinstance(conn, dict) and conn.get("dst"):
            iocs.ips.append(conn["dst"])
    for req in net.get("http", []) or []:
        if not isinstance(req, dict):
            continue
        url = req.get("uri") or ""
        host = req.get("host") or ""
        if url.startswith("http"):
            iocs.urls.append(url)
        elif host and url:
            iocs.urls.append(f"http://{host}{url}")
        if host:
            iocs.domains.append(host)


def _behaviour_iocs(data: Dict, iocs: IOCs) -> List[Process]:
    behavior = data.get("behavior") or {}
    summary = behavior.get("summary") or {}
    for key in summary.get("keys", []) or summary.get("write_keys", []) or []:
        iocs.registry_keys.append(str(key))
    for mutex in summary.get("mutexes", []) or summary.get("mutex", []) or []:
        iocs.mutexes.append(str(mutex))

    procs: List[Process] = []
    for proc in behavior.get("processes", []) or []:
        if not isinstance(proc, dict):
            continue
        procs.append(
            Process(
                pid=as_int(proc.get("process_id") or proc.get("pid")),
                ppid=as_int(proc.get("parent_id") or proc.get("ppid")),
                name=proc.get("process_name") or proc.get("name", ""),
                command_line=proc.get("command_line") or proc.get("environ", {}).get("CommandLine", "")
                if isinstance(proc.get("environ"), dict)
                else proc.get("command_line", ""),
            )
        )
    return procs


def _dropped(data: Dict, iocs: IOCs) -> None:
    for drop in data.get("dropped", []) or []:
        if not isinstance(drop, dict):
            continue
        iocs.dropped.append(
            DroppedFile(
                name=(drop.get("name") or [""])[0] if isinstance(drop.get("name"), list) else drop.get("name", ""),
                type=drop.get("type", ""),
                sha256=drop.get("sha256", ""),
            )
        )


def _families(data: Dict) -> List[str]:
    det = data.get("detections")
    fams: List[str] = []
    if isinstance(det, str):
        fams.append(det)
    elif isinstance(det, list):
        for d in det:
            fams.append(d.get("family", "") if isinstance(d, dict) else str(d))
    elif isinstance(det, dict):
        fams.append(det.get("family", ""))
    # CAPE config extraction also names families.
    for cfg in data.get("CAPE", {}).get("configs", []) if isinstance(data.get("CAPE"), dict) else []:
        if isinstance(cfg, dict):
            fams.extend(cfg.keys())
    return dedupe([f for f in fams if f])


def parse(path: str) -> TriageResult:
    """Load and normalise a report file into a :class:`TriageResult`."""
    data = load(path)
    info = data.get("info") or {}
    iocs = IOCs()

    _network_iocs(data, iocs)
    procs = _behaviour_iocs(data, iocs)
    _dropped(data, iocs)

    # Dedupe and tidy every indicator list.
    iocs.domains = dedupe(iocs.domains)
    iocs.ips = dedupe(iocs.ips)
    iocs.urls = dedupe(iocs.urls)
    iocs.registry_keys = dedupe(iocs.registry_keys)
    iocs.mutexes = dedupe(iocs.mutexes)

    source = "cape" if "CAPE" in data or "malscore" in data else "cuckoo"

    return TriageResult(
        sample=_sample(data),
        score=as_float(data.get("malscore", info.get("score"))),
        family=_families(data),
        signatures=_signatures(data),
        iocs=iocs,
        processes=procs,
        analysis_id=str(info.get("id")) if info.get("id") is not None else None,
        duration=as_int(info.get("duration")) or None,
        source=source,
    )
