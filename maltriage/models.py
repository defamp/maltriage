"""Data models for a triaged sandbox report.

Everything the parser produces is normalised into these dataclasses so the
analyzer and the reporters never have to care whether the source was a CAPE or
a legacy Cuckoo ``report.json``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Verdict ladder — kept identical to the rest of the toolkit (PhishTriage,
# LogSleuth) so a reviewer sees one consistent scale across the portfolio.
VERDICTS = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Verdicts that should fail an automated pipeline (CLI exits non-zero).
FAILING_VERDICTS = {"HIGH", "CRITICAL"}


@dataclass
class SampleInfo:
    """The analysed file's identity."""

    name: str = ""
    size: int = 0
    type: str = ""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""


@dataclass
class Signature:
    """A behavioural signature the sandbox fired."""

    name: str
    description: str = ""
    severity: int = 1
    ttps: List[str] = field(default_factory=list)


@dataclass
class Technique:
    """A resolved MITRE ATT&CK technique."""

    id: str
    name: str = ""

    @property
    def url(self) -> str:
        # Sub-techniques (T1059.001) live under their parent's page.
        base = self.id.split(".")[0]
        if "." in self.id:
            return f"https://attack.mitre.org/techniques/{base}/{self.id.split('.')[1]}/"
        return f"https://attack.mitre.org/techniques/{base}/"


@dataclass
class DroppedFile:
    name: str = ""
    type: str = ""
    sha256: str = ""


@dataclass
class IOCs:
    """Indicators of compromise extracted from the run."""

    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    dropped: List[DroppedFile] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    mutexes: List[str] = field(default_factory=list)

    def total(self) -> int:
        return (
            len(self.domains)
            + len(self.ips)
            + len(self.urls)
            + len(self.dropped)
            + len(self.registry_keys)
            + len(self.mutexes)
        )

    def is_empty(self) -> bool:
        return self.total() == 0


@dataclass
class Process:
    pid: int = 0
    ppid: int = 0
    name: str = ""
    command_line: str = ""


@dataclass
class TriageResult:
    """The full, normalised triage of one sandbox report."""

    sample: SampleInfo
    score: float = 0.0
    verdict: str = "CLEAN"
    family: List[str] = field(default_factory=list)
    signatures: List[Signature] = field(default_factory=list)
    techniques: List[Technique] = field(default_factory=list)
    iocs: IOCs = field(default_factory=IOCs)
    processes: List[Process] = field(default_factory=list)
    analysis_id: Optional[str] = None
    duration: Optional[int] = None
    source: str = "cape"

    def to_dict(self) -> Dict:
        """Machine-readable export (feeds e.g. IOC Hunter / a SOAR playbook)."""
        return {
            "sample": {
                "name": self.sample.name,
                "size": self.sample.size,
                "type": self.sample.type,
                "md5": self.sample.md5,
                "sha1": self.sample.sha1,
                "sha256": self.sample.sha256,
            },
            "verdict": self.verdict,
            "score": self.score,
            "family": self.family,
            "analysis_id": self.analysis_id,
            "duration": self.duration,
            "source": self.source,
            "signatures": [
                {
                    "name": s.name,
                    "severity": s.severity,
                    "description": s.description,
                    "ttps": s.ttps,
                }
                for s in self.signatures
            ],
            "mitre_attack": [{"id": t.id, "name": t.name, "url": t.url} for t in self.techniques],
            "iocs": {
                "domains": self.iocs.domains,
                "ips": self.iocs.ips,
                "urls": self.iocs.urls,
                "dropped_files": [
                    {"name": d.name, "type": d.type, "sha256": d.sha256} for d in self.iocs.dropped
                ],
                "registry_keys": self.iocs.registry_keys,
                "mutexes": self.iocs.mutexes,
            },
        }
