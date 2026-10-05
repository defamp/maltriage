"""Turn a parsed report into a verdict, ranked signatures and resolved TTPs."""

from __future__ import annotations

from typing import List

from .models import Signature, Technique, TriageResult
from .utils import dedupe, technique_name

# CAPE's malscore runs 0-10. These thresholds map it onto the shared ladder.
SCORE_THRESHOLDS = [
    (8.0, "CRITICAL"),
    (6.0, "HIGH"),
    (3.0, "MEDIUM"),
    (1.0, "LOW"),
    (0.0, "CLEAN"),
]


def _score_to_verdict(score: float) -> str:
    for threshold, verdict in SCORE_THRESHOLDS:
        if score >= threshold:
            return verdict
    return "CLEAN"


def _derive_score(signatures: List[Signature]) -> float:
    """Fallback score when the report carries no malscore.

    Approximates CAPE's weighting: each signature contributes its severity,
    capped at 10. A single sev-3 signature alone lands in MEDIUM.
    """
    if not signatures:
        return 0.0
    total = sum(max(s.severity, 1) for s in signatures)
    return min(float(total), 10.0)


def _resolve_techniques(signatures: List[Signature]) -> List[Technique]:
    ids: List[str] = []
    for sig in signatures:
        ids.extend(sig.ttps)
    techniques = [Technique(id=tid, name=technique_name(tid)) for tid in dedupe(ids)]
    # Stable, readable ordering: by technique id.
    return sorted(techniques, key=lambda t: t.id)


def analyze(result: TriageResult) -> TriageResult:
    """Populate ``verdict`` and ``techniques``; rank signatures by severity.

    Mutates and returns ``result`` so callers can chain parse -> analyze.
    """
    # Highest-severity signatures first, then alphabetical for determinism.
    result.signatures.sort(key=lambda s: (-s.severity, s.name))

    # Prefer the sandbox's own malscore; derive one only if it's absent/zero
    # while signatures clearly fired.
    if result.score <= 0 and result.signatures:
        result.score = _derive_score(result.signatures)

    result.verdict = _score_to_verdict(result.score)

    # A high-severity signature should never be buried under a soft verdict.
    if any(s.severity >= 3 for s in result.signatures) and result.verdict in ("CLEAN", "LOW"):
        result.verdict = "MEDIUM"

    result.techniques = _resolve_techniques(result.signatures)
    return result


def filter_signatures(result: TriageResult, min_severity: int) -> List[Signature]:
    """Signatures at or above ``min_severity`` (used by the reporters)."""
    return [s for s in result.signatures if s.severity >= min_severity]
