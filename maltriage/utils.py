"""Small helpers: deduping, type coercion and a bundled MITRE ATT&CK lookup.

The ATT&CK map is intentionally embedded (not fetched) so maltriage stays
100% offline with no API keys — matching the rest of the toolkit.
"""

from __future__ import annotations

from typing import Iterable, List

# A curated subset of MITRE ATT&CK technique ids -> names, covering the
# techniques sandboxes report most often. Unknown ids still render (just
# without a friendly name), so the tool never hides data it can't resolve.
ATTACK_TECHNIQUES = {
    "T1055": "Process Injection",
    "T1055.012": "Process Hollowing",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1112": "Modify Registry",
    "T1113": "Screen Capture",
    "T1120": "Peripheral Device Discovery",
    "T1134": "Access Token Manipulation",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1204": "User Execution",
    "T1204.002": "Malicious File",
    "T1211": "Exploitation for Defense Evasion",
    "T1218": "System Binary Proxy Execution",
    "T1222": "File and Directory Permissions Modification",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1489": "Service Stop",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1497.001": "System Checks",
    "T1518": "Software Discovery",
    "T1518.001": "Security Software Discovery",
    "T1543": "Create or Modify System Process",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1564": "Hide Artifacts",
    "T1566": "Phishing",
    "T1573": "Encrypted Channel",
    "T1614": "System Location Discovery",
    "T1614.001": "System Language Discovery",
    "T1057": "Process Discovery",
    "T1012": "Query Registry",
    "T1016": "System Network Configuration Discovery",
    "T1033": "System Owner/User Discovery",
    "T1070": "Indicator Removal",
    "T1105": "Ingress Tool Transfer",
}


def technique_name(tid: str) -> str:
    """Resolve an ATT&CK id to a name, falling back to the id itself."""
    return ATTACK_TECHNIQUES.get(tid, ATTACK_TECHNIQUES.get(tid.split(".")[0], ""))


def dedupe(items: Iterable, limit: int = 0) -> List:
    """Order-preserving dedupe, with an optional cap."""
    seen = set()
    out: List = []
    for item in items:
        key = item if isinstance(item, (str, int)) else str(item)
        if key in seen or key in ("", None):
            continue
        seen.add(key)
        out.append(item)
        if limit and len(out) >= limit:
            break
    return out


def as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
