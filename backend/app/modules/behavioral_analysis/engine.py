"""Static behavioral analysis engine.

Turns static-analysis signals into MITRE ATT&CK behaviors. No execution.

Sources consumed (all static):
  - raw file bytes (lower-cased substring search for API / keyword indicators)
  - suspicious_strings labels from risk.py
  - YARA matches (rule name + meta.mitre / meta.severity / meta.family)
  - network IOCs (urls / ips / domains)
  - metadata (entropy, likely_packed, extension mismatch, file type)
  - signature match

Each behavior lists its evidence rule-lambdas; a behavior is observed when
one or more evidence items fire. Confidence scales with corroboration.
"""

from __future__ import annotations

import re
from collections import defaultdict

# ---------------------------------------------------------------------------
# Tactic ordering (kill-chain order for attack_chain visualization)
# ---------------------------------------------------------------------------

_TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

_TACTIC_IDS: dict[str, str] = {
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Exfiltration": "TA0010",
    "Impact": "TA0040",
}

# ---------------------------------------------------------------------------
# Severity weighting for behavioral risk scoring
# ---------------------------------------------------------------------------

_SEV_WEIGHT: dict[str, int] = {
    "critical": 28,
    "high": 18,
    "medium": 10,
    "low": 5,
    "info": 1,
}

# Map technique_id base (Txxxx) to mitre url
def _mitre_url(technique_id: str) -> str:
    base = technique_id.split(".")[0]
    # sub-technique URLs use the full id without dot, e.g. T1059/001
    if "." in technique_id:
        return f"https://attack.mitre.org/techniques/{base}/{technique_id.split('.')[1]}/"
    return f"https://attack.mitre.org/techniques/{base}/"


# ---------------------------------------------------------------------------
# API keyword groups (mirrors ml/features/extractor import categories)
# ---------------------------------------------------------------------------

_API_NEEDLES: dict[str, tuple[str, ...]] = {
    "proc_inject": ("virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection", "setthreadcontext", "queueuserapc"),
    "crypto_enc": ("cryptencrypt", "bcryptencrypt", "cryptgenkey"),
    "keylog": ("setwindowshookex", "getasynckeystate", "getkeyboardstate", "getforegroundwindow"),
    "reg": ("regopenkey", "regsetvalue", "regcreatekey"),
    "anti_debug": ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"),
}

# Suspicious token regex is intentionally byte-level tolerant – we search raw bytes lowercased
def _contains(data_lc: bytes, needle: str) -> bool:
    return needle.lower().encode() in data_lc


def _count_contains(data_lc: bytes, needles: tuple[str, ...]) -> int:
    return sum(1 for n in needles if _contains(data_lc, n))


# ---------------------------------------------------------------------------
# Behavior definitions
#
# Each entry defines:
#   id, tactic, technique, technique_id, name, description, severity
#   check: function that appends evidence items into a list and returns bool-ish
# ---------------------------------------------------------------------------

def _add_evidence(evidence: list[dict], typ: str, value: str, conf: float = 0.85) -> None:
    evidence.append({"type": typ, "value": value, "confidence": conf})


def _behavior_defs() -> list[dict]:
    """Return the static catalog. Keep as function so definitions are fresh-copied."""
    return [
        {
            "id": "B001",
            "tactic": "Execution",
            "technique": "Command and Scripting Interpreter: PowerShell",
            "technique_id": "T1059.001",
            "name": "PowerShell execution",
            "description": "PowerShell invocation or encoded command pattern indicating interactive or fileless execution.",
            "severity": "high",
        },
        {
            "id": "B002",
            "tactic": "Execution",
            "technique": "Command and Scripting Interpreter: Windows Command Shell",
            "technique_id": "T1059.003",
            "name": "Command-shell execution",
            "description": "cmd.exe /c or shell invocation pattern suggestive of command delegation.",
            "severity": "medium",
        },
        {
            "id": "B003",
            "tactic": "Execution",
            "technique": "Native API",
            "technique_id": "T1106",
            "name": "Native API / injection primitives",
            "description": "Classic process-injection API set (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread).",
            "severity": "high",
        },
        {
            "id": "B004",
            "tactic": "Execution",
            "technique": "User Execution: Malicious File",
            "technique_id": "T1204.002",
            "name": "Malicious Office macro / dropper",
            "description": "VBA auto-exec (AutoOpen/Document_Open) with shell dropper primitives.",
            "severity": "high",
        },
        {
            "id": "B005",
            "tactic": "Persistence",
            "technique": "Boot or Logon Autostart Execution: Registry Run Keys",
            "technique_id": "T1547.001",
            "name": "Registry Run-key persistence",
            "description": "Registry Run-key artifact (\\CurrentVersion\\Run) or reg add persistence.",
            "severity": "medium",
        },
        {
            "id": "B006",
            "tactic": "Persistence",
            "technique": "Scheduled Task/Job",
            "technique_id": "T1053.005",
            "name": "Scheduled task persistence",
            "description": "schtasks /create or Register-ScheduledTask persistence artifact.",
            "severity": "medium",
        },
        {
            "id": "B007",
            "tactic": "Persistence",
            "technique": "Server-Side Component: Web Shell",
            "technique_id": "T1505.003",
            "name": "Web-shell deployment",
            "description": "PHP/ASP/JSP server-side shell (eval/base64_decode, WScript.Shell, Runtime.exec).",
            "severity": "critical",
        },
        {
            "id": "B008",
            "tactic": "Privilege Escalation",
            "technique": "Abuse Elevation Control Mechanism: Bypass UAC",
            "technique_id": "T1548.002",
            "name": "UAC bypass primitive",
            "description": "Known UAC-bypass binary or registry path (fodhelper, eventvwr, DelegateExecute).",
            "severity": "high",
        },
        {
            "id": "B009",
            "tactic": "Defense Evasion",
            "technique": "Obfuscated Files or Information",
            "technique_id": "T1027",
            "name": "Obfuscated / encoded payload",
            "description": "EncodedCommand, FromBase64String, gzip/deflate streams or -w hidden obfuscation.",
            "severity": "medium",
        },
        {
            "id": "B010",
            "tactic": "Defense Evasion",
            "technique": "Obfuscated Files or Information: Software Packing",
            "technique_id": "T1027.002",
            "name": "Packed / encrypted payload",
            "description": "High entropy, packing section names (UPX, Themida) or base64-embedded PE.",
            "severity": "medium",
        },
        {
            "id": "B011",
            "tactic": "Defense Evasion",
            "technique": "Impair Defenses: Disable or Modify Tools",
            "technique_id": "T1562.001",
            "name": "Security-tool tampering",
            "description": "Commands that disable Defender, firewall, or event logging.",
            "severity": "high",
        },
        {
            "id": "B012",
            "tactic": "Defense Evasion",
            "technique": "Impair Defenses: Disable or Modify Tools (AMSI/ETW)",
            "technique_id": "T1562.001",
            "name": "AMSI/ETW bypass",
            "description": "In-memory patching strings (AmsiScanBuffer, amsiInitFailed, EtwEventWrite).",
            "severity": "high",
        },
        {
            "id": "B013",
            "tactic": "Defense Evasion",
            "technique": "Virtualization/Sandbox Evasion",
            "technique_id": "T1497",
            "name": "Sandbox / VM evasion",
            "description": "Anti-analysis checks (IsDebuggerPresent, VBoxService, vmtoolsd, GetTickCount).",
            "severity": "medium",
        },
        {
            "id": "B014",
            "tactic": "Defense Evasion",
            "technique": "Masquerading",
            "technique_id": "T1036",
            "name": "Extension / type masquerading",
            "description": "Declared extension does not match detected content type (classic masquerading).",
            "severity": "low",
        },
        {
            "id": "B015",
            "tactic": "Credential Access",
            "technique": "OS Credential Dumping",
            "technique_id": "T1003",
            "name": "Credential dumping (LSASS / Mimikatz)",
            "description": "LSASS dumping primitives (sekurlsa::logonpasswords, mimikatz, MiniDumpWriteDump).",
            "severity": "critical",
        },
        {
            "id": "B016",
            "tactic": "Credential Access",
            "technique": "Credentials from Password Stores",
            "technique_id": "T1555",
            "name": "Browser / credential-store harvesting",
            "description": "Access to browser login databases (Login Data, Local State, wallet.dat, moz_logins).",
            "severity": "high",
        },
        {
            "id": "B017",
            "tactic": "Discovery",
            "technique": "Process Discovery",
            "technique_id": "T1057",
            "name": "Process enumeration",
            "description": "Process-listing APIs (CreateToolhelp32Snapshot, Process32First).",
            "severity": "low",
        },
        {
            "id": "B018",
            "tactic": "Collection",
            "technique": "Input Capture: Keylogging",
            "technique_id": "T1056.001",
            "name": "Keystroke capture",
            "description": "Keylogging API set (SetWindowsHookEx, GetAsyncKeyState, WH_KEYBOARD_LL).",
            "severity": "high",
        },
        {
            "id": "B019",
            "tactic": "Command and Control",
            "technique": "Application Layer Protocol: Web Protocols",
            "technique_id": "T1071.001",
            "name": "Web-protocol C2",
            "description": "Embedded HTTP(s) URLs with beacon-style config (gate.php, C2 header, sleep interval).",
            "severity": "high",
        },
        {
            "id": "B020",
            "tactic": "Command and Control",
            "technique": "Ingress Tool Transfer",
            "technique_id": "T1105",
            "name": "Ingress tool / download cradle",
            "description": "Living-off-the-land download primitives (certutil, bitsadmin, DownloadString/File, mshta).",
            "severity": "high",
        },
        {
            "id": "B021",
            "tactic": "Command and Control",
            "technique": "Encrypted Channel",
            "technique_id": "T1573",
            "name": "Encrypted / anonymous channel",
            "description": "Indicators of encrypted or onion-routed C2 (.onion, cobaltstrike, malleable beacon).",
            "severity": "high",
        },
        {
            "id": "B022",
            "tactic": "Command and Control",
            "technique": "Remote Access Tools (Beacon)",
            "technique_id": "T1219",
            "name": "Beacon / Cobalt Strike infrastructure",
            "description": "Beacon artifacts (beacon.dll, ReflectiveLoader, spawnto, CobaltStrike YARA).",
            "severity": "critical",
        },
        {
            "id": "B023",
            "tactic": "Impact",
            "technique": "Data Encrypted for Impact",
            "technique_id": "T1486",
            "name": "Ransomware encryption",
            "description": "Ransom-note language, bulk-encryption APIs (CryptEncrypt, BCryptEncrypt, .locked).",
            "severity": "critical",
        },
        {
            "id": "B024",
            "tactic": "Impact",
            "technique": "Inhibit System Recovery",
            "technique_id": "T1490",
            "name": "System recovery inhibition",
            "description": "Shadow-copy deletion (vssadmin delete shadows, wmic shadowcopy delete).",
            "severity": "high",
        },
        {
            "id": "B025",
            "tactic": "Defense Evasion",
            "technique": "Deobfuscate/Decode Files or Information",
            "technique_id": "T1140",
            "name": "Embedded PE droppper",
            "description": "Secondary PE header embedded in a non-PE file (droppers / stagers).",
            "severity": "medium",
        },
        {
            "id": "B026",
            "tactic": "Exfiltration",
            "technique": "Exfiltration Over C2 Channel",
            "technique_id": "T1041",
            "name": "Embedded data exfiltration",
            "description": "Large exfil-like IOC set: many URLs + high entropy + public IPs (heuristic).",
            "severity": "medium",
        },
    ]


BEHAVIOR_CATALOG: list[dict] = _behavior_defs()


# ---------------------------------------------------------------------------
# Core evaluator
# ---------------------------------------------------------------------------

def _score_behavior(severity: str, evidence_count: int) -> tuple[float, int]:
    """Return (confidence, risk_contribution) for a flagged behavior."""
    # corroboration: more independent evidence -> higher confidence
    base = 0.55
    if evidence_count == 1:
        conf = 0.62
    elif evidence_count == 2:
        conf = 0.82
    elif evidence_count >= 3:
        conf = 0.94
    else:
        conf = base
    # severity floors: critical behaviors are high-confidence even with one evidence
    if severity in ("critical", "high") and evidence_count == 1:
        conf = max(conf, 0.72)
    # risk contribution is severity weight scaled by corroboration
    weight = _SEV_WEIGHT.get(severity, 5)
    if evidence_count >= 3:
        weight = min(weight + 4, 30)
    elif evidence_count == 1 and severity in ("critical", "high"):
        weight = max(weight - 2, 8)
    return round(conf, 2), weight


def evaluate_behaviors(
    data: bytes,
    *,
    suspicious_strings: list[str] | None = None,
    yara_matches: list[dict] | None = None,
    network: dict | None = None,
    metadata: dict | None = None,
    signature_match: dict | None = None,
    strings_sample: list[str] | None = None,
) -> list[dict]:
    """Evaluate the catalog against static signals.

    Returns a list of behavior dicts enriched with observed, evidence, confidence, etc.
    One entry per catalog item (observed=True for flagged, False otherwise).
    """
    suspicious_strings = suspicious_strings or []
    yara_matches = yara_matches or []
    network = network or {"urls": [], "ips": [], "domains": []}
    metadata = metadata or {}
    signature_match = signature_match or {"matched": False}
    strings_sample = strings_sample or []

    data_lc = data.lower() if data else b""
    suspicious_set = set(suspicious_strings)
    yara_rule_names = {m.get("rule", "") for m in yara_matches}
    yara_families = {str(m.get("meta", {}).get("family", "")).lower() for m in yara_matches}
    yara_mitres: set[str] = set()
    for m in yara_matches:
        mitre = str(m.get("meta", {}).get("mitre", ""))
        for part in re.split(r"[,\s]+", mitre):
            part = part.strip()
            if part:
                yara_mitres.add(part.upper())

    # Helper closures for readability
    def has_yara(*names: str) -> bool:
        return any(n in yara_rule_names for n in names)

    def has_mitre(*ids: str) -> bool:
        return any(i.upper() in yara_mitres for i in ids)

    def has_susp(*labels: str) -> bool:
        return any(lbl in suspicious_set for lbl in labels)

    results: list[dict] = []

    for b in BEHAVIOR_CATALOG:
        bid = b["id"]
        ev: list[dict] = []

        # Each branch appends evidence where the static signal matches that behavior.
        if bid == "B001":  # PowerShell
            if _contains(data_lc, "powershell") or _contains(data_lc, "pwsh"):
                _add_evidence(ev, "string", "powershell keyword in file", 0.85)
            if has_susp("PowerShell execution"):
                _add_evidence(ev, "string", "suspicious string: PowerShell execution", 0.88)
            if has_yara("PowerShell_Download_Cradle", "PowerShell_Obfuscation_And_Bypass"):
                _add_evidence(ev, "yara", "YARA: PowerShell download/obfuscation rule", 0.95)
            if _contains(data_lc, "invoke-expression") or _contains(data_lc, "iex "):
                _add_evidence(ev, "api", "IEX / Invoke-Expression keyword", 0.78)
            if has_mitre("T1059.001"):
                _add_evidence(ev, "yara", "MITRE T1059.001 in YARA metadata", 0.90)

        elif bid == "B002":  # cmd.exe /c
            if has_susp("Command shell invocation"):
                _add_evidence(ev, "string", "suspicious string: cmd.exe /c", 0.88)
            if _contains(data_lc, "cmd.exe"):
                _add_evidence(ev, "string", "cmd.exe string", 0.80)
            if _contains(data_lc, "wscript") or _contains(data_lc, "cscript"):
                _add_evidence(ev, "string", "Script host wscript/cscript", 0.75)

        elif bid == "B003":  # Injection APIs
            hits = _count_contains(data_lc, _API_NEEDLES["proc_inject"])
            if hits:
                _add_evidence(ev, "api", f"Process-injection APIs found ({hits})", 0.90)
            if _contains(data_lc, "virtualalloc") or _contains(data_lc, "virtualprotect"):
                _add_evidence(ev, "api", "VirtualAlloc / VirtualProtect API", 0.85)
            if has_yara("Process_Injection_APIs"):
                _add_evidence(ev, "yara", "YARA: Process_Injection_APIs", 0.95)
            if has_mitre("T1055"):
                _add_evidence(ev, "yara", "MITRE T1055 in YARA metadata", 0.88)

        elif bid == "B004":  # Macro dropper
            if has_yara("Malicious_Office_Macro_Dropper"):
                _add_evidence(ev, "yara", "YARA: Malicious_Office_Macro_Dropper", 0.96)
            if _contains(data_lc, "autoopen") or _contains(data_lc, "document_open"):
                _add_evidence(ev, "string", "VBA auto-exec keyword", 0.85)
            if has_mitre("T1566.001", "T1059.005"):
                _add_evidence(ev, "yara", "MITRE T1566.001/T1059.005 in YARA", 0.88)

        elif bid == "B005":  # Run key
            if _contains(data_lc, "\\currentversion\\run") or _contains(data_lc, "currentversion\\run"):
                _add_evidence(ev, "string", "Registry Run-key path", 0.90)
            if _contains(data_lc, "reg add") and _contains(data_lc, "run"):
                _add_evidence(ev, "string", "reg add … Run persistence", 0.88)
            if has_yara("Persistence_Run_Key_Or_Task"):
                _add_evidence(ev, "yara", "YARA: Persistence_Run_Key_Or_Task", 0.90)
            if has_mitre("T1547.001"):
                _add_evidence(ev, "yara", "MITRE T1547.001", 0.85)

        elif bid == "B006":  # Scheduled task
            if has_susp("Scheduled task creation"):
                _add_evidence(ev, "string", "suspicious string: schtasks /create", 0.92)
            if _contains(data_lc, "schtasks"):
                _add_evidence(ev, "string", "schtasks keyword", 0.86)
            if _contains(data_lc, "register-scheduledtask"):
                _add_evidence(ev, "api", "Register-ScheduledTask", 0.90)
            if has_mitre("T1053.005"):
                _add_evidence(ev, "yara", "MITRE T1053.005", 0.84)

        elif bid == "B007":  # Web shell
            if has_yara("WebShell_Indicators"):
                _add_evidence(ev, "yara", "YARA: WebShell_Indicators", 0.98)
            if _contains(data_lc, "<?php") and _contains(data_lc, "eval"):
                _add_evidence(ev, "string", "PHP eval shell pattern", 0.90)
            if _contains(data_lc, "wscript.shell") and _contains(data_lc, "server.createobject"):
                _add_evidence(ev, "string", "ASP shell pattern", 0.88)
            if has_mitre("T1505.003"):
                _add_evidence(ev, "yara", "MITRE T1505.003", 0.90)

        elif bid == "B008":  # UAC bypass
            if has_yara("UAC_Bypass_Indicators"):
                _add_evidence(ev, "yara", "YARA: UAC_Bypass_Indicators", 0.94)
            if _contains(data_lc, "fodhelper") or _contains(data_lc, "computerdefaults"):
                _add_evidence(ev, "string", "UAC bypass binary name", 0.88)
            if _contains(data_lc, "delegateexecute"):
                _add_evidence(ev, "api", "DelegateExecute", 0.82)
            if has_mitre("T1548.002"):
                _add_evidence(ev, "yara", "MITRE T1548.002", 0.88)

        elif bid == "B009":  # Obfuscation encoded
            if has_susp("Encoded PowerShell command", "Base64 decode", "AMSI bypass"):
                # leverage suspicious_strings but be specific
                if "Encoded PowerShell command" in suspicious_set:
                    _add_evidence(ev, "string", "suspicious string: Encoded PowerShell command", 0.88)
                if "Base64 decode" in suspicious_set:
                    _add_evidence(ev, "string", "suspicious string: Base64 decode", 0.82)
            if _contains(data_lc, "-encodedcommand") or _contains(data_lc, "frombase64string"):
                _add_evidence(ev, "string", "Encoded PowerShell token", 0.86)
            if _contains(data_lc, "-w hidden") or _contains(data_lc, "-windowstyle hidden"):
                _add_evidence(ev, "string", "Obfuscated PowerShell args", 0.84)
            if has_yara("PowerShell_Obfuscation_And_Bypass", "Embedded_Base64_Blob"):
                _add_evidence(ev, "yara", "YARA: obfuscation / base64 blob", 0.90)
            if has_mitre("T1027"):
                _add_evidence(ev, "yara", "MITRE T1027", 0.80)

        elif bid == "B010":  # Packed
            if metadata.get("likely_packed"):
                _add_evidence(ev, "metadata", f"High entropy {metadata.get('shannon_entropy', '?')} (likely packed)", 0.84)
            if has_yara("Known_Packer_Section_Names", "Embedded_Base64_Blob"):
                _add_evidence(ev, "yara", "YARA: packer / base64 embedded PE", 0.88)
            if has_mitre("T1027.002"):
                _add_evidence(ev, "yara", "MITRE T1027.002", 0.82)
            if metadata.get("shannon_entropy", 0) and metadata.get("shannon_entropy", 0) > 7.5:
                _add_evidence(ev, "metadata", "Shannon entropy > 7.5", 0.80)

        elif bid == "B011":  # Disable tools
            if has_susp("Defender tampering"):
                _add_evidence(ev, "string", "suspicious string: Defender tampering", 0.90)
            if _contains(data_lc, "set-mppreference") or _contains(data_lc, "add-mppreference"):
                _add_evidence(ev, "string", "MpPreference tampering", 0.88)
            if has_yara("Defense_Evasion_Disable_Security_Tools"):
                _add_evidence(ev, "yara", "YARA: Disable_Security_Tools", 0.95)
            if _contains(data_lc, "wevtutil") or _contains(data_lc, "clear-eventlog"):
                _add_evidence(ev, "string", "Event-log clearing command", 0.84)
            if has_mitre("T1562.001"):
                _add_evidence(ev, "yara", "MITRE T1562.001", 0.84)

        elif bid == "B012":  # AMSI
            if has_susp("AMSI bypass"):
                _add_evidence(ev, "string", "suspicious string: AMSI bypass", 0.92)
            if _contains(data_lc, "amsiscanbuffer") or _contains(data_lc, "amsiutils"):
                _add_evidence(ev, "string", "AMSI artifact in file", 0.90)
            if has_yara("AMSI_Bypass_Indicators"):
                _add_evidence(ev, "yara", "YARA: AMSI_Bypass_Indicators", 0.96)
            if has_mitre("T1562.001"):
                # already counted but still corroborates
                pass

        elif bid == "B013":  # Sandbox evasion
            if has_yara("Sandbox_Anti_Analysis"):
                _add_evidence(ev, "yara", "YARA: Sandbox_Anti_Analysis", 0.88)
            hits = _count_contains(data_lc, _API_NEEDLES["anti_debug"])
            if hits:
                _add_evidence(ev, "api", f"Anti-debug APIs ({hits})", 0.84)
            if _contains(data_lc, "vboxservice") or _contains(data_lc, "vmtoolsd") or _contains(data_lc, "sbiedll"):
                _add_evidence(ev, "string", "VM/sandbox service name", 0.82)

        elif bid == "B014":  # Masquerading
            if metadata.get("extension_matches_content") is False:
                ext = metadata.get("extension") or "unknown"
                ftype = metadata.get("file_type") or "unknown"
                _add_evidence(ev, "metadata", f"Extension '{ext}' mismatches content ({ftype})", 0.88)
            if metadata.get("file_type") == "PHP script" and metadata.get("extension") == "jpg":
                _add_evidence(ev, "metadata", "PHP masquerading as image", 0.92)

        elif bid == "B015":  # LSASS dump
            if has_susp("Credential tooling"):
                _add_evidence(ev, "string", "suspicious string: Credential tooling (mimikatz/lsass)", 0.90)
            if _contains(data_lc, "mimikatz") or _contains(data_lc, "sekurlsa"):
                _add_evidence(ev, "string", "mimikatz / sekurlsa keyword", 0.96)
            if _contains(data_lc, "lsass.exe") or _contains(data_lc, "minidumpwritedump"):
                _add_evidence(ev, "string", "LSASS / MiniDump artifact", 0.88)
            if has_yara("Credential_Access_Tooling"):
                _add_evidence(ev, "yara", "YARA: Credential_Access_Tooling", 0.95)
            if has_mitre("T1003"):
                _add_evidence(ev, "yara", "MITRE T1003", 0.86)

        elif bid == "B016":  # Password stores
            if _contains(data_lc, "login data") or _contains(data_lc, "local state"):
                _add_evidence(ev, "string", "Browser credential store path", 0.88)
            if _contains(data_lc, "wallet.dat") or _contains(data_lc, "moz_logins"):
                _add_evidence(ev, "string", "Wallet / moz_logins path", 0.86)
            if _contains(data_lc, "chrome\\user data"):
                _add_evidence(ev, "string", "Chrome User Data path", 0.84)
            if has_mitre("T1555"):
                _add_evidence(ev, "yara", "MITRE T1555", 0.84)

        elif bid == "B017":  # Process discovery
            hits = _count_contains(data_lc, ("createtoolhelp32snapshot", "process32first", "openprocess"))
            if hits:
                _add_evidence(ev, "api", f"Process discovery APIs ({hits})", 0.82)
            if _contains(data_lc, "createtoolhelp32snapshot"):
                _add_evidence(ev, "api", "CreateToolhelp32Snapshot", 0.85)

        elif bid == "B018":  # Keylog
            if has_yara("Keylogger_Indicators"):
                _add_evidence(ev, "yara", "YARA: Keylogger_Indicators", 0.92)
            hits = _count_contains(data_lc, _API_NEEDLES["keylog"])
            if hits:
                _add_evidence(ev, "api", f"Keylogging APIs ({hits})", 0.88)
            if has_mitre("T1056.001"):
                _add_evidence(ev, "yara", "MITRE T1056.001", 0.85)

        elif bid == "B019":  # Web C2
            if network.get("urls"):
                _add_evidence(ev, "network", f"Embedded URL(s): {len(network['urls'])}", 0.82)
            if has_yara("C2_Beacon_Config", "CobaltStrike_Beacon_Indicators"):
                _add_evidence(ev, "yara", "YARA: C2 beacon config", 0.94)
            if network.get("domains") and len(network["domains"]) > 2:
                _add_evidence(ev, "network", f"Multiple domains ({len(network['domains'])})", 0.78)
            if has_mitre("T1071.001"):
                _add_evidence(ev, "yara", "MITRE T1071.001", 0.84)

        elif bid == "B020":  # Ingress tool transfer
            if has_susp("LOLBins (rundll32/regsvr32/mshta)", "certutil / bitsadmin download"):
                if "LOLBins (rundll32/regsvr32/mshta)" in suspicious_set:
                    _add_evidence(ev, "string", "suspicious string: LOLBin", 0.84)
                if "certutil / bitsadmin download" in suspicious_set:
                    _add_evidence(ev, "string", "suspicious string: certutil/bitsadmin download", 0.90)
            if _contains(data_lc, "certutil") and _contains(data_lc, "urlcache"):
                _add_evidence(ev, "string", "certutil urlcache download", 0.88)
            if _contains(data_lc, "bitsadmin") or _contains(data_lc, "downloadstring") or _contains(data_lc, "downloadfile"):
                _add_evidence(ev, "string", "Download cradle keyword", 0.84)
            if has_yara("PowerShell_Download_Cradle", "LOLBin_Ingress_Tool_Transfer"):
                _add_evidence(ev, "yara", "YARA: download cradle / LOLBin transfer", 0.94)
            if has_mitre("T1105"):
                _add_evidence(ev, "yara", "MITRE T1105", 0.84)

        elif bid == "B021":  # Encrypted channel onion
            if _contains(data_lc, ".onion"):
                _add_evidence(ev, "network", "Onion domain reference (.onion)", 0.96)
            if _contains(data_lc, "cobaltstrike") or _contains(data_lc, "meterpreter"):
                _add_evidence(ev, "string", "CobaltStrike / Meterpreter keyword", 0.92)
            if has_mitre("T1573"):
                _add_evidence(ev, "yara", "MITRE T1573", 0.82)
            if network.get("ips") and any(ip.startswith("45.") or ip.startswith("185.") for ip in network["ips"]):
                # heuristic: suspicious public IP ranges often used in examples (keep light)
                pass

        elif bid == "B022":  # Beacon infrastructure
            if has_yara("CobaltStrike_Beacon_Indicators"):
                _add_evidence(ev, "yara", "YARA: CobaltStrike_Beacon_Indicators", 0.98)
            if _contains(data_lc, "beacon.dll") or _contains(data_lc, "reflectiveloader"):
                _add_evidence(ev, "string", "Beacon artifact", 0.94)
            if has_mitre("T1071.001", "T1573") and has_yara("CobaltStrike_Beacon_Indicators"):
                _add_evidence(ev, "yara", "MITRE C2 + beacon corroboration", 0.88)

        elif bid == "B023":  # Ransomware encryption
            if has_yara("Ransomware_Note_Or_Behavior"):
                _add_evidence(ev, "yara", "YARA: Ransomware_Note_Or_Behavior", 0.98)
            if has_mitre("T1486"):
                _add_evidence(ev, "yara", "MITRE T1486", 0.88)
            if _contains(data_lc, "your files have been encrypted") or _contains(data_lc, "decryption key"):
                _add_evidence(ev, "string", "Ransom note language", 0.94)
            if _contains(data_lc, "cryptencrypt") or _contains(data_lc, "bcryptencrypt"):
                _add_evidence(ev, "api", "Encryption API CryptEncrypt/BCryptEncrypt", 0.86)
            if has_susp("Shadow copy deletion"):
                # ransom often comes with shadow deletion; kept as corroboration not primary
                pass

        elif bid == "B024":  # Inhibit recovery
            if has_susp("Shadow copy deletion"):
                _add_evidence(ev, "string", "suspicious string: Shadow copy deletion", 0.92)
            if has_yara("ShadowCopy_Deletion"):
                _add_evidence(ev, "yara", "YARA: ShadowCopy_Deletion", 0.96)
            if _contains(data_lc, "vssadmin delete shadows") or _contains(data_lc, "wmic shadowcopy delete"):
                _add_evidence(ev, "string", "Shadow deletion command", 0.94)
            if has_mitre("T1490"):
                _add_evidence(ev, "yara", "MITRE T1490", 0.88)

        elif bid == "B025":  # Embedded PE dropper
            if has_yara("Embedded_PE_In_NonExecutable", "Embedded_Base64_Blob"):
                if "Embedded_PE_In_NonExecutable" in yara_rule_names:
                    _add_evidence(ev, "yara", "YARA: Embedded_PE_In_NonExecutable", 0.92)
                if "Embedded_Base64_Blob" in yara_rule_names and _contains(data_lc, "tvqqaam"):
                    _add_evidence(ev, "yara", "YARA: Embedded_Base64_Blob with MZ payload", 0.88)
            if metadata.get("file_type") and "PE" not in metadata.get("file_type", "") and _contains(data_lc, "this program cannot be run in dos mode"):
                _add_evidence(ev, "string", "DOS stub in non-PE file", 0.86)

        elif bid == "B026":  # Exfiltration heuristic
            url_count = len(network.get("urls", []))
            ip_count = len(network.get("ips", []))
            entropy = metadata.get("shannon_entropy", 0) or 0
            if url_count >= 2 and entropy > 6.5:
                _add_evidence(ev, "network", f"{url_count} URLs + high entropy ({entropy:.2f}) - possible exfiltration", 0.70)
            if url_count >= 3 and ip_count >= 1:
                _add_evidence(ev, "network", f"Multiple IOCs ({url_count} URLs, {ip_count} IPs)", 0.72)

        observed = len(ev) > 0
        confidence, risk_contrib = _score_behavior(b["severity"], len(ev)) if observed else (0.0, 0)

        results.append(
            {
                **b,
                "mitre_url": _mitre_url(b["technique_id"]),
                "observed": observed,
                "evidence": ev,
                "confidence": confidence,
                "risk_contribution": risk_contrib,
            }
        )

    return results


def compute_behavioral_risk(behaviors: list[dict]) -> tuple[int, str, float]:
    """Compute aggregate behavioral risk score, level and avg confidence."""
    observed = [x for x in behaviors if x["observed"]]
    if not observed:
        return 0, "low", 0.0

    score = sum(x["risk_contribution"] for x in observed)
    # bonus for tactic diversity: each distinct tactic adds 4 points (capped)
    tactics = {x["tactic"] for x in observed}
    score += min(len(tactics) * 4, 16)
    # bonus for critical behaviors clustering
    criticals = sum(1 for x in observed if x["severity"] == "critical")
    if criticals >= 2:
        score += 10

    score = max(0, min(int(round(score)), 100))
    # level mirrors risk.py thresholds but for behavioral score the medium band is a bit wider
    if score > 64:
        level: str = "high"
    elif score > 24:
        level = "medium"
    else:
        level = "low"

    avg_conf = round(sum(x["confidence"] for x in observed) / len(observed), 2) if observed else 0.0
    return score, level, avg_conf


def tactics_summary(behaviors: list[dict]) -> list[dict]:
    total_by_tactic: dict[str, int] = defaultdict(int)
    detected_by_tactic: dict[str, int] = defaultdict(int)
    max_sev_by_tactic: dict[str, str] = {}
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    for x in behaviors:
        total_by_tactic[x["tactic"]] += 1
        if x["observed"]:
            detected_by_tactic[x["tactic"]] += 1
            cur = max_sev_by_tactic.get(x["tactic"])
            if cur is None or sev_order[x["severity"]] > sev_order[cur]:
                max_sev_by_tactic[x["tactic"]] = x["severity"]

    summary = []
    # preserve kill-chain order plus any leftover tactics alphabetically
    seen = set()
    for tactic in _TACTIC_ORDER:
        if tactic in total_by_tactic:
            summary.append(
                {
                    "tactic": tactic,
                    "tactic_id": _TACTIC_IDS.get(tactic, ""),
                    "detected": detected_by_tactic.get(tactic, 0),
                    "total": total_by_tactic[tactic],
                    "max_severity": max_sev_by_tactic.get(tactic),
                }
            )
            seen.add(tactic)
    for tactic in sorted(set(total_by_tactic) - seen):
        summary.append(
            {
                "tactic": tactic,
                "tactic_id": _TACTIC_IDS.get(tactic, ""),
                "detected": detected_by_tactic.get(tactic, 0),
                "total": total_by_tactic[tactic],
                "max_severity": max_sev_by_tactic.get(tactic),
            }
        )
    return summary


def attack_chain(behaviors: list[dict]) -> list[str]:
    observed_tactics = {x["tactic"] for x in behaviors if x["observed"]}
    return [t for t in _TACTIC_ORDER if t in observed_tactics]


def kill_chain_stage(behaviors: list[dict]) -> str | None:
    chain = attack_chain(behaviors)
    return chain[-1] if chain else None


def summarize(behaviors: list[dict], risk_level: str) -> str:
    observed = [x for x in behaviors if x["observed"]]
    if not observed:
        return "No malicious behaviors inferred from static signals. The file appears benign under behavioral analysis."
    tactic_list = attack_chain(behaviors)
    top = sorted(observed, key=lambda x: _SEV_WEIGHT.get(x["severity"], 0), reverse=True)[:2]
    top_names = ", ".join(x["name"] for x in top)
    tactic_str = ", ".join(tactic_list)
    if risk_level == "high":
        tone = "High-risk behavioral profile"
    elif risk_level == "medium":
        tone = "Suspicious behavioral indicators"
    else:
        tone = "Low-risk behavioral signals"
    return (
        f"{tone}: {len(observed)} behavior(s) detected across {len(tactic_list)} tactic(s) ({tactic_str}). "
        f"Top indicators: {top_names}. "
        f"All findings are static approximations; no code was executed."
    )
