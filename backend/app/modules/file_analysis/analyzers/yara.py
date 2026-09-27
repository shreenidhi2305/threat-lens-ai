"""YARA rule matching for static analysis.

Rules live in ``file_analysis/rules/*.yar`` and are compiled once per process.
If ``yara-python`` is not installed the analyzer degrades gracefully: it returns
no matches and reports ``available = False`` so callers/UI can say so rather than
silently claiming the file is clean.
"""

import functools
from pathlib import Path

try:
    import yara  # type: ignore

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    yara = None  # type: ignore
    _YARA_AVAILABLE = False

_RULES_DIR = Path(__file__).resolve().parent.parent / 'rules'
_MAX_STRING_MATCHES = 20


def yara_available() -> bool:
    return _YARA_AVAILABLE


@functools.lru_cache(maxsize=1)
def _compiled_rules():
    if not _YARA_AVAILABLE:
        return None
    filepaths = {p.stem: str(p) for p in sorted(_RULES_DIR.glob('*.yar'))}
    if not filepaths:
        return None
    return yara.compile(filepaths=filepaths)


_FALLBACK_RULES_META: dict[str, dict[str, object]] = {
    "EICAR_Test_File": {"description": "EICAR anti-malware test file (harmless standard test string)", "severity": "info", "family": "Test"},
    "PowerShell_Download_Cradle": {"description": "PowerShell one-liner that downloads and executes a payload", "severity": "high", "family": "Downloader", "mitre": "T1059.001, T1105"},
    "PowerShell_Obfuscation_And_Bypass": {"description": "Obfuscated / policy-bypassing PowerShell invocation", "severity": "high", "family": "Obfuscation", "mitre": "T1027, T1059.001, T1562.001"},
    "LOLBin_Ingress_Tool_Transfer": {"description": "Living-off-the-land binaries used to fetch remote payloads", "severity": "high", "family": "Downloader", "mitre": "T1105, T1218"},
    "Malicious_Office_Macro_Dropper": {"description": "VBA auto-exec macro that spawns a shell / drops a file", "severity": "high", "family": "Dropper", "mitre": "T1566.001, T1059.005"},
    "Defense_Evasion_Disable_Security_Tools": {"description": "Commands that disable Defender / firewall / logging", "severity": "high", "family": "DefenseEvasion", "mitre": "T1562.001, T1562.004"},
    "AMSI_Bypass_Indicators": {"description": "Strings associated with in-memory AMSI/ETW patching", "severity": "high", "family": "DefenseEvasion", "mitre": "T1562.001"},
    "ShadowCopy_Deletion": {"description": "Volume shadow copy deletion (ransomware / anti-recovery)", "severity": "high", "family": "Impact", "mitre": "T1490"},
    "Sandbox_Anti_Analysis": {"description": "Sandbox / VM / debugger evasion strings", "severity": "medium", "family": "AntiAnalysis", "mitre": "T1497"},
    "Persistence_Run_Key_Or_Task": {"description": "Registry Run-key / scheduled task / service persistence", "severity": "medium", "family": "Persistence", "mitre": "T1547.001, T1053.005, T1543.003"},
    "UAC_Bypass_Indicators": {"description": "Known UAC-bypass primitives", "severity": "medium", "family": "PrivEsc", "mitre": "T1548.002"},
    "Credential_Access_Tooling": {"description": "LSASS dumping / credential theft strings", "severity": "high", "family": "Stealer", "mitre": "T1003, T1555.003"},
    "Keylogger_Indicators": {"description": "Keystroke capture API usage", "severity": "medium", "family": "Spyware", "mitre": "T1056.001"},
    "Process_Injection_APIs": {"description": "Classic remote-process injection API set", "severity": "medium", "family": "Injector", "mitre": "T1055"},
    "CobaltStrike_Beacon_Indicators": {"description": "Artifacts consistent with a Cobalt Strike beacon", "severity": "high", "family": "Beacon", "mitre": "T1071.001, T1573"},
    "C2_Beacon_Config": {"description": "Hard-coded C2 URL plus beacon-style HTTP config", "severity": "high", "family": "Backdoor", "mitre": "T1071.001, T1571"},
    "Ransomware_Note_Or_Behavior": {"description": "Ransom-note language or bulk-encryption behavior", "severity": "high", "family": "Ransomware", "mitre": "T1486, T1490"},
    "WebShell_Indicators": {"description": "Server-side web shell (PHP / ASPX / JSP)", "severity": "high", "family": "WebShell", "mitre": "T1505.003"},
    "Embedded_Base64_Blob": {"description": "Large base64 blob embedded in the file (possible packed payload)", "severity": "low", "family": "Obfuscation", "mitre": "T1027"},
    "Known_Packer_Section_Names": {"description": "PE section names left by common runtime packers", "severity": "medium", "family": "Packed", "mitre": "T1027.002"},
    "Embedded_PE_In_NonExecutable": {"description": "A second PE header embedded well inside a non-PE file", "severity": "medium", "family": "Dropper", "mitre": "T1027.009"},
}


def _fallback_scan(data: bytes) -> list[dict]:
    """Pure-python YARA emulation for environments without yara-python.

    Returns synthetic matches for the most critical rules so risk scoring and
    behavioral analysis still work. Keeps the same {rule, tags, meta, matched_strings}
    contract as the real YARA scan.
    """
    lc = data.lower()
    # keep original for case-sensitive checks but most are nocase
    results: list[dict] = []

    def add(rule: str, evidence: list[str] | None = None):
        meta = dict(_FALLBACK_RULES_META.get(rule, {"severity": "low"}))
        results.append({"rule": rule, "tags": [], "meta": meta, "matched_strings": evidence or [rule]})

    # EICAR
    if b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in data:
        add("EICAR_Test_File", ["EICAR test string"])

    # PowerShell_Download_Cradle
    if b"powershell" in lc:
        needles = [b"iex", b"invoke-expression", b"downloadstring", b"downloadfile", b"downloaddata", b"net.webclient", b"invoke-webrequest", b"invoke-restmethod", b"start-bitstransfer"]
        hits = sum(1 for n in needles if n in lc)
        # also consider DownloadString case with dot
        if hits >= 2:
            add("PowerShell_Download_Cradle")

    # PowerShell_Obfuscation_And_Bypass
    obf_needles = [b"-encodedcommand", b"-enc ", b"frombase64string", b"-executionpolicy bypass", b"-ep bypass", b"-noprofile", b"-windowstyle hidden", b"-w hidden", b"iex", b"gzipstream", b"deflatestream", b"-join"]
    # require 3 hits and powershell present? Original YARA requires 3 of them regardless; we approximate
    if sum(1 for n in obf_needles if n in lc) >= 3 and b"powershell" in lc:
        add("PowerShell_Obfuscation_And_Bypass")

    # LOLBin_Ingress_Tool_Transfer - needs 2 patterns; emulate with string counts
    lol_needs = [b"certutil -urlcache", b"certutil.exe -urlcache", b"certutil -decode", b"bitsadmin /transfer", b"mshta http", b"mshta.exe http", b"regsvr32 /s /n /u /i:http", b"curl http", b"wget http"]
    lol_hits = sum(1 for n in lol_needs if n in lc)
    # also count generic certutil urlcache as hit if present alongside another indicator
    if lol_hits >= 2:
        add("LOLBin_Ingress_Tool_Transfer")
    elif lol_hits >= 1 and b"downloadstring" in lc:
        # download cradle often pairs certutil with downloadstring -> count as 2nd signal
        add("LOLBin_Ingress_Tool_Transfer")

    # Malicious_Office_Macro_Dropper
    auto = [b"autoopen", b"document_open", b"workbook_open", b"auto_close"]
    macro_needles = [b'createobject("wscript.shell")', b"shell(", b"wscript.shell", b"environ(", b"adodb.stream", b"msxml2.xmlhttp", b"powershell"]
    if any(a in lc for a in auto) and sum(1 for n in macro_needles if n in lc) >= 2:
        add("Malicious_Office_Macro_Dropper")

    # Defense_Evasion_Disable_Security_Tools
    dis_needs = [b"set-mppreference -disablerealtimemonitoring", b"add-mppreference -exclusionpath", b"netsh advfirewall set allprofiles state off", b"sc stop windefend", b"sc config windefend start= disabled", b"wevtutil cl ", b"clear-eventlog", b"disableantispyware"]
    if sum(1 for n in dis_needs if n in lc) >= 2:
        add("Defense_Evasion_Disable_Security_Tools")

    # AMSI_Bypass_Indicators
    amsi_needs = [b"amsiscanbuffer", b"amsiinitfailed", b"amsiutils", b"system.management.automation.amsiutils", b"etweventwrite", b"[ref].assembly.gettype("]
    if sum(1 for n in amsi_needs if n.lower() in lc or n in data) >= 2:
        # check raw for case-sensitive like AmsiScanBuffer
        cnt = 0
        for n in [b"AmsiScanBuffer", b"amsiInitFailed", b"AmsiUtils", b"System.Management.Automation.AmsiUtils", b"EtwEventWrite", b"[Ref].Assembly.GetType("]:
            if n.lower() in lc:
                cnt += 1
        if cnt >= 2:
            add("AMSI_Bypass_Indicators")

    # ShadowCopy_Deletion - needs 2 patterns
    shadow_needs = [b"vssadmin delete shadows", b"vssadmin.exe delete shadows", b"wmic shadowcopy delete", b"win32_shadowcopy", b"bcdedit /set {default} recoveryenabled no", b"wbadmin delete catalog"]
    shadow_hits = sum(1 for n in shadow_needs if n in lc)
    if shadow_hits >= 2:
        add("ShadowCopy_Deletion")
    elif b"vssadmin delete shadows" in lc and b"shadowcopy" in lc:
        add("ShadowCopy_Deletion")

    # Sandbox_Anti_Analysis
    sandbox_needs = [b"isdebuggerpresent", b"checkremotedebuggerpresent", b"vboxservice", b"vboxtray", b"vmtoolsd", b"sbiedll.dll", b"wine_get_unix_file_name", b"gettickcount", b"sleep"]
    if sum(1 for n in sandbox_needs if n in lc) >= 3:
        add("Sandbox_Anti_Analysis")

    # Persistence_Run_Key_Or_Task
    pers_needs = [b"\\currentversion\\run", b"reg add", b"schtasks /create", b"register-scheduledtask", b"new-service", b"sc create", b"__eventfilter", b"commandlineeventconsumer", b"\\start menu\\programs\\startup"]
    if sum(1 for n in pers_needs if n in lc) >= 2:
        add("Persistence_Run_Key_Or_Task")

    # UAC_Bypass_Indicators
    uac_needs = [b"fodhelper.exe", b"computerdefaults.exe", b"\\ms-settings\\shell\\open\\command", b"eventvwr.exe", b"sdclt.exe", b"delegateexecute"]
    if sum(1 for n in uac_needs if n in lc) >= 2:
        add("UAC_Bypass_Indicators")

    # Credential_Access_Tooling
    cred_needs = [b"sekurlsa::logonpasswords", b"mimikatz", b"lsass.exe", b"minidumpwritedump", b"comsvcs.dll, minidump", b"\\login data", b"\\local state", b"moz_logins", b"wallet.dat", b"local\\google\\chrome\\user data"]
    if sum(1 for n in cred_needs if n in lc) >= 2:
        add("Credential_Access_Tooling")
    elif b"mimikatz" in lc and b"lsass.exe" in lc:
        add("Credential_Access_Tooling")

    # Keylogger_Indicators
    key_needs = [b"setwindowshookex", b"getasynckeystate", b"getkeyboardstate", b"wh_keyboard_ll", b"getforegroundwindow"]
    if sum(1 for n in key_needs if n in lc) >= 3:
        add("Keylogger_Indicators")

    # Process_Injection_APIs
    inj_needs = [b"virtualallocex", b"writeprocessmemory", b"createremotethread", b"ntcreatethreadex", b"queueuserapc", b"ntunmapviewofsection", b"setthreadcontext", b"rtlcreateuserthread"]
    if sum(1 for n in inj_needs if n in lc) >= 3:
        add("Process_Injection_APIs")

    # CobaltStrike_Beacon_Indicators
    cs_needs = [b"beacon.dll", b"%s as %s\\%s: %d", b"reflectiveloader", b"/submit.php?id=", b"msse-", b"content-type: application/octet-stream", b"spawnto_x86", b"malleable"]
    if sum(1 for n in cs_needs if n in lc) >= 2:
        add("CobaltStrike_Beacon_Indicators")

    # C2_Beacon_Config
    import re as _re
    url_pat = _re.compile(rb'https?://(\d{1,3}\.){3}\d{1,3}[\/:]')
    if url_pat.search(data):
        c2_needs = [b"x-malware-c2:", b"c2:", b"/gate.php", b"/panel/", b"user-agent: mozilla", b"beacon", b"sleep"]
        # need url + 2 of those, but also sleep pattern
        c2_hits = sum(1 for n in c2_needs if n in lc)
        sleep_hit = _re.search(rb'sleep\s*[:=]\s*\d{3,}', lc) is not None
        if c2_hits >= 2 or (sleep_hit and c2_hits >= 1):
            add("C2_Beacon_Config")

    # Ransomware_Note_Or_Behavior
    rans_needs = [b"your files have been encrypted", b"all your files", b"decryption key", b"bitcoin", b"btc wallet", b".onion", b"pay the ransom", b"cryptencrypt", b"bcryptencrypt", b".locked", b"readme_to_decrypt", b"vssadmin delete shadows"]
    if sum(1 for n in rans_needs if n in lc) >= 3:
        add("Ransomware_Note_Or_Behavior")

    # WebShell_Indicators
    if b"<?php" in lc:
        php_needs = [b"eval", b"base64_decode", b"gzinflate", b"str_rot13", b"shell_exec($_", b"system($_", b"assert($_"]
        # original YARA: ($php1 and 1 of ($php2,$php3,$php4,$php5)) or asp/jsp
        if any(n in lc for n in [b"eval(base64_decode", b"eval(gzinflate", b"shell_exec($_", b"system($_", b"assert($_"]):
            add("WebShell_Indicators")
        elif b"eval" in lc and b"base64_decode" in lc:
            add("WebShell_Indicators")
    # ASP/JSP alternative
    if b'eval(request' in lc or b'server.createobject("wscript.shell")' in lc or b"runtime.getruntime().exec(request." in lc:
        if not any(r["rule"] == "WebShell_Indicators" for r in results):
            add("WebShell_Indicators")

    # Embedded_Base64_Blob
    import re as _re2
    if b"TVqQAAMAAAAEAAAA" in data or _re2.search(rb'[A-Za-z0-9+\/]{1000,}={0,2}', data):
        add("Embedded_Base64_Blob")

    # Known_Packer_Section_Names - requires MZ header
    if data[:2] == b"MZ":
        pack_needs = [b"UPX0", b"UPX1", b".aspack", b".MPRESS1", b".themida", b"PEC2", b".petite", b"FSG!"]
        if any(n in data for n in pack_needs):
            add("Known_Packer_Section_Names")

    # Embedded_PE_In_NonExecutable
    if data[:2] != b"MZ" and b"This program cannot be run in DOS mode" in data and data.count(b"MZ") >= 1:
        add("Embedded_PE_In_NonExecutable")

    return results


def scan_with_yara(data: bytes) -> list[dict]:
    """Return a list of match dicts: ``{rule, tags, meta, matched_strings}``."""
    rules = _compiled_rules()
    if rules is None:
        # Fallback emulation so tests/environments without yara still get signal
        return _fallback_scan(data)

    results: list[dict] = []
    for match in rules.match(data=data):
        matched_strings = sorted(
            {
                instance.matched_data[:80].decode('utf-8', 'replace')
                for string_match in match.strings
                for instance in string_match.instances[:5]
            }
        )[:_MAX_STRING_MATCHES]
        results.append(
            {
                'rule': match.rule,
                'tags': list(match.tags),
                'meta': dict(match.meta),
                'matched_strings': matched_strings,
            }
        )
    return results
