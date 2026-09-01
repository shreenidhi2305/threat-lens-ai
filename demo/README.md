# Demo assets

Harmless sample files for demonstrating the Milestone 1 static-analysis
pipeline. **None of these is real malware** and none contains the EICAR string,
so local antivirus will leave them alone. They only contain suspicious-looking
*text* (command strings, URLs) and random bytes.

Regenerate them with:

```bash
python demo/generate_samples.py
```

## Samples and expected results

| File | Risk | Verdict | What it demonstrates |
|---|---|---|---|
| `clean_notes.txt` | 0 · low | Likely Benign | Baseline — a clean file |
| `injector_strings.txt` | 22 · medium | Suspicious | YARA rule `Windows_Process_Injection_APIs` |
| `invoice_2026.pdf.exe` | 32 · medium | Suspicious | Extension/content mismatch + LOLBin strings |
| `packed_blob.bin` | 35 · medium | Suspicious | High Shannon entropy → "likely packed" |
| `suspicious_macro_dump.txt` | 92 · high | Potential Downloader Malware | YARA (PowerShell cradle + shell commands), embedded URL + public IP, suspicious command strings |
| `known_demo_trojan.bin` | 95 · high | Known Trojan | SHA-256 signature match against `signatures.json` |

Scores come from the rule-based engine in
`backend/app/modules/file_analysis/analyzers/risk.py` and may shift slightly if
the rules are tuned.

See `DEMO_SCRIPT.md` for the screen-recording walkthrough.
