# Demo assets

Synthetic detection-test files for the Milestone 1 walkthrough. **None is live
malware.** They contain no runnable payload and no EICAR string, so local
antivirus leaves them alone; the embedded URLs/IPs are inert indicator strings
that go nowhere. Their only job is to exercise the static-analysis pipeline
(hashing, metadata, signature matching, YARA, IOC extraction, risk scoring).

Regenerate with:

```bash
python demo/generate_samples.py
```

## Samples and expected verdicts

| File | Score | Verdict | Demonstrates |
|---|---|---|---|
| `clean_notes.txt` | 0 · low | Likely Benign | Baseline clean file |
| `injector_strings.txt` | 20 · medium | Suspicious | YARA `Process_Injection_APIs` |
| `packed_blob.bin` | 35 · medium | Suspicious | High Shannon entropy, "likely packed" |
| `invoice_2026.pdf.exe` | 54 · medium | Suspicious | Extension/content mismatch + persistence commands |
| `upload.php` | 72 · high | Potential WebShell Malware | YARA `WebShell_Indicators` |
| `invoice_macro.doc.txt` | 91 · high | Potential Dropper Malware | YARA Office-macro dropper + obfuscated PowerShell, embedded URL + IP |
| `README_TO_DECRYPT.txt` | 100 · high | Known Ransomware | **Signature match** + YARA ransom-note rule |
| `trojan_downloader.bin` | 100 · high | Known Trojan | **Signature match + 11 YARA rules** (downloader, LOLBins, AMSI bypass, Defender tampering, shadow-copy deletion, persistence, credential access, injection, C2 config), **6 URLs + 3 IPs** |

`trojan_downloader.bin` is the headline sample: upload it and the system
returns a 100/100 verdict with a named signature and a full detection
breakdown. Scores come from `backend/app/modules/file_analysis/analyzers/risk.py`
and shift slightly if the rules are tuned.

See `DEMO_SCRIPT.md` for the screen-recording walkthrough.
