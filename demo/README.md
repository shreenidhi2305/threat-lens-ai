# Demo assets

| Item | Purpose |
|---|---|
| `DEMO_SCRIPT.md` | Screen-share walkthrough of the whole platform (Milestones 1-4) |
| `m4_end_to_end_demo.py` | Drives a running API through every workflow and checks it; seeds all dashboards |
| `m2_live_ml_demo.py` | Streams one real malicious and one real benign PE (DikeDataset, MIT) through the API to show the ML model |
| `generate_samples.py` | Regenerates the synthetic samples in `samples/` |
| `samples/` | Synthetic detection-test files |

```bash
python demo/m4_end_to_end_demo.py              # full run against http://127.0.0.1:8000
python demo/m4_end_to_end_demo.py --skip-real  # no internet needed
python demo/m4_end_to_end_demo.py --pause      # wait for Enter between sections
python demo/m4_end_to_end_demo.py --rate-limit # also trip the login limiter (run last)
```

## The synthetic samples

**None is live malware.** They contain no runnable payload and no EICAR string, so local
antivirus leaves them alone; the embedded URLs and IPs are inert indicator strings that go
nowhere. Their job is to exercise the analysis pipeline. Real malware used by the demo is
streamed into memory from DikeDataset and posted straight to the API; it is never written to
disk.

| File | Score | Verdict | Demonstrates |
|---|---|---|---|
| `clean_notes.txt` | 0 | benign | Baseline clean file |
| `injector_strings.txt` | 20 | suspicious | YARA `Process_Injection_APIs` |
| `packed_blob.bin` | 35 | suspicious | High Shannon entropy, "likely packed" |
| `invoice_2026.pdf.exe` | 54 | suspicious | Extension/content mismatch plus persistence commands |
| `upload.php` | 72 | malicious | YARA `WebShell_Indicators` |
| `invoice_macro.doc.txt` | 91 | malicious | Office-macro dropper plus obfuscated PowerShell, embedded URL and IP |
| `README_TO_DECRYPT.txt` | 100 | malicious | **Signature match** plus ransom-note YARA rule |
| `trojan_downloader.bin` | 100 | malicious | **Signature match plus 11 YARA rules**, 6 URLs and 3 IPs |

## Keep the samples byte-identical

The two signature samples are matched by SHA-256 against
`backend/app/modules/file_analysis/data/signatures.json`. Any change, including Windows
line-ending conversion, breaks the match and the "Known Trojan" demo scores 72 instead of
100. `.gitattributes` marks `demo/samples/*` as `-text` to stop that, and
`backend/tests/test_demo_assets.py` fails if a sample drifts. If you regenerate samples,
update the signature hashes to match.
