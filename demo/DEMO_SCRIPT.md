# Milestone 1 — Demo Walkthrough

Screen-recording script: authentication, RBAC, and the static file-analysis
workflow, end to end. **Run time: ~4 minutes.**

---

## 0. Start the stack (before recording)

Two terminals from the repo root:

```bash
python -m uvicorn app.main:app --app-dir backend --port 8000
```

```bash
npm --prefix frontend run dev
```

Open **http://localhost:5173**. No database or cloud account needed: the backend
runs in local dev mode (dev login + local file storage). If the samples are
missing, run `python demo/generate_samples.py`.

---

## 1. Authentication (30s)

1. Show the sign-in screen.
2. Sign in as **`analyst@local`** (any password).
3. Land on the Overview dashboard. Point out the top-bar user menu (email +
   role) and "Your access: **Scan**".

*JWT auth. Locally a dev login; in production the same endpoint authenticates
against Supabase Auth and reads the role from the `profiles` table.*

---

## 2. Role-based access control (45s)

1. Sign out, sign back in as **`soc@local`**.
2. Dashboard now reads "**Read** — monitoring & dashboards only".
3. The sidebar has no **Submit File** or **Reports**: a SOC Team Member cannot
   run scans.
4. Optional, in `http://localhost:8000/docs`: `POST /api/v1/files/scan` with a
   SOC token → **403**; with an analyst token → **200**.

*RBAC is enforced server-side on every route via `require_roles()` and mirrored
in the database with row-level-security policies. The UI just reflects it.*

---

## 3. Clean file (20s)

1. Back in as **`analyst@local`** → **Submit File**.
2. Drop `demo/samples/clean_notes.txt`.
3. **Risk 0/100 · LOW · Likely Benign.** No indicators.

---

## 4. "We caught the malware" (90s)

1. **Submit File** → drop `demo/samples/trojan_downloader.bin`.
2. Walk the report top to bottom:
   - Verdict: **100/100 · HIGH · "Known Trojan (TrojanDownloader.Win32.Demo)"**,
     action *Escalate to Security Analyst*.
   - **Suspicious Indicators**: the known-signature hit, then ~11 YARA rules.
   - **Detection → Signature Match**: `TrojanDownloader.Win32.Demo`, severity
     high. The file's SHA-256 is in the signature set.
   - **Detection → YARA**: download cradle, LOLBin transfer, AMSI bypass,
     Defender tampering, shadow-copy deletion, persistence, credential access,
     process injection, C2 beacon config, base64 blob, each with matched
     strings and an ATT&CK id.
   - **Network Indicators**: 6 URLs and 3 IPs pulled straight from the bytes.
   - **File Details**: type, size, entropy, all three hashes (hover to copy).
3. Then drop `demo/samples/README_TO_DECRYPT.txt` → **100/100 · "Known
   Ransomware"** (signature + ransom-note YARA rule).
4. Optional quick hits:
   - `upload.php` → HIGH, YARA `WebShell_Indicators`.
   - `invoice_2026.pdf.exe` → MEDIUM, indicator *extension does not match
     detected content*.

*This is the full static pipeline from the spec: hashing, metadata, signature
matching, YARA, IOC extraction, folded into one risk score and an indicator
report. The file is stored and analyzed, never executed.*

---

## 5. It's a real product (30s)

1. **Overview** — the scans you just ran populate the history, stats, and risk
   distribution.
2. **Analytics** — detection rate, risk breakdown, top classifications.
3. **Alerts** — the two high-risk files raised alerts automatically.
4. Optional: `docs/MILESTONE_1.md` (deliverable checklist) and
   `cd backend && python -m pytest -q` → **39 passed**.

---

## Quick reference

| Sample | Verdict |
|---|---|
| `clean_notes.txt` | 0 · Likely Benign |
| `injector_strings.txt` | 20 · Suspicious (YARA: process injection) |
| `packed_blob.bin` | 35 · Suspicious (high entropy) |
| `invoice_2026.pdf.exe` | 54 · Suspicious (extension mismatch) |
| `upload.php` | 72 · Potential WebShell Malware |
| `invoice_macro.doc.txt` | 91 · Potential Dropper Malware |
| `README_TO_DECRYPT.txt` | 100 · Known Ransomware (signature) |
| `trojan_downloader.bin` | 100 · Known Trojan (signature + 11 YARA rules) |
