# Milestone 1 — Demo Walkthrough

Screen-recording script showing that authentication, RBAC, and the static
file-analysis workflow all work end to end.

**Total run time: ~4 minutes.**

---

## 0. Start the stack (before recording)

Two terminals, from the repo root:

```bash
python -m uvicorn app.main:app --app-dir backend --port 8000
```

```bash
npm --prefix frontend run dev
```

Open **http://localhost:5173**. No database or cloud account is needed — the
backend runs in local dev mode (dev login + local file storage).

If the sample files are missing: `python demo/generate_samples.py`.

---

## 1. Authentication (30s)

1. Show the login screen.
2. Sign in as **`analyst@local`** (any password).
3. Land on the Dashboard — point out the header shows the signed-in user and
   role (*Security Analyst*), and "Your access: **Scan**".

*Talking point: JWT-based auth. Locally it uses a dev login; in production the
same endpoint authenticates against Supabase Auth and reads the role from the
`profiles` table.*

---

## 2. Role-based access control (45s)

1. Sign out, sign back in as **`soc@local`**.
2. Show the Dashboard: access is now "**Read** — Monitoring & dashboards only".
3. Point at the sidebar — **Submit File / Analysis Report are gone**. A SOC
   Team Member can't run scans.
4. (Optional, in `/docs`) call `POST /api/v1/files/scan` with the SOC token →
   **403 Insufficient permissions**. With the analyst token → **200**.

*Talking point: RBAC is enforced server-side on every route via `require_roles()`,
and mirrored in the DB with row-level-security policies. The UI just reflects it.*

---

## 3. Static file analysis — a clean file (30s)

1. Back in as **`analyst@local`** → **Submit File**.
2. Upload `demo/samples/clean_notes.txt`.
3. Report shows **Risk 0/100 · LOW · Likely Benign**, no indicators.

---

## 4. Static file analysis — malware (90s)

1. **Submit File** → upload `demo/samples/suspicious_macro_dump.txt`.
2. Walk through the report:
   - **Risk 92/100 · HIGH · "Potential Downloader Malware"**, recommended
     action: *Escalate to Security Analyst*.
   - **Suspicious Indicators**: YARA matches, embedded URL, embedded public IP,
     suspicious command strings.
   - **File Metadata**: detected type, size, Shannon entropy.
   - **Hashes**: MD5 / SHA-1 / SHA-256.
   - **YARA Matches**: `Suspicious_PowerShell_Download_Cradle`,
     `Suspicious_Windows_Shell_Commands` with the matched strings.
   - **Network Indicators**: the extracted URL and IP.
3. Then upload `demo/samples/known_demo_trojan.bin` →
   **Risk 95/100 · "Known Trojan"** via a **signature match**
   (`ThreatLens.Demo.Trojan`).
4. (Optional) `invoice_2026.pdf.exe` → **MEDIUM**, indicator: *extension does
   not match detected content*.

*Talking point: this is the full static pipeline from the spec — hashing,
metadata, signature matching, YARA, IOC extraction — combined into one risk
score and a suspicious-indicators report. The file is stored and analysed; it
is never executed.*

---

## 5. Wrap (15s)

- Show `docs/MILESTONE_1.md` — deliverable checklist, all green.
- Show `python -m pytest -q` in `backend/` → **36 passed**.

---

## Quick reference — what each sample shows

| Sample | Result |
|---|---|
| `clean_notes.txt` | 0 · Likely Benign |
| `injector_strings.txt` | 22 · Suspicious (YARA: process-injection APIs) |
| `invoice_2026.pdf.exe` | 32 · Suspicious (extension mismatch) |
| `packed_blob.bin` | 35 · Suspicious (high entropy / packed) |
| `suspicious_macro_dump.txt` | 92 · Potential Downloader Malware |
| `known_demo_trojan.bin` | 95 · Known Trojan (signature) |
