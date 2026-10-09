# ThreatLens AI: end-to-end demo (Milestones 1-4)

A screen-share walkthrough of the whole platform. **Run time: about 12 minutes**, or 5 if
you only do the sections marked *core*.

---

## 0. Before you share your screen

Two terminals from the repo root:

```bash
cd backend && python -m uvicorn app.main:app --port 8000
```

```bash
npm --prefix frontend run dev
```

Then seed every dashboard with one command (add `--skip-real` if you are offline):

```bash
python demo/m4_end_to_end_demo.py
```

It signs in as each role, scans the demo corpus plus a real malware sample, raises alerts,
opens and closes an incident, generates reports, records analyst feedback, exercises the
researcher and admin features, and finishes with a pass/fail line for every check. If it
says `30/30 checks passed`, everything below will work on screen.

Optional extra: `--rate-limit` also trips the login rate limiter, but it blocks further
sign-ins for about a minute, so run it last or skip it.

Open **http://localhost:5173**. No database or cloud account is needed: the backend runs in
local dev mode. Accounts (any password): `analyst@local`, `soc@local`, `admin@local`,
`researcher@local`. If samples are missing, run `python demo/generate_samples.py`.

> The two signature samples (`trojan_downloader.bin`, `README_TO_DECRYPT.txt`) are matched
> by SHA-256, so they must stay byte-identical. `.gitattributes` protects them from
> line-ending conversion, and `backend/tests/test_demo_assets.py` fails if they change.

---

## 1. Frame it (30s, *core*)

"ThreatLens AI takes a suspicious file and returns one explained verdict. Static rules and
a machine-learning model both run on every file and are fused into the verdict; behavior is
mapped to MITRE ATT&CK; alerts, reports, analytics and administration are built around it.
Files are analysed, never executed."

---

## 2. Authentication and role-based access (45s, *core*)

1. Sign in as **`analyst@local`**. Point at the user menu (email and role).
2. Sign out, sign in as **`soc@local`**. The sidebar has no **Submit File**: a SOC member
   cannot scan. Open `/research` by URL: **"Not available for your role"**.
3. Optional, in `http://localhost:8000/docs`: `POST /files/upload` with a SOC token is a
   **403**.

*Roles are enforced server-side on every route; the UI mirrors them. Matrix: `docs/RBAC.md`.*

---

## 3. Static analysis: "we caught the malware" (90s, *core*) [M1]

As **analyst**, **Submit File**:

1. `demo/samples/clean_notes.txt` → **0/100, benign**.
2. `demo/samples/trojan_downloader.bin` → **100/100, malicious**. Walk the report: verdict
   and recommended action; **Signature Match** `TrojanDownloader.Win32.Demo`; the **YARA**
   rules (download cradle, LOLBin transfer, AMSI bypass, persistence, C2 config) each with
   an ATT&CK id; **Network Indicators** (6 URLs, 3 IPs pulled from the bytes); hashes,
   entropy and file type.
3. Quick hits: `upload.php` (web shell), `invoice_macro.doc.txt` (macro dropper),
   `invoice_2026.pdf.exe` (extension mismatch).

---

## 4. The ML model adds what rules miss (60s, *core*) [M2]

Run `python demo/m2_live_ml_demo.py` (or look at the seeded `sample_a.exe`). A real malicious
PE has **0 static signals** yet the model scores it **98.5%**, so the fused verdict is
**MALICIOUS 82/100, engines: ML only**. A real benign PE stays **BENIGN**.

*Detector ROC-AUC 0.9997, false-positive rate 1.4% on held-out data. Static rules and ML are
both mandatory; the fusion explains which engine drove the verdict.*

---

## 5. Behavior analysis (45s) [M3]

Open **Behavior Analysis** (or the behavior panel on a report): the trojan maps to ~16
ATT&CK techniques across an attack chain **Execution → Persistence → Defense Evasion →
Credential Access → Command and Control → Impact**, each with evidence and confidence.
*Inferred from static signals only; nothing is run.*

---

## 6. SOC workflow (90s, *core*) [M2, M3]

As **soc**:

1. **Threat Monitor**: live feed, filters, timeline, ML-only catches. Expand a row.
2. **Alerts**: the malicious files raised alerts automatically. **Acknowledge** one, select
   three and **Create incident**, then move it through **contained → closed** in the
   Incidents panel.
3. The **bell** shows the notification feed (alert raised, acknowledged, incident opened).
4. **Reports → Threat summary** (operational report) and, on Threat Monitor, **download
   report** (filtered, with charts). Both appear in the Report Center history.

---

## 7. Learning from analysts (45s) [M4]

On **Threat Monitor**, expand a row and press **Mark benign (false positive)** or
**Confirm malicious**. *This ground truth measures real-world accuracy and feeds retraining;
the admin console shows it next.*

---

## 8. Researcher workspace (45s) [M4]

As **researcher**: **Research**. The datasets panel shows the training corpus (4,419
records, MIT-licensed DikeDataset), the platform's analysed samples and the
analyst-labelled set, with CSV export. The families table drills into a family: samples,
average score, ML categories, signatures.

---

## 9. Administrator console (2 min, *core*) [M4]

As **admin**: **Admin Console**.

1. **Platform monitor**: uptime, request volume, latency, rate-limited requests, data
   counts. The yellow banner flags dev defaults (default JWT secret, dev login); the API
   refuses to start with these in production.
2. **Users & roles**: change `researcher@local` to SOC Team Member. It applies at their next
   sign-in. You cannot change your own role or demote the last administrator.
3. **Settings & policies**: alert threshold, API and login rate limits, session lifetime,
   upload cap. Change one and save; restore defaults.
4. **Integrations**: VirusTotal, email, SIEM/SOAR webhook and Supabase status, with test
   buttons. *Alerts and incidents are forwarded to a SIEM as HMAC-signed JSON.*
5. **Activity log**: every sign-in, scan, report, role change and settings change, with
   who and when. Filter, then export CSV.
6. **ML models**: deployed versions and metrics, **live accuracy from analyst feedback**,
   drift status ("retraining recommended" after enough wrong verdicts), labelled-data
   export, and **Reload models** (hot swap, no restart).

---

## 10. It's a real product (30s) [all]

- **Analytics**: detection rate, risk and agreement breakdowns, top families, CSV export.
- **Profile**: edit your display name; the permission list matches the role.
- Terminal: `cd backend && python -m pytest -q` → all tests pass.
- `http://localhost:8000/docs` and `docs/postman/` for the API.
- Deployment: `docker compose up --build -d` serves the production images (nginx + API) on one port;
  `docker compose --profile public up -d` adds a free temporary public URL. See `docs/DEPLOYMENT.md`.

---

## Quick reference

| Sample | Static score | Verdict |
|---|---|---|
| `clean_notes.txt` | 0 | benign |
| `injector_strings.txt` | 20 | suspicious (process-injection YARA) |
| `packed_blob.bin` | 35 | suspicious (high entropy) |
| `invoice_2026.pdf.exe` | 54 | suspicious (extension mismatch) |
| `upload.php` | 72 | malicious (web shell) |
| `README_TO_DECRYPT.txt` | 100 | malicious (ransomware signature) |
| `invoice_macro.doc.txt` | 91 | malicious (macro dropper) |
| `trojan_downloader.bin` | 100 | malicious (signature + 11 YARA rules) |
| `sample_a.exe` (real PE) | 0 static, 98.5% ML | malicious, ML only |

## If something looks off

- Dashboards empty: run `python demo/m4_end_to_end_demo.py` again (data is in memory and is
  cleared when the API restarts).
- `429 Too Many Requests` on sign-in: the login limiter is working; wait a minute.
- Signature samples score 72 instead of 100: a Windows checkout converted their line
  endings. `git checkout -- demo/samples` after `.gitattributes` is in place restores them.
