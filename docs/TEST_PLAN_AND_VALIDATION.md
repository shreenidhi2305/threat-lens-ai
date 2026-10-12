# Milestone 4 — Testing & Workflow Validation (Weeks 7–8)

**Role implemented:** Perform application testing and workflow validation.
**Owner artifact:** `backend/tests/test_workflow_validation.py` (36 tests) + this report.

## 1. Scope

Validated the complete ThreatLens AI user journeys end-to-end through the
HTTP API (`TestClient`, local dev login, no external services required):

| ID | Workflow | What is checked |
|----|----------|-----------------|
| WF1 | Health, auth & RBAC | `/health`, dev login for all 4 roles, 401 anonymous, 403 SOC-on-upload, `/users/me` |
| WF2 | Upload → full pipeline | benign → `benign/low`, dropper → `malicious/high`, EICAR detected, empty → 400, `/analysis/scan` re-run, latency < 30 s |
| WF3 | Result integrity | verdict level/label agreement, score 0–100, hashes, `size_bytes`, URLs, MITRE `behavioral_analysis` block, rules-only fusion |
| WF4 | Threat monitoring | detections +1 per scan, snapshot == stats, timeline buckets 24/7/30, filters + 422 on bad values, monitoring PDF |
| WF5 | Alerts + notifications | malicious raises alert / benign does not, SHA dedupe, ack → resolve, incident creation, stats, notification read |
| WF6 | Reports & analytics | investigation PDF + history, summary PDF + window validation, report retrieval by ID (`file_hash`) + PDF re-render, analytics summary/timeline, behavior catalog/analyze |
| WF7 | Resilience & edge cases | VirusTotal down, behavior-engine crash, ML crash → scan still 201; unconfigured intel reports `available:false`; 32 MiB cap wired |

## 2. How to run

```bash
cd backend
pip install -r requirements.txt        # must include yara-python + lightgbm
python -m pytest -q                   # full suite (existing + workflow validation)
python -m pytest tests/test_workflow_validation.py -q   # this role only

cd ../frontend
npm install
npx tsc -b          # typecheck
npx vite build      # production build
```

## 3. Results (2026-10-08, Windows, Python 3.10, Node 20+)

- **Backend:** **148 passed, 0 failed**
  (112 pre-existing + 36 new workflow-validation tests).
- **Frontend:** `tsc -b` clean, `vite build` succeeds
  (`dist/assets/index-*.js` 375 kB / 113 kB gzip).

## 4. Key finding during validation (fixed by environment, documented by tests)

A baseline run with a minimal install (no `yara-python`, no `lightgbm`)
produced **102 passed / 10 failed**. Root cause: without YARA the static
engine gracefully degrades (dropper scores ~42 `medium` instead of 72+
`high`), so high-severity-gated assertions (fusion level, alert generation,
notification fan-out, webshell floor) fail. Installing the full
`requirements.txt` (`yara-python`, `lightgbm`) returns the suite to green.
The new `test_workflow_validation.py` documents this: alert-dedupe tests use
unique bytes per scan (SHA-keyed dedupe), and schema assertions use the real
field names (`size_bytes`, `file_hash`, `total_samples`, `behaviors`,
`threat_intel.available/reason`).

## 5. Manual validation checklist (for the live demo)

1. `docker compose up --build` → frontend :5173, backend :8000 both healthy.
2. Login as `analyst@local` → upload dropper sample → verdict `malicious/high`
   with MITRE tactics + kill chain visible.
3. Threat Monitor shows the new detection; filters (level/verdict/search) work.
4. Alerts shows 1 new open alert; acknowledge → resolve; group into incident.
5. Reports: download investigation PDF, summary PDF; re-download by report ID.
6. Analytics dashboard totals increment; timeline renders.
7. Upload empty file → clean 400 error; SOC login → upload correctly forbidden.

## 6. Files changed for this role

- Added: `backend/tests/test_workflow_validation.py`
- Added: `docs/TEST_PLAN_AND_VALIDATION.md` (this file)
- No production code changed (validation only; failures traced to environment,
  not app logic).
