# Third-party notices

ThreatLens AI's own code is released under the [MIT License](LICENSE). It is built on the open-source
components below, each under its own license (all permissive, and compatible with MIT). This list
covers the principal direct dependencies; their transitive dependencies are listed in
`frontend/package-lock.json` and carry their own licenses. Consult each project for its full terms.

## Backend (Python)

| Component | License |
|---|---|
| FastAPI, Pydantic, pydantic-settings | MIT |
| SQLAlchemy, python-jose | MIT |
| Supabase Python client | MIT |
| LightGBM | MIT |
| pefile | MIT |
| Uvicorn, passlib | BSD-3-Clause |
| NumPy, pandas, scikit-learn | BSD-3-Clause |
| ReportLab | BSD-3-Clause (ReportLab Open Source License) |
| python-multipart, requests | Apache-2.0 |
| yara-python (YARA) | Apache-2.0 (YARA engine: BSD-3-Clause) |

## Frontend (JavaScript / TypeScript)

| Component | License |
|---|---|
| React, React DOM, React Router | MIT |
| Axios | MIT |
| Vite, @vitejs/plugin-react | MIT |
| Tailwind CSS, PostCSS, Autoprefixer | MIT |
| oxlint | MIT |
| TypeScript | Apache-2.0 |

The UI loads the **Inter** and **JetBrains Mono** typefaces from Google Fonts at runtime
(SIL Open Font License 1.1). They are not bundled in this repository.

## Containers and deployment

| Component | License |
|---|---|
| nginx (`nginx` base image) | BSD-2-Clause |
| Python and Node.js base images | PSF-2.0 and MIT respectively |
| cloudflared (optional public tunnel) | Apache-2.0 |

## Data, models and external services

- **DikeDataset** (<https://github.com/iosifache/DikeDataset>), MIT-licensed. The bundled detection and
  classification models were trained on it. The raw malware is never stored in this repository.
- **MITRE ATT&CK®** is a registered trademark of The MITRE Corporation. Technique names and identifiers used
  in the behavioral analysis are referenced under MITRE's ATT&CK terms of use
  (<https://attack.mitre.org/resources/terms-of-use/>).
- **VirusTotal** hash lookups (optional, enabled with `VIRUSTOTAL_API_KEY`) are subject to VirusTotal's
  terms of service. Only file hashes are sent, never file contents.
- The YARA rules in `backend/app/modules/file_analysis/rules/` and the demo samples in `demo/samples/` were
  written for this project. The samples are synthetic test files, not live malware.

## Safe use

ThreatLens AI is a defensive analysis tool. It performs static analysis only and never executes the files it
receives. The software is provided "as is", without warranty (see `LICENSE`); do not rely on it as your
only line of defense.
