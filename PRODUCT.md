# PRODUCT.md — ThreatLens AI

## Register

**product** — an authenticated analyst console. Design serves the task; the
interface should recede and let the verdict and the evidence carry the screen.

## Product purpose

A malware-analysis platform. An analyst uploads a suspicious file; ThreatLens
runs a static-analysis pipeline (hashing, file-type/metadata, signature
matching, YARA, embedded-IOC extraction) and returns one risk verdict plus the
evidence behind it. Used for SOC triage, enterprise security, and malware
research.

## Users

- **Security Analyst** — uploads and triages files, reads reports, works a queue.
- **SOC Team Member** — watches threat and alert dashboards, no scan rights.
- **Administrator** — user/role management plus everything analysts do.
- **Researcher** — bulk sample analysis, family-level investigation.

Primary surface is the analyst's: submit a file, read the report, move on.

## Physical scene

A security analyst mid-shift, triaging a queue of uploaded files on a 24-inch
monitor in a dimmed operations room, scanning for HIGH-risk verdicts and reading
hash / IOC data over a long shift. → **Dark theme.** Severity color-coding must
be the loudest thing on screen; everything else stays quiet.

## Tone

Precise, calm, factual. It reports evidence, it does not editorialize or alarm.
"Escalate to a Security Analyst" not "DANGER!". Verdicts are stated plainly with
a score and the indicators that produced it.

## Anti-references

- Neon-on-black "hacker terminal" cosplay.
- Generic blue SaaS dashboard with a hero-metric row.
- Consumer antivirus scare-UI (big red shields, "Your PC is at risk").
- Milestone / roadmap / "coming soon" language anywhere in the product.

## Strategic principles

1. **Color means severity.** The UI is near-monochrome; green / amber / red are
   reserved for risk level and semantic state. One restrained indigo carries
   interactive affordance (focus, links, active nav) only.
2. **Evidence over decoration.** Every panel shows real analyzer output. No
   filler charts.
3. **The verdict is the headline.** Score, level, classification, recommended
   action, visible without scrolling.
4. **Technical data is monospaced and copyable.** Hashes, paths, IOCs, rule
   names.
5. **Empty states teach.** "No alerts in the last 24 hours", not "Milestone 2".
