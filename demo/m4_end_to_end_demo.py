"""ThreatLens AI end-to-end demo driver (Milestones 1-4).

Drives a running API through every workflow in the spec and narrates what it does, so
you can run it before (or while) screen-sharing: it seeds realistic data for every
dashboard and proves each feature against the live server.

    python demo/m4_end_to_end_demo.py                 # full run
    python demo/m4_end_to_end_demo.py --skip-real     # no internet: skip the real PE samples
    python demo/m4_end_to_end_demo.py --pause         # wait for Enter between sections
    python demo/m4_end_to_end_demo.py --rate-limit    # also trip the login rate limiter (last step)
    python demo/m4_end_to_end_demo.py --api http://localhost:8000/api/v1

Needs the backend running with the local dev login (no Supabase) and `requests`.
Real malware is streamed into memory from DikeDataset (MIT) and posted straight to the
API; it is never written to disk. Reports are only checked, not saved.
"""

from __future__ import annotations

import argparse
import io
import sys
import time
from pathlib import Path

import requests

SAMPLES = Path(__file__).parent / 'samples'
RAW = 'https://raw.githubusercontent.com/iosifache/DikeDataset/main/files'
MALWARE_HASH = '936c36121f73b175ef68231ee234c55103c93d7dfeb75dd8fdc3480aa5c08aeb'
BENIGN_HASH = 'ca6710ac624c4badd89606d2d46270b68a494b9778a109477955f6403d77493e'

ROLES = {
    'analyst': 'analyst@local',
    'soc': 'soc@local',
    'admin': 'admin@local',
    'researcher': 'researcher@local',
}

# (file, what it demonstrates)
STATIC_SAMPLES = [
    ('clean_notes.txt', 'clean baseline'),
    ('trojan_downloader.bin', 'signature + 11 YARA rules'),
    ('README_TO_DECRYPT.txt', 'ransomware note'),
    ('upload.php', 'web shell'),
    ('invoice_macro.doc.txt', 'macro dropper'),
    ('invoice_2026.pdf.exe', 'extension mismatch'),
    ('packed_blob.bin', 'high-entropy / packed'),
]


class Demo:
    def __init__(self, api: str, pause: bool) -> None:
        self.api = api.rstrip('/')
        self.pause = pause
        self.tokens: dict[str, str] = {}
        self.checks = 0
        self.failures: list[str] = []
        self.scans: dict[str, dict] = {}

    # --- plumbing ----------------------------------------------------------
    def section(self, title: str) -> None:
        if self.pause:
            input('\n[Enter] to continue... ')
        print(f'\n{"=" * 74}\n{title}\n{"=" * 74}')

    def say(self, text: str) -> None:
        print(f'  {text}')

    def check(self, ok: bool, text: str) -> bool:
        self.checks += 1
        print(f'  [{"ok" if ok else "FAIL"}] {text}')
        if not ok:
            self.failures.append(text)
        return ok

    def token(self, who: str) -> str:
        if who not in self.tokens:
            r = requests.post(
                f'{self.api}/auth/login', json={'email': ROLES[who], 'password': 'demo'}, timeout=15
            )
            r.raise_for_status()
            self.tokens[who] = r.json()['access_token']
        return self.tokens[who]

    def call(self, method: str, path: str, who: str | None = None, **kw) -> requests.Response:
        headers = kw.pop('headers', {})
        if who:
            headers['Authorization'] = f'Bearer {self.token(who)}'
        return requests.request(method, f'{self.api}{path}', headers=headers, timeout=120, **kw)

    def get(self, path: str, who: str, **kw):
        r = self.call('GET', path, who, **kw)
        r.raise_for_status()
        return r.json()

    def upload(self, who: str, name: str, data: bytes) -> dict:
        r = self.call(
            'POST', '/files/upload', who,
            files={'file': (name, io.BytesIO(data), 'application/octet-stream')},
        )
        r.raise_for_status()
        return r.json()

    # --- sections ----------------------------------------------------------
    def health_and_auth(self) -> None:
        self.section('1. Authentication & role-based access control (M1)')
        r = requests.get(self.api.rsplit('/api/', 1)[0] + '/health', timeout=10)
        self.check(r.ok and r.json().get('status') == 'ok', 'API is healthy')
        for who in ROLES:
            me = self.get('/users/me', who)
            self.say(f'{who:<11} signed in as {me["email"]:<18} role: {me["role"]}')
        soc_upload = self.call('POST', '/files/upload', 'soc', files={'file': ('x.txt', b'x')})
        self.check(soc_upload.status_code == 403, 'SOC member cannot upload files (403)')
        res_admin = self.call('GET', '/admin/overview', 'researcher')
        self.check(res_admin.status_code == 403, 'Researcher cannot open the admin console (403)')
        anon = self.call('GET', '/threats/stats')
        self.check(anon.status_code == 401, 'Anonymous requests are rejected (401)')

    def static_analysis(self) -> None:
        self.section('2. Static analysis & fused verdicts (M1 + M2)')
        self.say(f'{"file":<26}{"static":>8}{"ML":>8}   {"verdict":<11}{"score":>6}  {"engines":<11} note')
        for name, note in STATIC_SAMPLES:
            path = SAMPLES / name
            if not path.exists():
                self.say(f'{name}: missing (run python demo/generate_samples.py)')
                continue
            res = self.upload('analyst', name, path.read_bytes())
            self.scans[name] = res
            v, ml = res['verdict'], res['ml']
            ml_txt = f'{ml["malware_probability"]:.0%}' if ml and ml.get('applicable') else 'n/a'
            self.say(
                f'{name:<26}{res["risk"]["score"]:>8}{ml_txt:>8}   {v["label"]:<11}{v["score"]:>6}  '
                f'{v["agreement"]:<11} {note}'
            )
        trojan = self.scans.get('trojan_downloader.bin')
        if trojan:
            self.check(trojan['verdict']['label'] == 'malicious', 'known trojan -> MALICIOUS')
            self.check(trojan['signature_match']['matched'], 'hash signature matched')
            self.check(len(trojan['yara_matches']) >= 5, f'{len(trojan["yara_matches"])} YARA rules matched')
            net = trojan['network_indicators']
            self.say(f'indicators pulled from the bytes: {len(net["urls"])} URLs, {len(net["ips"])} IPs')
        clean = self.scans.get('clean_notes.txt')
        if clean:
            self.check(clean['verdict']['label'] == 'benign', 'clean file -> BENIGN')

    def real_samples(self, skip: bool) -> None:
        self.section('3. Real malware through the ML model (M2)')
        if skip:
            self.say('skipped (--skip-real)')
            return
        try:
            mal = requests.get(f'{RAW}/malware/{MALWARE_HASH}.exe', timeout=30)
            ben = requests.get(f'{RAW}/benign/{BENIGN_HASH}.exe', timeout=30)
            mal.raise_for_status()
            ben.raise_for_status()
        except requests.RequestException as exc:
            self.say(f'could not fetch DikeDataset samples ({type(exc).__name__}); continuing')
            return
        for label, data, name in (('malicious PE', mal.content, 'sample_a.exe'), ('benign PE', ben.content, 'sample_b.exe')):
            res = self.upload('analyst', name, data)
            self.scans[name] = res
            v, ml = res['verdict'], res['ml']
            self.say(
                f'{label}: static {res["risk"]["score"]}/100, ML {ml["malware_probability"]:.1%}, '
                f'fused {v["label"].upper()} {v["score"]}/100 [{v["agreement"]}] {v["classification"]}'
            )
        a = self.scans.get('sample_a.exe')
        if a:
            self.check(a['verdict']['label'] == 'malicious', 'real malware caught (the ML model adds what rules miss)')
        b = self.scans.get('sample_b.exe')
        if b:
            self.check(b['verdict']['label'] == 'benign', 'real benign PE stays clean')

    def behavior_and_intel(self) -> None:
        self.section('4. Behavioral analysis & threat intelligence (M3)')
        res = self.scans.get('trojan_downloader.bin')
        if not res:
            return
        beh = res.get('behavioral_analysis') or {}
        self.say(
            f'{beh.get("behaviors_detected", 0)} MITRE ATT&CK behaviours inferred, '
            f'kill-chain stage: {beh.get("kill_chain_stage")}'
        )
        self.say('attack chain: ' + ' -> '.join(beh.get('attack_chain', [])))
        for b in [b for b in beh.get('behaviors', []) if b['observed']][:5]:
            self.say(f'  {b["technique_id"]:<10} {b["technique"]:<42} {b["severity"]:<8} conf {b["confidence"]:.0%}')
        self.check(beh.get('behaviors_detected', 0) >= 3, 'behavioral analysis found ATT&CK techniques (static only, nothing executed)')
        intel = res.get('threat_intel') or {}
        self.say('VirusTotal: ' + ('hash looked up' if intel.get('available') else intel.get('reason', 'unavailable')))

    def soc_workflow(self) -> None:
        self.section('5. SOC workflow: monitoring, alerts, notifications, incidents (M2 + M3)')
        stats = self.get('/threats/stats', 'soc')
        self.say(
            f'threat monitor: {stats["total_detections"]} detections, {stats["malicious"]} malicious, '
            f'{stats["suspicious"]} suspicious, ML-only catches {stats["ml_only_catches"]}'
        )
        alerts = self.get('/alerts/?status=open', 'soc')
        self.check(len(alerts) >= 1, f'{len(alerts)} open alerts raised automatically')
        unread = self.get('/notifications/unread-count', 'soc')['unread']
        self.check(unread >= 1, f'{unread} unread in-app notifications (the bell)')
        if alerts:
            ids = [a['id'] for a in alerts[:3]]
            ack = self.call('POST', f'/alerts/{ids[0]}/acknowledge', 'soc')
            self.check(ack.ok, 'SOC acknowledged the top alert')
            inc = self.call('POST', '/alerts/incidents', 'soc', json={'alert_ids': ids, 'title': 'Demo campaign'})
            self.check(inc.status_code == 201, f'incident opened grouping {len(ids)} alert(s)')
            if inc.ok:
                iid = inc.json()['id']
                for state in ('contained', 'closed'):
                    r = self.call('PATCH', f'/alerts/incidents/{iid}', 'soc', json={'status': state})
                    self.check(r.ok and r.json()['status'] == state, f'incident moved to {state}')

    def reports(self) -> None:
        self.section('6. Reporting workflows (M2 + M3)')
        scan = self.scans.get('trojan_downloader.bin')
        if scan:
            r = self.call('POST', '/reports/pdf', 'analyst', json=scan)
            self.check(r.ok and r.content[:4] == b'%PDF', f'investigation report PDF ({len(r.content) // 1024} KB)')
        r = self.call('POST', '/reports/summary', 'soc', params={'window': '7d'})
        self.check(r.ok and r.content[:4] == b'%PDF', f'operational summary PDF for SOC ({len(r.content) // 1024} KB)')
        r = self.call('GET', '/threats/report', 'soc', params={'window': '24h', 'threats_only': 'true'})
        self.check(r.ok and r.content[:4] == b'%PDF', f'filtered threat-monitoring report ({len(r.content) // 1024} KB)')
        history = self.get('/reports/history?limit=5', 'soc')
        self.say('report history: ' + '; '.join(f'{h["report_type"]}' for h in history))
        self.check(len(history) >= 3, 'every generated report is logged')

    def feedback(self) -> None:
        self.section('7. Analyst feedback & model health (M4: continuous learning)')
        scan = self.scans.get('invoice_2026.pdf.exe') or self.scans.get('packed_blob.bin')
        if scan:
            r = self.call('POST', '/feedback', 'analyst', json={'sha256': scan['sha256'], 'label': 'benign', 'note': 'internal build artifact'})
            self.check(r.status_code == 201, f'analyst marked a verdict as a false positive (model said {r.json().get("model_verdict")})')
        mal = self.scans.get('trojan_downloader.bin')
        if mal:
            r = self.call('POST', '/feedback', 'soc', json={'sha256': mal['sha256'], 'label': 'malicious'})
            self.check(r.status_code == 201, 'SOC confirmed a true positive')
        s = self.get('/feedback/summary', 'researcher')
        self.say(f'{s["total"]} reviewed samples, fused precision {s["fused_verdict"]["precision"]}, recall {s["fused_verdict"]["recall"]}')
        self.say(s['retrain_reason'])

    def research(self) -> None:
        self.section('8. Researcher workspace: datasets & families (M4)')
        for d in self.get('/research/datasets', 'researcher'):
            self.say(f'dataset  {d["name"]:<42} {d["records"]:>6} records  {"exportable" if d["exportable"] else "reference"}')
        families = self.get('/research/families', 'researcher')
        for f in families[:5]:
            self.say(f'family   {f["family"]:<24} {f["samples"]:>3} samples  avg score {f["avg_score"]}')
        self.check(len(families) >= 1, f'{len(families)} malware families profiled')
        r = self.call('GET', '/research/datasets/analysed-corpus/export.csv', 'researcher')
        rows = max(len(r.text.splitlines()) - 1, 0)
        self.check(r.ok and rows >= 1, f'dataset export: {rows} rows of CSV')

    def admin(self) -> None:
        self.section('9. Administrator console (M4)')
        o = self.get('/admin/overview', 'admin')
        self.say(
            f'platform: v{o["version"]}, {o["persistence"]} data, {o["auth_mode"]} auth, '
            f'{o["requests"]["total_requests"]} requests, avg {o["requests"]["avg_latency_ms"]} ms'
        )
        for w in o['warnings']:
            self.say(f'warning: {w}')
        users = self.get('/admin/users', 'admin')
        self.check(len(users) >= 4, f'{len(users)} users visible to the administrator')

        r = self.call('PATCH', '/admin/users/researcher@local/role', 'admin', json={'role': 'SOC Team Member'})
        self.check(r.ok, 'admin changed researcher@local -> SOC Team Member')
        self.tokens.pop('researcher', None)
        self.check(self.get('/users/me', 'researcher')['role'] == 'SOC Team Member', 'new role applies at next sign-in')
        self.call('PATCH', '/admin/users/researcher@local/role', 'admin', json={'role': 'Researcher'})
        self.tokens.pop('researcher', None)

        r = self.call('PUT', '/admin/settings', 'admin', json={'values': {'ALERT_MIN_LEVEL': 'medium'}})
        self.check(r.ok, 'security policy changed: alert threshold -> medium')
        self.call('POST', '/admin/settings/reset', 'admin')
        self.say('(policy restored to the default)')

        for i in self.get('/admin/integrations', 'admin'):
            state = 'configured' if i['configured'] else 'not configured'
            self.say(f'integration  {i["name"]:<34} {state}')
        audit = self.get('/admin/audit?limit=8', 'admin')
        self.say('latest activity:')
        for e in audit[:6]:
            self.say(f'  {e["at"][11:19]}  {(e["actor"] or "-"):<18} {e["action"]:<20} {(e["detail"] or e["target"] or "")[:40]}')
        self.check(any(e['action'] == 'user.role_change' for e in self.get('/admin/audit?limit=200', 'admin')), 'role change recorded in the audit log')
        models = self.get('/admin/models', 'admin')
        self.say(f'models: detector {models["registry"]["detector"]["version"]}, classifier {models["registry"]["classifier"]["version"]}')

    def rate_limit(self) -> None:
        self.section('10. API gateway rate limiting (M4)')
        codes = []
        for _ in range(30):
            r = requests.post(f'{self.api}/auth/login', json={'email': 'analyst@local', 'password': 'x'}, timeout=10)
            codes.append(r.status_code)
            if r.status_code == 429:
                self.say(f'attempt {len(codes)}: 429 Too Many Requests, retry after {r.headers.get("Retry-After")}s')
                break
        self.check(429 in codes, 'repeated sign-in attempts are throttled')
        self.say('(the login budget refills within a minute)')

    def finish(self) -> int:
        print(f'\n{"=" * 74}')
        print(f'{self.checks - len(self.failures)}/{self.checks} checks passed')
        for f in self.failures:
            print(f'  FAILED: {f}')
        print('Now switch to the browser: Overview, Threat Monitor, Alerts, Reports, Behavior,')
        print('Analytics, Research and the Admin Console all reflect what was just done.')
        return 1 if self.failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--api', default='http://127.0.0.1:8000/api/v1')
    parser.add_argument('--skip-real', action='store_true', help='skip the real PE samples (needs internet)')
    parser.add_argument('--pause', action='store_true', help='wait for Enter between sections')
    parser.add_argument('--rate-limit', action='store_true', help='also demonstrate the login rate limit (run last)')
    args = parser.parse_args()

    demo = Demo(args.api, args.pause)
    try:
        demo.health_and_auth()
        demo.static_analysis()
        demo.real_samples(args.skip_real)
        demo.behavior_and_intel()
        demo.soc_workflow()
        demo.reports()
        demo.feedback()
        demo.research()
        demo.admin()
        if args.rate_limit:
            demo.rate_limit()
    except requests.ConnectionError:
        print(f'\nCould not reach the API at {args.api}. Start it with:\n'
              '  python -m uvicorn app.main:app --app-dir backend --port 8000')
        return 2
    except requests.HTTPError as exc:
        print(f'\nRequest failed: {exc} -> {exc.response.text[:300]}')
        return 1
    return demo.finish()


if __name__ == '__main__':
    sys.exit(main())
