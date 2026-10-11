"""Deploy ThreatLens AI to a free Hugging Face Space with one command.

    set HF_TOKEN=hf_xxx            (PowerShell: $env:HF_TOKEN = "hf_xxx")
    python deploy/huggingface/deploy.py

Needs only a free Hugging Face account and an access token with **write** permission
(https://huggingface.co/settings/tokens). The token stays in your terminal; this script never
stores it. If you already ran `huggingface-cli login`, no HF_TOKEN is needed.

What it does:
  1. checks the token and finds your username
  2. creates the Space (Docker, public) if it doesn't exist
  3. on the first deploy, sets the two secrets the app needs (a fresh JWT secret and the demo
     password); on later deploys it leaves them alone unless you pass --reset-secrets
  4. uploads a clean copy of the project (no git needed, files go up byte-for-byte)
  5. waits for the build and checks the live site (UI, sign-in gate, ML model, seeded data)

    --dry-run     assemble the upload folder and show the plan; no network, no account needed
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from prepare import prepare  # noqa: E402

ACCOUNTS = ['analyst@local', 'soc@local', 'admin@local', 'researcher@local']
FAILED = {'BUILD_ERROR', 'RUNTIME_ERROR', 'CONFIG_ERROR', 'NO_APP_FILE', 'DELETING'}
MIN_PASSWORD = 12


class DeployError(RuntimeError):
    pass


def space_url(repo_id: str) -> str:
    """The direct (non-embedded) URL of a Space: lower-case, '_' and '.' become '-'."""
    owner, name = repo_id.split('/', 1)
    slug = f'{owner}-{name}'.lower().replace('_', '-').replace('.', '-')
    return f'https://{slug}.hf.space'


def new_secrets(password: str | None) -> tuple[str, str]:
    password = password or secrets.token_urlsafe(12)
    if len(password) < MIN_PASSWORD:
        raise DeployError(f'The demo password must be at least {MIN_PASSWORD} characters.')
    return secrets.token_urlsafe(48), password


def deploy(
    api: Any,
    name: str,
    *,
    private: bool = False,
    password: str | None = None,
    reset_secrets: bool = False,
    wait_minutes: float = 20,
    poll_seconds: float = 15,
    sleep=time.sleep,
    log=print,
) -> dict[str, Any]:
    """Run the whole deployment against ``api`` (a ``huggingface_hub.HfApi``). Returns a summary."""
    try:
        user = api.whoami()['name']
    except Exception as exc:  # noqa: BLE001
        raise DeployError(
            'Could not sign in to Hugging Face. Set HF_TOKEN to an access token with WRITE permission '
            '(https://huggingface.co/settings/tokens), or run `huggingface-cli login`.'
        ) from exc
    repo_id = f'{user}/{name}'
    log(f'Signed in as {user}. Space: {repo_id}')

    existed = api.repo_exists(repo_id, repo_type='space')
    api.create_repo(repo_id, repo_type='space', space_sdk='docker', private=private, exist_ok=True)
    log('Space exists.' if existed else 'Created the Space.')

    shown_password: str | None = None
    if not existed or reset_secrets:
        jwt_secret, shown_password = new_secrets(password)
        api.add_space_secret(repo_id, 'JWT_SECRET_KEY', jwt_secret)
        api.add_space_secret(repo_id, 'DEV_LOGIN_PASSWORD', shown_password)
        log('Set the JWT_SECRET_KEY and DEV_LOGIN_PASSWORD secrets.')
    else:
        log('Kept the existing secrets (use --reset-secrets to replace them).')

    with tempfile.TemporaryDirectory(prefix='threatlens-space-') as tmp:
        files = prepare(Path(tmp))
        log(f'Uploading {len(files)} files ...')
        api.upload_folder(
            repo_id=repo_id,
            repo_type='space',
            folder_path=tmp,
            commit_message='Deploy ThreatLens AI',
        )

    url = space_url(repo_id)
    deadline = time.monotonic() + wait_minutes * 60
    stage = last = None
    while time.monotonic() < deadline:
        stage = str(getattr(api.get_space_runtime(repo_id), 'stage', '')).split('.')[-1]
        if stage != last:
            log(f'  build/run stage: {stage}')
            last = stage
        if stage == 'RUNNING':
            break
        if stage in FAILED:
            raise DeployError(
                f'The Space reported {stage}. Open https://huggingface.co/spaces/{repo_id}?logs=build '
                'to read the log (the app also logs exactly which setting it refused).'
            )
        sleep(poll_seconds)
    else:
        raise DeployError(
            f'Still "{stage}" after {wait_minutes:g} minutes. The build may just be slow; '
            f'watch https://huggingface.co/spaces/{repo_id}'
        )

    return {'repo_id': repo_id, 'url': url, 'password': shown_password, 'existed': existed}


def verify_live(url: str, password: str | None, log=print) -> bool:
    """Best-effort check of the live site. Never raises."""
    try:
        import requests
    except ImportError:
        log('(install `requests` to run the live check)')
        return True
    ok = True
    try:
        for _ in range(20):  # the app may still be starting up
            if requests.get(f'{url}/health', timeout=15).ok:
                break
            time.sleep(5)
        cfg = requests.get(f'{url}/api/v1/auth/config', timeout=15).json()
        log(f'  site is up; sign-in mode: {cfg}')
        if password:
            r = requests.post(f'{url}/api/v1/auth/login', json={'email': 'admin@local', 'password': password}, timeout=15)
            ok &= r.ok
            log(f'  demo password accepted: {r.ok}')
            if r.ok:
                h = {'Authorization': 'Bearer ' + r.json()['access_token']}
                model = requests.get(f'{url}/api/v1/malware/model', headers=h, timeout=15).json()
                loaded = bool(model.get('detector'))
                ok &= loaded
                log(f'  ML model loaded: {loaded}')
                stats = requests.get(f'{url}/api/v1/threats/stats', headers=h, timeout=15).json()
                log(f'  dashboards seeded: {stats.get("total_detections")} detections, {stats.get("malicious")} malicious')
    except Exception as exc:  # noqa: BLE001
        log(f'  live check could not complete: {type(exc).__name__}: {exc}')
        return False
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--name', default='threatlens-ai', help='Space name (default: threatlens-ai)')
    parser.add_argument('--private', action='store_true', help='make the Space private (not shareable)')
    parser.add_argument('--password', help='demo sign-in password (12+ chars); default: generated')
    parser.add_argument('--reset-secrets', action='store_true', help='replace the secrets on an existing Space')
    parser.add_argument('--wait-minutes', type=float, default=20)
    parser.add_argument('--dry-run', action='store_true', help='assemble the upload folder only; no network')
    args = parser.parse_args()

    if args.dry_run:
        with tempfile.TemporaryDirectory(prefix='threatlens-space-') as tmp:
            files = prepare(Path(tmp))
            print(f'Dry run: would upload {len(files)} files to <your-username>/{args.name} as a public Docker Space.')
            print('  first deploy: sets JWT_SECRET_KEY and DEV_LOGIN_PASSWORD secrets; later deploys keep them.')
            print(f'  largest files: {", ".join(sorted(files, key=lambda f: -(Path(tmp) / f).stat().st_size)[:3])}')
        return 0

    try:
        from huggingface_hub import HfApi
    except ImportError:
        print('Install the Hugging Face client first:  pip install huggingface_hub')
        return 1

    try:
        summary = deploy(
            HfApi(token=os.environ.get('HF_TOKEN') or None),
            args.name,
            private=args.private,
            password=args.password,
            reset_secrets=args.reset_secrets,
            wait_minutes=args.wait_minutes,
        )
    except DeployError as exc:
        print(f'\nStopped: {exc}')
        return 1

    print('\nChecking the live site ...')
    healthy = verify_live(summary['url'], summary['password'])

    print('\n' + '=' * 70)
    print(f'Public link : {summary["url"]}')
    if summary['password']:
        print(f'Password    : {summary["password"]}   (shown once; save it)')
    else:
        print('Password    : unchanged (the one you set on the first deploy)')
    print(f'Accounts    : {", ".join(ACCOUNTS)}')
    print('=' * 70)
    print('Free Spaces sleep when idle (about a minute to wake) and data resets on restart;')
    print('open the link yourself shortly before a review.')
    return 0 if healthy else 2


if __name__ == '__main__':
    sys.exit(main())
