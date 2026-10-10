"""Assemble a ready-to-push Hugging Face Space folder from this repository.

    python deploy/huggingface/prepare.py --out ../threatlens-space

`--out` can be an empty folder or a clone of your (empty) Space repository. The script copies only
what the image needs (backend app, frontend sources, demo samples, Dockerfile, Space README),
never overwrites an existing `.git`, and keeps the demo samples byte-for-byte identical (they are
matched by SHA-256). It prints a fresh JWT secret and demo password to paste into the Space's
"Variables and secrets"; it does not save them anywhere.
"""

from __future__ import annotations

import argparse
import secrets
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

FRONTEND_FILES = [
    'package.json', 'package-lock.json', 'index.html', 'tsconfig.json', 'tsconfig.app.json',
    'tsconfig.node.json', 'vite.config.ts', 'tailwind.config.js', 'postcss.config.js',
]
GITATTRIBUTES_LINES = [
    'backend/app/ml/models/artifacts/*.txt -text -diff',
    'demo/samples/* -text',
]
IGNORE = shutil.ignore_patterns('__pycache__', '*.pyc', '.pytest_cache', 'node_modules', 'dist')


def copy_tree(src: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, ignore=IGNORE)


def prepare(out: Path) -> list[str]:
    out.mkdir(parents=True, exist_ok=True)

    copy_tree(ROOT / 'backend' / 'app', out / 'backend' / 'app')
    shutil.copy2(ROOT / 'backend' / 'requirements.txt', out / 'backend' / 'requirements.txt')

    frontend = out / 'frontend'
    frontend.mkdir(exist_ok=True)
    for name in FRONTEND_FILES:
        shutil.copy2(ROOT / 'frontend' / name, frontend / name)
    copy_tree(ROOT / 'frontend' / 'src', frontend / 'src')
    if (ROOT / 'frontend' / 'public').is_dir():
        copy_tree(ROOT / 'frontend' / 'public', frontend / 'public')

    copy_tree(ROOT / 'demo' / 'samples', out / 'demo' / 'samples')

    shutil.copy2(HERE / 'Dockerfile', out / 'Dockerfile')
    shutil.copy2(HERE / 'README.md', out / 'README.md')

    # Append (never replace) so a Space's own LFS rules survive, and the samples are never
    # line-ending-converted when committed from Windows.
    attrs = out / '.gitattributes'
    existing = attrs.read_text(encoding='utf-8') if attrs.exists() else ''
    missing = [line for line in GITATTRIBUTES_LINES if line not in existing]
    if missing:
        sep = '' if existing.endswith('\n') or not existing else '\n'
        attrs.write_text(existing + sep + '\n'.join(missing) + '\n', encoding='utf-8')

    return sorted(str(p.relative_to(out)) for p in out.rglob('*') if p.is_file() and '.git' not in p.parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', required=True, help='target folder (empty, or a clone of your Space)')
    args = parser.parse_args()

    out = Path(args.out).resolve()
    if out == ROOT or ROOT in out.parents:
        print('Choose an --out folder outside the repository.')
        return 1
    files = prepare(out)
    print(f'Prepared {len(files)} files in {out}\n')
    print('Paste these into the Space: Settings -> Variables and secrets -> New secret')
    print(f'  JWT_SECRET_KEY     = {secrets.token_urlsafe(48)}')
    print(f'  DEV_LOGIN_PASSWORD = {secrets.token_urlsafe(12)}   (this is the demo sign-in password)')
    print('\nThen, in that folder:  git add -A && git commit -m "Deploy ThreatLens" && git push')
    return 0


if __name__ == '__main__':
    sys.exit(main())
