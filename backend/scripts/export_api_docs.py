"""Export the API contract: docs/openapi.json and a ready-to-import Postman collection.

    cd backend && PYTHONPATH=. python scripts/export_api_docs.py

The collection has a ``baseUrl`` variable (the server root) and a ``token`` variable; the "Sign in"
request stores the returned token automatically, and every other request sends it as a
bearer token. Change the email in "Sign in" to try each role
(analyst@ / soc@ / admin@ / researcher@local).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault('RATE_LIMIT_ENABLED', 'false')

from app.main import app  # noqa: E402

DOCS = Path(__file__).resolve().parents[2] / 'docs'
SAMPLE = {'string': 'string', 'integer': 1, 'number': 1.0, 'boolean': True}

TAG_ORDER = [
    'auth', 'users', 'files', 'behavior', 'malware', 'threats', 'alerts', 'notifications',
    'reports', 'analytics', 'feedback', 'research', 'admin',
]


def _resolve(schema: dict, spec: dict, depth: int = 0) -> object:
    """Build a small example value for a JSON schema."""
    if depth > 4:
        return None
    if '$ref' in schema:
        name = schema['$ref'].split('/')[-1]
        return _resolve(spec['components']['schemas'][name], spec, depth + 1)
    for key in ('anyOf', 'oneOf'):
        if key in schema:
            options = [o for o in schema[key] if o.get('type') != 'null']
            return _resolve(options[0], spec, depth + 1) if options else None
    if 'example' in schema:
        return schema['example']
    if 'default' in schema and schema['default'] is not None:
        return schema['default']
    if 'enum' in schema:
        return schema['enum'][0]
    kind = schema.get('type')
    if kind == 'object' or 'properties' in schema:
        return {
            name: _resolve(sub, spec, depth + 1)
            for name, sub in schema.get('properties', {}).items()
        }
    if kind == 'array':
        return [_resolve(schema.get('items', {}), spec, depth + 1)]
    return SAMPLE.get(kind, None)


def _item(path: str, method: str, op: dict, spec: dict) -> dict:
    query, variables = [], []
    for p in op.get('parameters', []):
        value = p.get('schema', {}).get('default', '')
        if p['in'] == 'query':
            query.append({'key': p['name'], 'value': str(value), 'disabled': not p.get('required')})
        elif p['in'] == 'path':
            variables.append({'key': p['name'], 'value': f"<{p['name']}>"})

    url_path = [seg for seg in path.strip('/').split('/') if seg]
    url_path = [f':{seg[1:-1]}' if seg.startswith('{') else seg for seg in url_path]
    request: dict = {
        'method': method.upper(),
        'header': [],
        'url': {
            'raw': '{{baseUrl}}/' + '/'.join(url_path),
            'host': ['{{baseUrl}}'],
            'path': url_path,
            'query': query,
            'variable': variables,
        },
        'description': op.get('summary') or (op.get('description') or '').split('\n')[0],
    }

    body = op.get('requestBody', {}).get('content', {})
    if 'application/json' in body:
        example = _resolve(body['application/json']['schema'], spec)
        request['header'].append({'key': 'Content-Type', 'value': 'application/json'})
        request['body'] = {
            'mode': 'raw',
            'raw': json.dumps(example, indent=2),
            'options': {'raw': {'language': 'json'}},
        }
    elif 'multipart/form-data' in body:
        request['body'] = {'mode': 'formdata', 'formdata': [{'key': 'file', 'type': 'file', 'src': []}]}

    if path.endswith('/auth/login'):
        request['auth'] = {'type': 'noauth'}
        request['body']['raw'] = json.dumps({'email': 'analyst@local', 'password': 'demo'}, indent=2)
    return {'name': f'{method.upper()} {path}', 'request': request}


def build_collection(spec: dict) -> dict:
    groups: dict[str, list[dict]] = {}
    for path, methods in spec['paths'].items():
        for method, op in methods.items():
            if method not in ('get', 'post', 'put', 'patch', 'delete'):
                continue
            tag = (op.get('tags') or ['other'])[0]
            item = _item(path, method, op, spec)
            if path.endswith('/auth/login'):
                item['event'] = [{
                    'listen': 'test',
                    'script': {'type': 'text/javascript', 'exec': [
                        "pm.collectionVariables.set('token', pm.response.json().access_token);",
                    ]},
                }]
                item['name'] = 'Sign in (stores the token)'
            groups.setdefault(tag, []).append(item)

    ordered = sorted(groups, key=lambda t: TAG_ORDER.index(t) if t in TAG_ORDER else 99)
    return {
        'info': {
            'name': 'ThreatLens AI API',
            'description': spec['info'].get('description') or 'ThreatLens AI REST API',
            'schema': 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
        },
        'auth': {'type': 'bearer', 'bearer': [{'key': 'token', 'value': '{{token}}', 'type': 'string'}]},
        'variable': [
            {'key': 'baseUrl', 'value': 'http://localhost:8000'},
            {'key': 'token', 'value': ''},
        ],
        'item': [{'name': tag, 'item': groups[tag]} for tag in ordered],
    }


def main() -> int:
    spec = app.openapi()
    DOCS.mkdir(exist_ok=True)
    (DOCS / 'openapi.json').write_text(json.dumps(spec, indent=2), encoding='utf-8')

    collection = build_collection(spec)
    postman = DOCS / 'postman'
    postman.mkdir(exist_ok=True)
    (postman / 'ThreatLens.postman_collection.json').write_text(
        json.dumps(collection, indent=2), encoding='utf-8'
    )
    endpoints = sum(len(g['item']) for g in collection['item'])
    print(f'{endpoints} endpoints in {len(collection["item"])} folders -> {DOCS}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
