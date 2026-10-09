"""Administrator-editable platform settings and security policies.

Only a small, validated allow-list of settings can be changed at runtime. Each
change is held as an override on top of the environment-driven ``settings`` and is
saved to a JSON file so it survives a restart of the same container/host.
Secrets, credentials and infrastructure URLs are deliberately not editable here.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)

# backend/app/core/runtime_settings.py -> parents[2] == backend/
_DEFAULT_PATH = Path(__file__).resolve().parents[2] / 'var' / 'platform_settings.json'

EDITABLE: dict[str, dict[str, Any]] = {
    'ALERT_MIN_LEVEL': {
        'label': 'Alert threshold',
        'group': 'Security policy',
        'description': 'Lowest fused verdict level that raises an alert.',
        'type': 'choice',
        'choices': ['low', 'medium', 'high'],
    },
    'RATE_LIMIT_PER_MINUTE': {
        'label': 'API rate limit',
        'group': 'Security policy',
        'description': 'Requests per minute allowed for one user (or IP when unauthenticated).',
        'type': 'int',
        'min': 10,
        'max': 10000,
    },
    'LOGIN_RATE_LIMIT_PER_MINUTE': {
        'label': 'Login attempt limit',
        'group': 'Security policy',
        'description': 'Sign-in attempts per minute allowed from one IP address.',
        'type': 'int',
        'min': 3,
        'max': 1000,
    },
    'JWT_ACCESS_TOKEN_EXPIRE_MINUTES': {
        'label': 'Session lifetime (minutes)',
        'group': 'Security policy',
        'description': 'How long a sign-in stays valid. Applies to new sign-ins.',
        'type': 'int',
        'min': 5,
        'max': 1440,
    },
    'MAX_UPLOAD_MB': {
        'label': 'Max upload size (MB)',
        'group': 'Platform',
        'description': 'Largest file accepted for analysis.',
        'type': 'int',
        'min': 1,
        'max': 256,
    },
}


def _coerce(name: str, value: Any) -> Any:
    spec = EDITABLE[name]
    if spec['type'] == 'choice':
        text = str(value).strip().lower()
        if text not in spec['choices']:
            raise ValueError(f"{name} must be one of: {', '.join(spec['choices'])}")
        return text
    if isinstance(value, bool):
        raise ValueError(f'{name} must be a whole number')
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f'{name} must be a whole number') from exc
    if not spec['min'] <= number <= spec['max']:
        raise ValueError(f"{name} must be between {spec['min']} and {spec['max']}")
    return number


class RuntimeSettings:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._overrides: dict[str, Any] = {}
        self._load()

    @property
    def _path(self) -> Path:
        return Path(os.environ.get('PLATFORM_SETTINGS_FILE') or _DEFAULT_PATH)

    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return
        for name, value in (raw or {}).items():
            if name in EDITABLE:
                try:
                    self._overrides[name] = _coerce(name, value)
                except ValueError:
                    logger.warning('Ignoring invalid saved setting %s', name)

    def _save(self) -> None:
        try:
            path = self._path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(self._overrides, indent=2), encoding='utf-8')
        except OSError:
            logger.warning('Could not persist platform settings; changes last until restart')

    def get(self, name: str) -> Any:
        with self._lock:
            if name in self._overrides:
                return self._overrides[name]
        return getattr(settings, name)

    def update(self, changes: dict[str, Any]) -> dict[str, Any]:
        """Validate and apply ``changes``; returns ``{name: new_value}`` for real changes."""
        unknown = [name for name in changes if name not in EDITABLE]
        if unknown:
            raise ValueError(f"Setting(s) cannot be changed: {', '.join(sorted(unknown))}")
        cleaned = {name: _coerce(name, value) for name, value in changes.items()}
        applied: dict[str, Any] = {}
        with self._lock:
            for name, value in cleaned.items():
                if self._effective(name) != value:
                    applied[name] = value
                if value == getattr(settings, name):
                    self._overrides.pop(name, None)
                else:
                    self._overrides[name] = value
            self._save()
        return applied

    def reset(self) -> None:
        with self._lock:
            self._overrides.clear()
            self._save()

    def _effective(self, name: str) -> Any:
        return self._overrides.get(name, getattr(settings, name))

    def describe(self) -> list[dict[str, Any]]:
        with self._lock:
            overrides = dict(self._overrides)
        fields = []
        for name, spec in EDITABLE.items():
            default = getattr(settings, name)
            field = {
                'key': name,
                'label': spec['label'],
                'group': spec['group'],
                'description': spec['description'],
                'type': spec['type'],
                'value': overrides.get(name, default),
                'default': default,
                'overridden': name in overrides,
            }
            if spec['type'] == 'choice':
                field['choices'] = spec['choices']
            else:
                field['min'] = spec['min']
                field['max'] = spec['max']
            fields.append(field)
        return fields


runtime_settings = RuntimeSettings()
