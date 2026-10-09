"""SIEM / SOAR integration: forward alerts and incidents as signed JSON webhooks.

Configure ``SIEM_WEBHOOK_URL`` (a SIEM HTTP collector or a SOAR playbook trigger).
Each event is a small JSON document; when ``SIEM_WEBHOOK_SECRET`` is set it is
signed with HMAC-SHA256 in ``X-ThreatLens-Signature`` so the receiver can verify it,
and ``SIEM_WEBHOOK_TOKEN`` is sent as a bearer token. Delivery is best-effort and
runs on a background thread, so a slow or failing receiver never delays or breaks
alerting.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any

import requests

from app.core.config import settings

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 5


class SiemForwarder:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stats: dict[str, Any] = {
            'sent': 0,
            'failed': 0,
            'last_status': None,
            'last_error': None,
            'last_event_at': None,
        }

    @staticmethod
    def build_event(event_type: str, severity: str | None, data: dict[str, Any]) -> dict[str, Any]:
        return {
            'source': 'threatlens-ai',
            'version': settings.API_VERSION,
            'event_type': event_type,
            'severity': severity,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': data,
        }

    @staticmethod
    def sign(body: bytes) -> str | None:
        if not settings.SIEM_WEBHOOK_SECRET:
            return None
        digest = hmac.new(settings.SIEM_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
        return f'sha256={digest}'

    def _deliver(self, event: dict[str, Any]) -> tuple[bool, str | None]:
        body = json.dumps(event, default=str).encode()
        headers = {'Content-Type': 'application/json', 'User-Agent': 'ThreatLens-AI'}
        if settings.SIEM_WEBHOOK_TOKEN:
            headers['Authorization'] = f'Bearer {settings.SIEM_WEBHOOK_TOKEN}'
        signature = self.sign(body)
        if signature:
            headers['X-ThreatLens-Signature'] = signature
        try:
            response = requests.post(
                settings.SIEM_WEBHOOK_URL, data=body, headers=headers, timeout=_TIMEOUT_SECONDS
            )
            ok = 200 <= response.status_code < 300
            error = None if ok else f'HTTP {response.status_code}'
            status = response.status_code
        except Exception as exc:  # noqa: BLE001 - never raise into alerting
            ok, error, status = False, f'{type(exc).__name__}: {exc}'[:200], None
        with self._lock:
            self._stats['sent' if ok else 'failed'] += 1
            self._stats['last_status'] = status
            self._stats['last_error'] = error
            self._stats['last_event_at'] = event['timestamp']
        if not ok:
            logger.warning('SIEM delivery failed for %s: %s', event['event_type'], error)
        return ok, error

    def forward(
        self,
        event_type: str,
        data: dict[str, Any],
        severity: str | None = None,
        background: bool = True,
    ) -> bool:
        """Queue an event for delivery. Returns False when no SIEM is configured."""
        if not settings.siem_configured:
            return False
        event = self.build_event(event_type, severity, data)
        if background:
            threading.Thread(target=self._deliver, args=(event,), daemon=True).start()
            return True
        return self._deliver(event)[0]

    def send_test(self) -> dict[str, Any]:
        if not settings.siem_configured:
            return {'ok': False, 'error': 'SIEM_WEBHOOK_URL is not configured'}
        event = self.build_event('integration.test', 'info', {'message': 'ThreatLens test event'})
        ok, error = self._deliver(event)
        return {'ok': ok, 'error': error}

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {'configured': settings.siem_configured, 'signed': bool(settings.SIEM_WEBHOOK_SECRET), **self._stats}


siem_forwarder = SiemForwarder()
