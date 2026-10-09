"""Platform activity / audit log.

Security-relevant actions (sign-ins, scans, role changes, settings changes, alert
triage, report downloads, ...) are recorded here for the administrator's activity
view. Recording never raises: an audit failure must not break the action itself.
Persisted to Supabase when configured; otherwise (and on failure) held in memory.
"""

from __future__ import annotations

import logging
import uuid
from collections import deque
from datetime import datetime, timezone

from fastapi import Request

from app.core.config import settings
from app.core.rate_limit import client_ip
from app.db.repositories.audit import AuditRepository
from app.modules.audit.schemas import AuditEvent

logger = logging.getLogger(__name__)

_MAX_EVENTS = 5000


class AuditService:
    def __init__(self) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=_MAX_EVENTS)
        self._repository = AuditRepository()

    def record(
        self,
        action: str,
        *,
        actor: str | None = None,
        role: str | None = None,
        target: str | None = None,
        detail: str | None = None,
        status: str = 'success',
        ip: str | None = None,
    ) -> AuditEvent | None:
        try:
            event = AuditEvent(
                id=str(uuid.uuid4()),
                at=datetime.now(timezone.utc),
                actor=actor,
                role=role,
                action=action,
                target=target,
                detail=(detail[:500] if detail else None),
                status=status,
                ip=ip,
            )
            self._events.appendleft(event)
            self._persist(event)
            return event
        except Exception:  # noqa: BLE001 - auditing must never break the audited action
            logger.exception('Failed to record audit event %s', action)
            return None

    def record_request(
        self,
        request: Request | None,
        action: str,
        *,
        user=None,
        actor: str | None = None,
        **kwargs,
    ) -> AuditEvent | None:
        """Record an event, taking actor/role from a ``CurrentUser`` and the IP from the request."""
        if user is not None:
            actor = actor or user.user_id
            kwargs.setdefault('role', user.roles[0] if user.roles else None)
        ip = client_ip(request) if request is not None else None
        return self.record(action, actor=actor, ip=ip, **kwargs)

    def _persist(self, event: AuditEvent) -> None:
        if not settings.supabase_configured:
            return
        try:
            self._repository.create({
                'id': event.id,
                'actor': event.actor,
                'role': event.role,
                'action': event.action,
                'target': event.target,
                'detail': event.detail,
                'status': event.status,
                'ip': event.ip,
                'created_at': event.at,
            })
        except Exception:  # noqa: BLE001
            pass  # keep the in-memory copy

    def _all(self) -> list[AuditEvent]:
        if settings.supabase_configured:
            try:
                rows = self._repository.list(limit=_MAX_EVENTS)
                items = []
                for row in rows:
                    row = dict(row)
                    row['at'] = row.pop('created_at', None) or row.get('at')
                    items.append(AuditEvent.model_validate(row))
                return items
            except Exception:  # noqa: BLE001
                pass
        return list(self._events)

    def list_events(
        self,
        limit: int = 100,
        action: str | None = None,
        actor: str | None = None,
        q: str | None = None,
    ) -> list[AuditEvent]:
        items = self._all()
        if action:
            items = [e for e in items if e.action == action or e.action.startswith(f'{action}.')]
        if actor:
            items = [e for e in items if (e.actor or '').lower() == actor.lower()]
        if q and q.strip():
            needle = q.strip().lower()
            items = [
                e for e in items
                if needle in e.action.lower()
                or needle in (e.actor or '').lower()
                or needle in (e.target or '').lower()
                or needle in (e.detail or '').lower()
            ]
        return items[:limit]

    def counts_by_action(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for event in self._all():
            counts[event.action] = counts.get(event.action, 0) + 1
        return counts


audit_service = AuditService()
