from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.dependencies import CurrentUser, require_roles
from app.modules.notifications.schemas import Notification, NotificationCounts
from app.modules.notifications.service import notifications_service

router = APIRouter()

_VIEW_ROLES = ('Security Analyst', 'SOC Team Member', 'Administrator')


@router.get('/', response_model=list[Notification])
def list_notifications(
    _user: CurrentUser = Depends(require_roles(*_VIEW_ROLES)),
    unread_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
) -> list[Notification]:
    return notifications_service.list_notifications(unread_only=unread_only, limit=limit)


@router.get('/unread-count', response_model=NotificationCounts)
def unread_count(_user: CurrentUser = Depends(require_roles(*_VIEW_ROLES))) -> NotificationCounts:
    return notifications_service.counts()


@router.post('/{notification_id}/read', response_model=Notification)
def mark_read(
    notification_id: str,
    _user: CurrentUser = Depends(require_roles(*_VIEW_ROLES)),
) -> Notification:
    notification = notifications_service.mark_read(notification_id)
    if notification is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'Notification not found')
    return notification


@router.post('/read-all')
def mark_all_read(_user: CurrentUser = Depends(require_roles(*_VIEW_ROLES))) -> dict[str, int]:
    return {'marked': notifications_service.mark_all_read()}
