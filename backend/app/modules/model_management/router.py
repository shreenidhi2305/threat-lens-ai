from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response

from app.core.dependencies import CurrentUser, require_roles
from app.modules.audit.service import audit_service
from app.modules.model_management.schemas import FeedbackRecord, FeedbackRequest, FeedbackSummary
from app.modules.model_management.service import feedback_service

router = APIRouter()

_SUBMIT_ROLES = ('Security Analyst', 'SOC Team Member', 'Administrator')
_READ_ROLES = ('Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher')


@router.post('', response_model=FeedbackRecord, status_code=status.HTTP_201_CREATED)
def submit_feedback(
    payload: FeedbackRequest,
    request: Request,
    user: CurrentUser = Depends(require_roles(*_SUBMIT_ROLES)),
) -> FeedbackRecord:
    """Confirm or correct a verdict. The latest correction for a sample wins."""
    try:
        record = feedback_service.submit(payload.sha256, payload.label, payload.note, user.user_id)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    audit_service.record_request(
        request, 'feedback.submit', user=user, target=record.sha256,
        detail=f'{record.label} (model said {record.model_verdict})',
    )
    return record


@router.get('', response_model=list[FeedbackRecord])
def list_feedback(
    _user: CurrentUser = Depends(require_roles(*_READ_ROLES)),
    limit: int = Query(200, ge=1, le=2000),
) -> list[FeedbackRecord]:
    return feedback_service.list_feedback(limit)


@router.get('/summary', response_model=FeedbackSummary)
def feedback_summary(_user: CurrentUser = Depends(require_roles(*_READ_ROLES))) -> FeedbackSummary:
    return feedback_service.summary()


@router.get('/export.csv')
def export_feedback(
    request: Request,
    user: CurrentUser = Depends(require_roles('Administrator', 'Researcher')),
) -> Response:
    audit_service.record_request(request, 'feedback.export', user=user)
    return Response(
        content=feedback_service.export_csv(),
        media_type='text/csv',
        headers={'Content-Disposition': 'attachment; filename="analyst-feedback.csv"'},
    )
