from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response

from app.core.dependencies import CurrentUser, require_roles
from app.modules.audit.service import audit_service
from app.modules.research.schemas import DatasetInfo, FamilyDetail, FamilySummary
from app.modules.research.service import research_service

router = APIRouter()

_ROLES = ('Researcher', 'Security Analyst', 'Administrator')


def _csv(content: str, filename: str) -> Response:
    return Response(
        content=content,
        media_type='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@router.get('/datasets', response_model=list[DatasetInfo])
def list_datasets(_user: CurrentUser = Depends(require_roles(*_ROLES))) -> list[DatasetInfo]:
    return research_service.datasets()


@router.get('/datasets/{dataset_id}/export.csv')
def export_dataset(
    dataset_id: str,
    request: Request,
    user: CurrentUser = Depends(require_roles(*_ROLES)),
) -> Response:
    content = research_service.export_dataset(dataset_id)
    if content is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'Dataset not found or not exportable')
    audit_service.record_request(request, 'research.export', user=user, target=dataset_id)
    return _csv(content, f'{dataset_id}.csv')


@router.get('/families', response_model=list[FamilySummary])
def list_families(_user: CurrentUser = Depends(require_roles(*_ROLES))) -> list[FamilySummary]:
    return research_service.families()


@router.get('/families/export.csv')
def export_families(
    request: Request, user: CurrentUser = Depends(require_roles(*_ROLES))
) -> Response:
    audit_service.record_request(request, 'research.export', user=user, target='families')
    return _csv(research_service.families_csv(), 'malware-families.csv')


@router.get('/families/{family}', response_model=FamilyDetail)
def get_family(
    family: str, _user: CurrentUser = Depends(require_roles(*_ROLES))
) -> FamilyDetail:
    detail = research_service.family(family)
    if detail is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'Family not found')
    return detail
