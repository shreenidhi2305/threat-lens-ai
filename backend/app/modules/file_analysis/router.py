from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from app.core.dependencies import CurrentUser, require_roles
from app.modules.file_analysis import storage
from app.modules.file_analysis.schemas import AnalysisRequest, AnalysisResult
from app.modules.pipeline.service import pipeline_service

router = APIRouter()

# Roles allowed to submit files for analysis (per spec RBAC matrix).
_SCAN_ROLES = ('Security Analyst', 'Administrator', 'Researcher')

# Reject uploads larger than this (bytes). Analysis holds the file in memory.
_MAX_UPLOAD_BYTES = 32 * 1024 * 1024


@router.post('/upload', response_model=AnalysisResult, status_code=status.HTTP_201_CREATED)
async def upload_and_scan(
    file: UploadFile = File(...),
    user: CurrentUser = Depends(require_roles(*_SCAN_ROLES)),
) -> AnalysisResult:
    """Upload a suspicious file, store it, and run the full detection pipeline.

    Static analysis, ML inference, verdict fusion, detection logging and alerting
    all run (Milestone 2). Nothing is executed.
    """
    data = await file.read()
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Uploaded file is empty')
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, 'File exceeds 32 MB limit')

    object_path = storage.save_sample(data, file.filename or 'sample')
    return pipeline_service.scan(object_path, data, actor=user.user_id)


@router.post('/scan', response_model=AnalysisResult)
def scan_stored_file(
    payload: AnalysisRequest,
    user: CurrentUser = Depends(require_roles(*_SCAN_ROLES)),
) -> AnalysisResult:
    """Re-run the full pipeline on an already-stored sample (by object path).

    Falls back to analysing the path string itself when no stored object exists,
    so the endpoint stays usable in tests and quick demos.
    """
    data = storage.load_sample(payload.object_path)
    if data is None:
        data = payload.object_path.encode('utf-8')
    return pipeline_service.scan(payload.object_path, data, actor=user.user_id)
