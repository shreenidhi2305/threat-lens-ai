import asyncio

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.concurrency import run_in_threadpool

from app.core.config import settings
from app.core.dependencies import CurrentUser, require_roles
from app.modules.file_analysis import storage
from app.modules.file_analysis.schemas import AnalysisRequest, AnalysisResult
from app.modules.pipeline.service import pipeline_service

router = APIRouter()

# Roles allowed to submit files for analysis (per spec RBAC matrix).
_SCAN_ROLES = ('Security Analyst', 'Administrator', 'Researcher')

# Reject uploads larger than this (bytes). Analysis holds the file in memory.
_MAX_UPLOAD_BYTES = 32 * 1024 * 1024
_READ_CHUNK = 1024 * 1024

# Scans are CPU-heavy and hold the whole file in memory, so cap how many run at
# once. Extra uploads wait here (cheaply, on the event loop) instead of piling up
# threads. Created lazily so it binds to the running loop.
_scan_slots: asyncio.Semaphore | None = None


def _slots() -> asyncio.Semaphore:
    global _scan_slots
    if _scan_slots is None:
        _scan_slots = asyncio.Semaphore(max(1, settings.MAX_CONCURRENT_SCANS))
    return _scan_slots


async def _read_limited(file: UploadFile) -> bytes:
    """Read the upload in chunks, aborting as soon as it exceeds the size limit."""
    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(_READ_CHUNK):
        total += len(chunk)
        if total > _MAX_UPLOAD_BYTES:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, 'File exceeds 32 MB limit')
        chunks.append(chunk)
    return b''.join(chunks)


@router.post('/upload', response_model=AnalysisResult, status_code=status.HTTP_201_CREATED)
async def upload_and_scan(
    file: UploadFile = File(...),
    user: CurrentUser = Depends(require_roles(*_SCAN_ROLES)),
) -> AnalysisResult:
    """Upload a suspicious file, store it, and run the full detection pipeline.

    Static analysis, ML inference, verdict fusion, detection logging and alerting
    all run (Milestone 2). Nothing is executed.
    """
    data = await _read_limited(file)
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Uploaded file is empty')

    # The pipeline is synchronous and CPU-bound. Running it directly inside this
    # ``async def`` would block the event loop and stall every other request
    # (polling, dashboards, alerts) for the whole scan, so hand it to a worker thread.
    async with _slots():
        object_path = await run_in_threadpool(storage.save_sample, data, file.filename or 'sample')
        return await run_in_threadpool(pipeline_service.scan, object_path, data, user.user_id)


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
