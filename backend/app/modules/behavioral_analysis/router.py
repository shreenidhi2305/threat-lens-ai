"""Behavioral analysis routes.

POST /behavior/analyze          -> file upload -> behavioral result
POST /behavior/from-analysis   -> AnalysisResult JSON -> behavioral result
GET  /behavior/catalog         -> full behavior catalog (all tactics/techniques)
GET  /behavior/tactics         -> tactic list with counts from catalog
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from app.core.dependencies import CurrentUser, require_roles
from app.modules.behavioral_analysis.engine import BEHAVIOR_CATALOG, _TACTIC_IDS, _TACTIC_ORDER, _mitre_url
from app.modules.behavioral_analysis.schemas import BehavioralAnalysisRequest, BehavioralAnalysisResult
from app.modules.behavioral_analysis.service import behavioral_analysis_service
from app.modules.file_analysis import storage
from app.modules.file_analysis.schemas import AnalysisResult
from app.modules.file_analysis.service import file_analysis_service

router = APIRouter()

_SCAN_ROLES = ("Security Analyst", "Administrator", "Researcher", "SOC Team Member")

_MAX_UPLOAD_BYTES = 32 * 1024 * 1024


@router.get("/catalog")
def get_catalog(
    _user: CurrentUser = Depends(require_roles(*_SCAN_ROLES)),
) -> dict:
    """Return the full catalog of behaviors this system can infer (static reference)."""
    items = []
    for b in BEHAVIOR_CATALOG:
        items.append(
            {
                **b,
                "tactic_id": _TACTIC_IDS.get(b["tactic"], ""),
                "mitre_url": _mitre_url(b["technique_id"]),
            }
        )
    return {"total": len(items), "behaviors": items, "tactic_order": _TACTIC_ORDER}


@router.get("/tactics")
def get_tactics(
    _user: CurrentUser = Depends(require_roles(*_SCAN_ROLES)),
) -> dict:
    counts: dict[str, int] = {}
    for b in BEHAVIOR_CATALOG:
        counts[b["tactic"]] = counts.get(b["tactic"], 0) + 1
    tactics = [
        {"tactic": t, "tactic_id": _TACTIC_IDS.get(t, ""), "total_behaviors": counts.get(t, 0)}
        for t in _TACTIC_ORDER
        if t in counts
    ]
    return {"tactics": tactics, "order": _TACTIC_ORDER}


@router.post("/analyze", response_model=BehavioralAnalysisResult, status_code=status.HTTP_200_OK)
async def analyze_upload(
    file: UploadFile = File(...),
    user: CurrentUser = Depends(require_roles(*_SCAN_ROLES)),
) -> BehavioralAnalysisResult:
    """Static behavioral analysis directly on an uploaded file (no execution)."""
    data = await file.read()
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Uploaded file is empty")
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File exceeds 32 MB limit")

    object_path = storage.save_sample(data, file.filename or "sample")
    # Run lightweight static analysis to feed the behavioral engine with richer signals
    static = file_analysis_service.analyze_static_file(object_path, data)
    result = behavioral_analysis_service.analyze(
        data,
        object_path=object_path,
        suspicious_strings=static.suspicious_strings,
        yara_matches=[m.model_dump() for m in static.yara_matches],
        network=static.network_indicators.model_dump(),
        metadata=static.metadata.model_dump(),
        signature_match=static.signature_match.model_dump(),
        strings_sample=static.strings_sample,
        file_hash=static.sha256,
    )
    return result


@router.post("/from-analysis", response_model=BehavioralAnalysisResult)
def analyze_from_analysis(
    payload: AnalysisResult,
    _user: CurrentUser = Depends(require_roles(*_SCAN_ROLES)),
) -> BehavioralAnalysisResult:
    """Derive behavioral analysis from an existing AnalysisResult (e.g. from /files/upload)."""
    return behavioral_analysis_service.analyze_from_analysis_result(payload)


@router.post("/from-storage", response_model=BehavioralAnalysisResult)
def analyze_stored(
    payload: BehavioralAnalysisRequest,
    _user: CurrentUser = Depends(require_roles(*_SCAN_ROLES)),
) -> BehavioralAnalysisResult:
    """Behavioral analysis for a previously uploaded object path."""
    data = storage.load_sample(payload.object_path)
    if data is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sample not found. Upload it first via /files/upload.")
    static = file_analysis_service.analyze_static_file(payload.object_path, data)
    return behavioral_analysis_service.analyze(
        data,
        object_path=payload.object_path,
        suspicious_strings=static.suspicious_strings,
        yara_matches=[m.model_dump() for m in static.yara_matches],
        network=static.network_indicators.model_dump(),
        metadata=static.metadata.model_dump(),
        signature_match=static.signature_match.model_dump(),
        strings_sample=static.strings_sample,
        file_hash=static.sha256,
    )
