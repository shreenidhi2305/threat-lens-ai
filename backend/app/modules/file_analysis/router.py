from fastapi import APIRouter

from app.modules.file_analysis.schemas import AnalysisRequest, AnalysisResult
from app.modules.file_analysis.service import file_analysis_service

router = APIRouter()


@router.post('/scan', response_model=AnalysisResult)
def scan_file(payload: AnalysisRequest) -> AnalysisResult:
    return file_analysis_service.analyze_static_file(payload.object_path, payload.object_path.encode('utf-8'))
