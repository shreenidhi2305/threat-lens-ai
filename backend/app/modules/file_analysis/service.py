from app.modules.file_analysis.analyzers.hashing import calculate_hashes
from app.modules.file_analysis.schemas import AnalysisResult


class FileAnalysisService:
    def analyze_static_file(self, object_path: str, data: bytes) -> AnalysisResult:
        hashes = calculate_hashes(data)
        return AnalysisResult(
            object_path=object_path,
            sha256=hashes['sha256'],
            md5=hashes['md5'],
            notes=['Static analysis scaffold only. Do not execute uploaded files.'],
        )


file_analysis_service = FileAnalysisService()
