from app.modules.file_analysis.analyzers.hashing import calculate_hashes
from app.modules.file_analysis.analyzers.metadata import extract_metadata
from app.modules.file_analysis.analyzers.signature_matching import match_signature
from app.modules.file_analysis.analyzers.yara import scan_with_yara
from app.modules.file_analysis.schemas import (
    AnalysisResult,
    FileHashes,
    FileMetadata,
    SignatureMatch,
    YaraMatch,
)


class FileAnalysisService:

    def analyze_static_file(self, object_path: str, data: bytes) -> AnalysisResult:

        hashes = calculate_hashes(data)

        metadata = extract_metadata(data, filename=object_path)

        yara_results = scan_with_yara(data)

        signature_result = match_signature(hashes["sha256"])

        return AnalysisResult(
            object_path=object_path,
            sha256=hashes["sha256"],
            md5=hashes["md5"],
            hashes=FileHashes(**hashes),
            metadata=FileMetadata(**metadata),
            signature_match=SignatureMatch(**signature_result),
            yara_matches=[YaraMatch(**result) for result in yara_results],
            notes=[
                "Static analysis scaffold only. Do not execute uploaded files."
            ],
        )


file_analysis_service = FileAnalysisService()