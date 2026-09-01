from app.modules.file_analysis.analyzers.hashing import calculate_hashes
from app.modules.file_analysis.analyzers.metadata import extract_metadata
from app.modules.file_analysis.analyzers.network_indicators import extract_network_indicators
from app.modules.file_analysis.analyzers.risk import assess
from app.modules.file_analysis.analyzers.signature_matching import match_signature
from app.modules.file_analysis.analyzers.strings import extract_strings
from app.modules.file_analysis.analyzers.yara import scan_with_yara, yara_available
from app.modules.file_analysis.schemas import (
    AnalysisResult,
    FileHashes,
    FileMetadata,
    NetworkIndicators,
    RiskAssessment,
    SignatureMatch,
    YaraMatch,
)

_STRINGS_SAMPLE_LIMIT = 40


class FileAnalysisService:
    def analyze_static_file(self, object_path: str, data: bytes) -> AnalysisResult:
        """Run the full static-analysis pipeline over ``data``. Never executes it."""
        hashes = calculate_hashes(data)
        metadata = extract_metadata(data, filename=object_path)
        signature_result = match_signature(hashes['sha256'])
        yara_matches = scan_with_yara(data)
        network = extract_network_indicators(data)

        assessment = assess(
            data=data,
            metadata=metadata,
            yara_matches=yara_matches,
            signature_match=signature_result,
            network=network,
        )

        strings_sample = extract_strings(data, min_length=6)[:_STRINGS_SAMPLE_LIMIT]

        return AnalysisResult(
            object_path=object_path,
            sha256=hashes['sha256'],
            md5=hashes['md5'],
            hashes=FileHashes(**hashes),
            metadata=FileMetadata(**metadata),
            signature_match=SignatureMatch(**signature_result),
            yara_matches=[YaraMatch(**m) for m in yara_matches],
            yara_available=yara_available(),
            network_indicators=NetworkIndicators(**network),
            suspicious_indicators=assessment['suspicious_indicators'],
            suspicious_strings=assessment['suspicious_strings'],
            strings_sample=strings_sample,
            risk=RiskAssessment(**assessment['risk']),
            notes=['Static analysis only. Uploaded files are never executed.'],
        )


file_analysis_service = FileAnalysisService()
