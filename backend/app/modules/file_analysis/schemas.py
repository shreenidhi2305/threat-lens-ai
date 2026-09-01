from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    object_path: str


class SignatureMatch(BaseModel):
    matched: bool
    name: str | None = None
    type: str | None = None
    severity: str | None = None


class FileHashes(BaseModel):
    """Cryptographic digests of the uploaded sample."""

    md5: str
    sha1: str
    sha256: str


class FileMetadata(BaseModel):
    """Static metadata derived from the sample without executing it."""

    size_bytes: int = Field(description="File size in bytes.")
    file_type: str = Field(description="Human-readable file type from magic bytes.")
    mime_type: str = Field(description="Best-effort MIME type from content.")
    magic_hex: str = Field(description="Hex of the first bytes of the file.")
    extension: str | None = Field(
        default=None, description="Declared file extension, lowercased (if the upload name is known)."
    )
    extension_matches_content: bool | None = Field(
        default=None,
        description="Whether the declared extension is consistent with the detected content type. "
        "False is a classic disguise indicator.",
    )
    shannon_entropy: float = Field(description="Byte entropy in bits/byte (0-8).")
    likely_packed: bool = Field(
        description="Heuristic: binary content with high entropy, suggesting packing/encryption."
    )
    printable_ratio: float = Field(description="Fraction of printable-ASCII bytes.")
    likely_text: bool = Field(description="Whether the sample looks like a text file.")


class YaraMatch(BaseModel):
    rule: str
    tags: list[str] = []
    meta: dict[str, object] = {}
    matched_strings: list[str] = []


class NetworkIndicators(BaseModel):
    urls: list[str] = []
    ips: list[str] = []
    domains: list[str] = []


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100, description="Aggregate static risk score, 0-100.")
    level: str = Field(description="low | medium | high")
    classification: str = Field(description="Human-readable verdict.")
    recommended_action: str


class AnalysisResult(BaseModel):
    object_path: str
    # Kept as top-level fields for backward compatibility with the existing contract.
    sha256: str
    md5: str
    hashes: FileHashes
    metadata: FileMetadata
    signature_match: SignatureMatch
    yara_matches: list[YaraMatch] = []
    yara_available: bool = True
    network_indicators: NetworkIndicators = NetworkIndicators()
    suspicious_indicators: list[str] = []
    suspicious_strings: list[str] = []
    strings_sample: list[str] = []
    risk: RiskAssessment
    notes: list[str]
