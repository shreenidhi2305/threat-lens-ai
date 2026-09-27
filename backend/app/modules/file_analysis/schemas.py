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


class BehaviorCapability(BaseModel):
    """One inferred capability, with the static evidence that raised it."""

    category: str
    label: str
    evidence: list[str] = []


class BehaviorProfile(BaseModel):
    """Static behavioral-analysis output (Milestone 3 AI Prediction Module).

    Derived entirely from imports, PE structure, YARA family tags and
    suspicious strings -- the file is never executed.
    """

    available: bool = False
    is_pe: bool = False
    capabilities: list[BehaviorCapability] = []
    narrative: str = 'Behavioral analysis not run.'
    pe_summary: dict[str, object] = {}
    import_summary: dict[str, object] = {}


class ThreatIntelResult(BaseModel):
    """Best-effort VirusTotal enrichment, keyed by SHA-256.

    Informational only: it never affects the fused verdict score, so a slow
    or unreachable VirusTotal never changes a scan's outcome.
    """

    configured: bool = False
    available: bool = False
    malicious: int | None = None
    suspicious: int | None = None
    undetected: int | None = None
    harmless: int | None = None
    total_engines: int | None = None
    reputation: int | None = None
    permalink: str | None = None
    reason: str | None = None


class CategoryScore(BaseModel):
    category: str
    probability: float


class MLPrediction(BaseModel):
    """Output of the ML prediction service."""

    available: bool
    applicable: bool = False
    malicious: bool | None = None
    malware_probability: float | None = Field(default=None, ge=0, le=1)
    category: str | None = None
    category_confidence: float | None = None
    top_categories: list[CategoryScore] = []
    model_versions: dict[str, str | None] = {}
    reason: str | None = None


class Verdict(BaseModel):
    """The fused final verdict: static rules AND the ML model, combined."""

    label: str = Field(description="malicious | suspicious | benign")
    score: int = Field(ge=0, le=100, description="Fused risk score, 0-100.")
    level: str = Field(description="low | medium | high")
    confidence: float = Field(ge=0, le=1)
    classification: str = Field(description="Human-readable verdict, e.g. 'Trojan'.")
    family: str | None = None
    recommended_action: str
    sources: dict[str, object] = Field(
        default_factory=dict, description="What each engine contributed."
    )
    agreement: str = Field(description="agree | ml-only | rules-only | conflict")
    novel_threat: bool = Field(
        default=False,
        description="True when the ML model alone flagged this sample as malicious, with no "
        "matching signature or YARA rule -- an unknown/zero-day-style detection.",
    )


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
    behavior: BehaviorProfile = BehaviorProfile()
    # Populated by the pipeline service (Milestone 2). Absent for a bare static scan.
    ml: MLPrediction | None = None
    verdict: Verdict | None = None
    # Populated by the pipeline service (Milestone 3). Best-effort; never blocks a scan.
    threat_intel: ThreatIntelResult = ThreatIntelResult()
    notes: list[str]
