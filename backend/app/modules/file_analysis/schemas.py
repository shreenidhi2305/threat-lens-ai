from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    object_path: str

class SignatureMatch(BaseModel):
    matched: bool
    name: str | None
    type: str | None

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


class AnalysisResult(BaseModel):
    object_path: str
    # Kept as top-level fields for backward compatibility with the existing contract.
    sha256: str
    md5: str
    hashes: FileHashes
    metadata: FileMetadata
    signature_match: SignatureMatch
    notes: list[str]
