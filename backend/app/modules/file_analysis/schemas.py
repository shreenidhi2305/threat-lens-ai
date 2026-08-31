from pydantic import BaseModel


class AnalysisRequest(BaseModel):
    object_path: str

class SignatureMatch(BaseModel):
    matched: bool
    name: str | None
    type: str | None

class AnalysisResult(BaseModel):
    object_path: str
    sha256: str
    md5: str
    notes: list[str]
