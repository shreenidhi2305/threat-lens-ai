from pydantic import BaseModel


class AnalysisRequest(BaseModel):
    object_path: str


class AnalysisResult(BaseModel):
    object_path: str
    sha256: str
    md5: str
    notes: list[str]
