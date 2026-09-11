from pydantic import BaseModel


class AnalyticsSummary(BaseModel):
    total_samples: int
    classified_samples: int
