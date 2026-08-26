from typing import Any


class FeatureExtractor:
    def extract(self, analysis_result: Any) -> dict[str, Any]:
        return {'features': analysis_result}
