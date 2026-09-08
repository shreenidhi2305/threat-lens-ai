from typing import Any


class FeatureExtractor:
    def extract(self, analysis_result: Any) -> dict[str, Any]:
        """Convert static-analysis output into the model-facing feature contract."""
        if analysis_result is None:
            return {'risk_score': 0, 'risk_level': 'low', 'suspicious_indicator_count': 0}

        def read(name: str, default: Any = None) -> Any:
            if isinstance(analysis_result, dict):
                return analysis_result.get(name, default)
            return getattr(analysis_result, name, default)

        risk = read('risk', {})
        if isinstance(risk, dict):
            risk_score = risk.get('score', 0)
            risk_level = risk.get('level', 'low')
        else:
            risk_score = getattr(risk, 'score', 0)
            risk_level = getattr(risk, 'level', 'low')

        indicators = read('suspicious_indicators', []) or []
        signature = read('signature_match', {})
        signature_type = signature.get('type') if isinstance(signature, dict) else getattr(signature, 'type', None)

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'suspicious_indicator_count': len(indicators),
            'signature_type': signature_type,
        }
