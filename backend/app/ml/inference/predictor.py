from typing import Any


class Predictor:
    def predict(self, model_name: str, features: Any) -> dict[str, Any]:
        """Temporary deterministic mock; replace this body with real model inference."""
        risk_score = int(features.get('risk_score', 0)) if isinstance(features, dict) else 0
        signature_type = features.get('signature_type') if isinstance(features, dict) else None

        if signature_type:
            predicted_class = str(signature_type)
        elif risk_score >= 80:
            predicted_class = 'Ransomware'
        elif risk_score >= 60:
            predicted_class = 'Trojan'
        elif risk_score >= 20:
            predicted_class = 'Spyware'
        else:
            predicted_class = 'Benign'

        confidence = round(min(0.99, max(0.55, 0.55 + abs(risk_score - 50) / 100)), 2)
        if predicted_class == 'Benign':
            confidence = round(max(confidence, 0.90), 2)
        return {
            'model_name': model_name,
            'source': 'mock',
            'predicted_class': predicted_class,
            'confidence': confidence,
        }
