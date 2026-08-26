from typing import Any


class Predictor:
    def predict(self, model_name: str, features: Any) -> dict[str, Any]:
        return {'model_name': model_name, 'status': 'not_implemented', 'result': None}
