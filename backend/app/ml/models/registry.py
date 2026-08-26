from typing import Any


class ModelRegistry:
    def load(self, model_name: str) -> Any:
        raise NotImplementedError
