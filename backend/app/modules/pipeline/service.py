"""Detection pipeline orchestrator.

Runs the mandatory stages from the architecture diagram in order for every
uploaded file:

    File Service (done by caller)
      -> Analysis Service        static analysis + feature extraction
      -> ML Prediction Service   model inference
      -> Classification Service  verdict fusion (Result Generation)
      -> Threat Monitoring       detection logging
      -> Report Generation       threat prediction report
      -> Alert Service           alert generation
"""

from __future__ import annotations

import logging

from app.ml.inference.predictor import predict as ml_predict
from app.modules.alerts.service import alerts_service
from app.modules.file_analysis.schemas import AnalysisResult, MLPrediction
from app.modules.file_analysis.service import file_analysis_service
from app.modules.pipeline.fusion import fuse
from app.modules.reports.service import reports_service
from app.modules.threat_monitoring.service import threat_monitoring_service

logger = logging.getLogger(__name__)


class PipelineService:
    def scan(
        self,
        object_path: str,
        data: bytes,
        actor: str | None = None,
    ) -> AnalysisResult:

        # 1. static analysis
        result = file_analysis_service.analyze_static_file(
            object_path,
            data,
        )

        # 2. ML inference
        try:
            ml = MLPrediction(
                **ml_predict(
                    data,
                    result.model_dump(),
                )
            )
        except Exception:  # noqa: BLE001 - never let the model break the pipeline
            logger.exception("ML prediction failed")
            ml = MLPrediction(
                available=False,
                reason="inference error",
            )

        result.ml = ml

        # 3. classification / result generation
        result.verdict = fuse(result, ml)

        # 4. threat prediction report
        try:
            reports_service.create_threat_prediction_report(result)
        except Exception:  # noqa: BLE001 - report failure must not break detection
            logger.exception("Threat prediction report creation failed")

        # 5. detection logging
        detection = threat_monitoring_service.record(
            result,
            actor=actor,
        )

        # 6. alerting
        alerts_service.evaluate(
            result,
            detection_id=detection.id,
            actor=actor,
        )

        return result


pipeline_service = PipelineService()