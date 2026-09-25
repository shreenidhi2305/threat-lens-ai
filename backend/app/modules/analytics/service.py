from __future__ import annotations

from datetime import datetime, timezone

from app.ml.models.registry import registry_status
from app.modules.alerts.service import alerts_service
from app.modules.analytics.schemas import AnalyticsSummary
from app.modules.reports.service import reports_service
from app.modules.threat_monitoring.service import threat_monitoring_service


class AnalyticsService:
    """Aggregates detection, alert, report and model data for the analytics
    dashboard.

    Detection counts are delegated to ``ThreatMonitoringService`` (the single
    source of truth also used by the Threat Monitor page) so the two views
    never disagree; this module adds alert, report and model context on top.
    """

    def summary(self) -> AnalyticsSummary:
        open_alerts_list = alerts_service.list_alerts(status='open')
        open_alerts = len(open_alerts_list)
        critical_alerts = sum(1 for a in open_alerts_list if a.severity == 'critical')

        stats = threat_monitoring_service.get_stats(open_alerts=open_alerts)
        detections = threat_monitoring_service.all_detections()
        avg_score = round(sum(d.score for d in detections) / len(detections), 2) if detections else 0.0

        model = registry_status()
        det_info = model.get('detector') or {}
        clf_info = model.get('classifier') or {}

        return AnalyticsSummary(
            total_samples=stats['total_detections'],
            classified_samples=stats['malicious'] + stats['suspicious'] + stats['benign'],
            malicious=stats['malicious'],
            suspicious=stats['suspicious'],
            benign=stats['benign'],
            detection_rate=stats['detection_rate'],
            last_24h=stats['last_24h'],
            avg_risk_score=avg_score,
            by_level=stats['by_level'],
            by_verdict=stats['by_verdict'],
            by_agreement=stats['by_agreement'],
            top_families=stats['top_families'],
            ml_only_catches=stats['ml_only_catches'],
            open_alerts=open_alerts,
            critical_alerts=critical_alerts,
            reports_generated=len(reports_service.list_report_history(limit=1000)),
            detector_version=det_info.get('version'),
            classifier_version=clf_info.get('version'),
            generated_at=datetime.now(timezone.utc),
        )


analytics_service = AnalyticsService()