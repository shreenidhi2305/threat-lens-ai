from app.modules.analytics.schemas import AnalyticsSummary


class AnalyticsService:
    def summary(self) -> AnalyticsSummary:
        return AnalyticsSummary(total_samples=0, classified_samples=0)


analytics_service = AnalyticsService()
