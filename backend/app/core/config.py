from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = 'ThreatLens AI API'
    API_PREFIX: str = '/api/v1'
    API_VERSION: str = '0.1.0'

    JWT_SECRET_KEY: str = 'change-me'
    JWT_ALGORITHM: str = 'HS256'
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    SUPABASE_URL: str = ''
    SUPABASE_SERVICE_KEY: str = ''
    SUPABASE_DB_URL: str = ''
    SUPABASE_STORAGE_BUCKET: str = 'samples'

    VIRUSTOTAL_API_KEY: str = ''

    # Comma-separated list of origins allowed to call the API from a browser.
    CORS_ALLOW_ORIGINS: str = 'http://localhost:5173,http://127.0.0.1:5173'

    # Alert Service: verdict level at or above which an alert is raised.
    ALERT_MIN_LEVEL: str = 'high'
    # Email notifications for alerts (optional; alerts still work without SMTP).
    SMTP_HOST: str = ''
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ''
    SMTP_PASSWORD: str = ''
    SMTP_USE_TLS: bool = True
    ALERT_EMAIL_FROM: str = 'threatlens@localhost'
    ALERT_EMAIL_TO: str = ''

    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8')

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ALLOW_ORIGINS.split(',') if origin.strip()]

    @property
    def supabase_configured(self) -> bool:
        """True when real Supabase credentials are present.

        When False, auth falls back to a local dev login (see auth service).
        """
        return bool(self.SUPABASE_URL and self.SUPABASE_SERVICE_KEY)

    @property
    def smtp_configured(self) -> bool:
        return bool(self.SMTP_HOST and self.ALERT_EMAIL_TO)


settings = Settings()
