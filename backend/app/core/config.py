from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = 'ThreatLens AI API'
    API_PREFIX: str = '/api/v1'
    API_VERSION: str = '1.0.0'

    # 'production' turns on startup safety checks and disables the local dev login.
    APP_ENV: str = 'development'
    # Escape hatch for demo deployments with no identity provider (never for real data).
    ALLOW_DEV_LOGIN: bool = False
    # When set, the dev login only accepts this shared password (use it for any demo that is
    # reachable by other people, e.g. a public tunnel). Empty = any password (local dev only).
    DEV_LOGIN_PASSWORD: str = ''
    # Honour X-Forwarded-For when running behind a reverse proxy / load balancer.
    TRUST_PROXY_HEADERS: bool = False

    JWT_SECRET_KEY: str = 'change-me'
    JWT_ALGORITHM: str = 'HS256'
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    SUPABASE_URL: str = ''
    SUPABASE_SERVICE_KEY: str = ''
    SUPABASE_DB_URL: str = ''
    SUPABASE_STORAGE_BUCKET: str = 'samples'

    VIRUSTOTAL_API_KEY: str = ''
    VIRUSTOTAL_TIMEOUT_SECONDS: float = 4.0

    # Performance tuning.
    # Max scans running at once (each holds the whole file in memory and is CPU-heavy).
    MAX_CONCURRENT_SCANS: int = 2
    # Requests slower than this are logged as warnings by the timing middleware.
    SLOW_REQUEST_SECONDS: float = 1.0

    # API gateway: per-principal sliding-window rate limits (requests per minute).
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 240
    LOGIN_RATE_LIMIT_PER_MINUTE: int = 20
    # Largest accepted upload, in megabytes.
    MAX_UPLOAD_MB: int = 32

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

    # SIEM / SOAR integration: alerts and incidents are forwarded as signed JSON events.
    SIEM_WEBHOOK_URL: str = ''
    SIEM_WEBHOOK_TOKEN: str = ''
    SIEM_WEBHOOK_SECRET: str = ''

    model_config = SettingsConfigDict(
    env_file='.env',
    env_file_encoding='utf-8',
    extra='ignore'
)

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

    @property
    def siem_configured(self) -> bool:
        return bool(self.SIEM_WEBHOOK_URL)

    @property
    def is_production(self) -> bool:
        return self.APP_ENV.strip().lower() == 'production'

    @property
    def dev_login_password_required(self) -> bool:
        return bool(self.DEV_LOGIN_PASSWORD)

    @property
    def dev_login_enabled(self) -> bool:
        """The local dev login is available outside production, or when explicitly allowed."""
        return (not self.is_production) or self.ALLOW_DEV_LOGIN

    @property
    def virustotal_configured(self) -> bool:
        return bool(self.VIRUSTOTAL_API_KEY)


settings = Settings()
