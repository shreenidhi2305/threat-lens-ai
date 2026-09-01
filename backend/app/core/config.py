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


settings = Settings()
