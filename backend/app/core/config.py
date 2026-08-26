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

    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8')


settings = Settings()
