from pydantic_settings import BaseSettings
class AppConfig(BaseSettings):
    env: str = 'prod'
