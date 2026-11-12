from pydantic import BaseSettings
class AppConfig(BaseSettings):
    env: str = 'prod'
