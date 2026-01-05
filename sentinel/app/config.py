from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv
load_dotenv()

class Settings(BaseSettings):
    # API Keys
    IPSTACK_API_KEY: str
    VIRUSTOTAL_API_KEY: str 
    GEMINI_API_KEY:str 
    
    # Servers
    MCP_SERVER: str
    MAIN_SERVER:str 

    # Database
    DB_URI: str

    # Redis - Newly Added
    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_DB: int

    # Slack
    SLACK_WEBHOOK_URL: str
    
    # ClickHouse
    CH_HOST: str
    CH_USER: str
    CH_PASSWORD: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )

settings = Settings()