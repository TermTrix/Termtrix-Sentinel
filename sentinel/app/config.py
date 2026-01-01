from pydantic_settings import BaseSettings,SettingsConfigDict
from dotenv import load_dotenv
load_dotenv()

class Settings(BaseSettings):
    IPSTACK_API_KEY: str = "IPSTACK_API_KEY"
    VIRUSTOTAL_API_KEY: str = "VIRUSTOTAL_API_KEY"
    GEMINI_API_KEY:str = "GEMINI_API_KEY"
    
    MCP_SERVER: str = "MCP_SERVER"
    MAIN_SERVER:str = "MAIN_SERVER"

    DB_URI: str = "DB_URI"

    SLACK_WEBHOOK_URL: str = "SLACK_WEBHOOK_URL"
    

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )

settings = Settings()