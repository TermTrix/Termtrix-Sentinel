from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    IPSTACK_API_KEY: str
    VIRUSTOTAL_API_KEY: str
    MCP_SERVER: str
    GEMINI_API_KEY:str
    

    class Config:
        env_file = ".env"