import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseModel):
    NMAP_PATH: str = os.getenv("NMAP_PATH", "nmap")
    ALLOWED_TARGET_REGEX: str = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^localhost$|^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    MAX_TIMEOUT_SECONDS: int = 300

    # LLM 配置
    LLM_API_KEY: str = os.getenv("LLM_API_KEY", "")
    LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "deepseek-chat")


settings = Settings()