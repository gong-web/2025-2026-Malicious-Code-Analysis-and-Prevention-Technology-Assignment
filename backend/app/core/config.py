"""
配置文件
"""

from pydantic_settings import BaseSettings
from typing import List
from pathlib import Path


class Settings(BaseSettings):
    """应用配置"""
    
    # 应用配置
    APP_NAME: str = "YARA-X Manager"
    VERSION: str = "0.1.0"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://localhost:5173",
        "http://localhost:5174",  # Vite default
        "http://127.0.0.1:5174"
    ]
    
    # 数据库
    DATABASE_URL: str = "sqlite:///./yara_manager.db"
    # DATABASE_URL: str = "postgresql://user:password@localhost/yara_db"
    
    # Redis (任务队列)
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # JWT 认证
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # YARA 配置
    YARA_RULES_DIR: str = "./rules"
    YARA_COMPILED_DIR: str = "./compiled"
    MAX_RULE_SIZE: int = 10 * 1024 * 1024  # 10MB
    
    # Sigma 配置 - 使用绝对路径
    # 获取项目根目录（backend/app/core/config.py向上3级）
    _project_root = Path(__file__).resolve().parent.parent.parent.parent
    SIGMA_COMPILED_PATH: str = str(_project_root / "data" / "sigma_rules_compiled.bin")
    
    # 扫描配置
    SCAN_TIMEOUT: int = 300  # 5分钟
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
    SCAN_THREADS: int = 4
    
    # 上传配置
    UPLOAD_DIR: str = "./uploads"
    MAX_UPLOAD_SIZE: int = 500 * 1024 * 1024  # 500MB

    # VirusTotal Public API (used for sandbox behavior fetching)
    VT_API_KEY: str = ""
    VT_API_BASE_URL: str = "https://www.virustotal.com/api/v3"
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


settings = Settings()
