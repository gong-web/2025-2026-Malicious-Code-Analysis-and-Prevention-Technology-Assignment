"""
YARA-X Manager Backend Application
Main entry point for FastAPI application
"""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api import rules, scan, reports, auth, sigma_rules, sigma_scan
from app.core.logger import setup_logging
from app.core.database import init_db

# Initialize logging
setup_logging()

app = FastAPI(
    title="YARA-X Manager API",
    description="恶意代码检测与 YARA 规则管理系统",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Initialize DB on startup
@app.on_event("startup")
def on_startup():
    init_db()

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(auth.router, prefix="/api/auth", tags=["认证"])
app.include_router(rules.router, prefix="/api/rules", tags=["YARA 规则"])
app.include_router(sigma_rules.router, prefix="/api/sigma-rules", tags=["Sigma 规则"])
app.include_router(sigma_scan.router, prefix="/api/sigma-scan", tags=["Sigma 扫描"])
app.include_router(scan.router, prefix="/api/scan", tags=["扫描任务"])
app.include_router(reports.router, prefix="/api/reports", tags=["检测报告"])


@app.get("/")
async def root():
    """根路径"""
    return {
        "message": "YARA-X Manager API",
        "version": "0.1.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy"}


if __name__ == "__main__":
    import logging
    
    # 设置日志级别为 INFO，避免 DEBUG 级别的详细日志
    logging.basicConfig(level=logging.INFO)
    
    # 禁用 multipart 模块的 DEBUG 日志
    logging.getLogger("multipart.multipart").setLevel(logging.WARNING)
    
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False,
        log_level="info"  # 修改为 info 级别
    )
