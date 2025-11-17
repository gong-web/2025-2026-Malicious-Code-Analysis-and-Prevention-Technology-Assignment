from fastapi import FastAPI
import shutil
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from app.db import Base, engine
import app.sql_models
from app.sql_models import Rule
from app.db import get_db_session
from app.api import samples, scans, rules, reports
from app.api import scan_v2  # 新增前端兼容API
import app.celery_app
from app.config import BASE, RULES_DIR
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
app = FastAPI(title="Yara-X Scanner API", version="0.1")

Base.metadata.create_all(bind=engine)

def load_rules_from_my_rules():
    src = Path("my_rules")
    dst = RULES_DIR
    dst.mkdir(parents=True, exist_ok=True)
    yar_files = [
        p for p in src.rglob("*.yar")
        if len(p.relative_to(src).parts) <= 5
    ]
    for f in yar_files:
        name_only = f.name
        target = dst / name_only
        shutil.copy2(f, target)
        with get_db_session() as db:
            exists = db.query(Rule).filter(Rule.name == name_only).first()
            if exists:
                continue
            r = Rule(name=name_only, path=str(target), active=True)
            db.add(r)
            db.commit()
            db.refresh(r)

load_rules_from_my_rules()

# CORS - adjust origins as needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# include routers with /api prefix
app.include_router(samples.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(rules.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(scan_v2.router, prefix="/api")  # 前端兼容的扫描API


@app.get("/")
def root():
    return {"service": "yara-x-scanner", "status": "ok"}

