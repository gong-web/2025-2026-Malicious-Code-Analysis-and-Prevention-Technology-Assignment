from fastapi import APIRouter, UploadFile, HTTPException, File, Depends
from fastapi.responses import FileResponse
from typing import List
from sqlalchemy.orm import Session
from app.db import get_db
from app.sql_models import Sample, Scan
from app.tasks import download_and_register
# Set the path prefix to/samples
router = APIRouter(prefix="/samples", tags=["samples"])
# Asynchronous reading of files and passing binary data to Celery,aand return sample'ID
@router.post("/upload")
async def upload_sample(files: List[UploadFile] = File(...), db: Session = Depends(get_db)):
    task_ids = []
    for file in files:
        data = await file.read()
        task = download_and_register.delay(data, file.filename)
        task_ids.append(task.id)
    db.commit()
    return {"task_ids": task_ids}
# Read basic information of all samples
@router.get("/")
def list_samples(db: Session = Depends(get_db)):
    from pathlib import Path
    import os
    import hashlib
    from datetime import datetime
    
    rows = db.query(Sample).all()
    result = []
    for s in rows:
        # 计算真实的文件大小和哈希值
        size = 0
        hash_value = ""
        upload_time = "2025-11-12"
        
        if s.path and os.path.exists(s.path):
            size = os.path.getsize(s.path)
            upload_time = datetime.fromtimestamp(os.path.getctime(s.path)).strftime("%Y-%m-%d %H:%M:%S")
            
            # 计算文件哈希值
            try:
                with open(s.path, 'rb') as f:
                    file_bytes = f.read()
                    hash_value = hashlib.sha256(file_bytes).hexdigest()
            except:
                hash_value = "N/A"
        
        # 统计扫描次数
        scan_count = db.query(Scan).filter(Scan.filename == s.filename).count()
        
        result.append({
            "id": s.id,
            "name": s.filename,  # 前端期望的字段名
            "filename": s.filename,  # 完整文件名
            "hash": hash_value,  # SHA256哈希值
            "size": size,
            "upload_time": upload_time,
            "scan_count": scan_count,
            "path": s.path  # 文件路径
        })
    
    return result
# Query sample information based on the input file name
@router.get("/{sample_name}")
def get_sample(sample_name: str, db: Session = Depends(get_db)):
    s = db.query(Sample).filter(Sample.filename == sample_name).first()
    if not s:
        raise HTTPException(status_code=404, detail="sample not found")
    return {"id": s.id, "filename": s.filename, "path": s.path}
