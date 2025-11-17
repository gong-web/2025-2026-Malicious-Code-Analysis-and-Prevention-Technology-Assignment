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
    rows = db.query(Sample).all()
    return [
        {"id": s.id, "filename": s.filename, "path": s.path}
        for s in rows
    ]
# Query sample information based on the input file name
@router.get("/{sample_name}")
def get_sample(sample_name: str, db: Session = Depends(get_db)):
    s = db.query(Sample).filter(Sample.filename == sample_name).first()
    if not s:
        raise HTTPException(status_code=404, detail="sample not found")
    return {"id": s.id, "filename": s.filename, "path": s.path}
