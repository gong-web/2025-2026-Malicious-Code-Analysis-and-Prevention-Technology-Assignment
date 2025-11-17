from fastapi import APIRouter, UploadFile, HTTPException, Form, File, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List
from pathlib import Path
from app.db import get_db
from app.sql_models import Rule
from app.tasks import validate_and_store_rule
from app.storage import delete_rule
router = APIRouter(prefix="/rules", tags=["rules"])
@router.post("/upload")
async def upload_rules(files: List[UploadFile] = File(...)):
    task_ids = []
    for file in files:
        content = (await file.read()).decode("utf-8")
        task = validate_and_store_rule.delay(content, file.filename)
        task_ids.append(task.id)
    return {"task_ids": task_ids}

@router.get("/")
def list_rules(db: Session = Depends(get_db)):
    rows = db.query(Rule).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "active": r.active,
            "path": r.path
        }
        for r in rows
    ]

@router.post("/delete/{ids}")
def delete_rules(ids: str, db: Session = Depends(get_db)):
    id_list = [int(id) for id in ids.split(",")]
    rules = db.query(Rule).filter(Rule.id.in_(id_list)).all()
    for rule in rules:
        db.delete(rule)
        delete_rule(Path(rule.path))
    db.commit()
    return {"message": "Rules deleted successfully"}
