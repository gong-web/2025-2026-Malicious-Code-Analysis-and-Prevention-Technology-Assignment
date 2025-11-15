from fastapi import APIRouter, HTTPException, File, Depends, Body
from pydantic import BaseModel
from typing import List, Optional
import json
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.db import get_db
from app.sql_models import Sample, Scan, Rule
from app.tasks import run_scan

# Request model for starting scan
class ScanRequest(BaseModel):
    sample_names: List[str] = []
    rule_ids: Optional[List[int]] = None

# Set the path prefix to/scans
router = APIRouter(prefix="/scans", tags=["scans"])

# Allow clicking after file download to scan all uploaded samples or specific samples
@router.post("/start")
def start_scan(request: ScanRequest = Body(...), db: Session = Depends(get_db)):
    # get rules: either specified ones or all active rules
    if request.rule_ids:
        rules = db.query(Rule).filter(Rule.id.in_(request.rule_ids)).all()
    else:
        rules = db.query(Rule).filter(Rule.active == True).all()
    
    if not rules:
        raise HTTPException(404, "no active rules found")
    
    rule_paths = [r.path for r in rules]
    
    # get samples: either specified ones or all samples
    if request.sample_names:
        samples = db.query(Sample).filter(Sample.filename.in_(request.sample_names)).all()
    else:
        samples = db.query(Sample).all()
    
    if not samples:
        raise HTTPException(404, "no samples found")
    
    # start a Celery task for each sample
    task_ids = []
    for s in samples:
        t = run_scan.delay(s.id, rule_paths)
        task_ids.append({"sample": s.filename, "task_id": t.id})
    
    return {"scan_name": samples[0].filename if samples else "", "scans_started": task_ids}

@router.get("/status")
def scan_status_stream(db: Session = Depends(get_db)):
    def gen():
        while True:
            rows = db.query(Scan).all()
            if not rows:
                yield "data: []\n\n"
                break
            out = []
            all_done = True
            for sc in rows:
                out.append({
                    "id": sc.id,
                    "filename": sc.filename,
                    "status": sc.status,
                    "started_at": sc.started_at,
                    "finished_at": sc.finished_at
                })
                if sc.status not in ("done", "error"):
                    all_done = False
            yield f"data: {json.dumps(out)}\n\n"
            if all_done:
                break
    return StreamingResponse(gen(), media_type="text/event-stream")

@router.get("/{scan_name}/results")
def scan_results(scan_name: str, db: Session = Depends(get_db)):
    sc = db.query(Scan).filter(Scan.filename == scan_name).first()
    if not sc:
        raise HTTPException(404, "scan not found")
    if sc.status == "running":
        return {"scan_name": sc.filename, "status": sc.status, "results": [], "total_samples": 1, "completed": 0}
    
    # 解析结果为结构化数据
    results = []
    if sc.result:
        try:
            result_data = json.loads(sc.result)
            matches = result_data.get('matches', [])
            results = [{
                "sample_name": sc.filename,
                "matched_rules": [m.get('rule', 'unknown') for m in matches],
                "scan_time": 5.0,  # 可以计算实际扫描时间
                "status": sc.status
            }]
        except:
            pass
    
    return {
        "scan_name": sc.filename,
        "results": results,
        "total_samples": 1,
        "completed": 1 if sc.status == "done" else 0
    }
