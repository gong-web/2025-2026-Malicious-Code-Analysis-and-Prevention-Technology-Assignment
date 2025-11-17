from fastapi import APIRouter, HTTPException, File, Depends
import json
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.db import get_db
from app.sql_models import Sample, Scan, Rule
from app.tasks import run_scan
# Set the path prefix to/scans
router = APIRouter(prefix="/scans", tags=["scans"])
# Allow clicking after file download to scan all uploaded samples
@router.post("/start")
def start_scan(db: Session = Depends(get_db)):
    # get all active rules
    rules = db.query(Rule).filter(Rule.active == True).all()
    rule_paths = [r.path for r in rules]
    # get all samples
    samples = db.query(Sample).all()
    if not samples:
        raise HTTPException(404, "no samples found")
    # start a Celery task for each sample
    task_ids = []
    for s in samples:
        t = run_scan.delay(s.id, rule_paths)
        task_ids.append({"sample": s.filename, "task_id": t.id})
    return {"scans_started": task_ids}

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
        return {"status": sc.status}
    return {"filename": sc.filename, "status": sc.status, "result": sc.result}
