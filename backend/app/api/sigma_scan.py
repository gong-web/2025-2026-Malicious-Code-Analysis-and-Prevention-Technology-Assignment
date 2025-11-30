from fastapi import APIRouter, HTTPException, UploadFile, File, Depends, BackgroundTasks
from typing import List, Dict, Any
from pydantic import BaseModel
import json
import yaml
from app.services.sigma_service import get_sigma_engine
from app.services.dynamic_analyzer import DynamicAnalyzer
from app.core.sigma_engine import SigmaEngine
from app.core.database import get_db
from sqlalchemy.orm import Session
from app.models.scan import ScanTask, ScanResult, ScanStatus, ThreatLevel
import shutil
import tempfile
import os
import uuid
from datetime import datetime

router = APIRouter()
dynamic_analyzer = DynamicAnalyzer()

class SigmaScanRequest(BaseModel):
    events: List[Dict[str, Any]]

class SigmaScanResult(BaseModel):
    total_events: int
    matches: List[Dict[str, Any]]

@router.post("/events", response_model=SigmaScanResult)
async def scan_events(
    request: SigmaScanRequest,
    engine: SigmaEngine = Depends(get_sigma_engine)
):
    """
    Scan a list of events (dicts) against Sigma rules.
    """
    try:
        results = engine.scan_events(request.events)
        return {
            "total_events": len(request.events),
            "matches": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.post("/file")
async def scan_log_file(
    file: UploadFile = File(...),
    engine: SigmaEngine = Depends(get_sigma_engine)
):
    """
    Scan an uploaded log file (JSON, JSONL, YAML).
    """
    content = await file.read()
    events = []
    
    filename = file.filename.lower()
    try:
        if filename.endswith('.json'):
            try:
                # Try parsing as list of dicts
                events = json.loads(content)
                if not isinstance(events, list):
                    # Maybe it's a single dict
                    events = [events]
            except json.JSONDecodeError:
                # Try JSONL
                events = []
                for line in content.decode('utf-8').splitlines():
                    if line.strip():
                        events.append(json.loads(line))
                        
        elif filename.endswith(('.yml', '.yaml')):
            data = yaml.safe_load(content)
            if isinstance(data, list):
                events = data
            else:
                events = [data]
        else:
            # Treat as text lines, wrap in simple event
            lines = content.decode('utf-8', errors='replace').splitlines()
            events = [{"message": line} for line in lines]
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse file: {str(e)}")
        
    if not events:
        return {"total_events": 0, "matches": []}
        
    results = engine.scan_events(events)
    
    return {
        "filename": file.filename,
        "total_events": len(events),
        "matches_count": len(results),
        "matches": results
    }

@router.post("/reload")
async def reload_rules(engine: SigmaEngine = Depends(get_sigma_engine)):
    """
    Reload Sigma rules from disk.
    """
    engine.reload_rules()
    return {"message": f"Rules reloaded. Active rules: {len(engine.rules)}"}


@router.post("/dynamic")
async def dynamic_scan(
    file: UploadFile = File(...),
    duration: int = 10,
    sandbox: bool = True,
    engine: SigmaEngine = Depends(get_sigma_engine),
    db: Session = Depends(get_db)
):
    """
    Upload an executable and perform analysis.
    
    - **sandbox=True**: (Default) Safe mode. Does NOT execute the file. Extracts strings to simulate suspicious events.
    - **sandbox=False**: DANGEROUS! Executes the file on the server to capture real logs.
    """
    if not file.filename.endswith(('.exe', '.bat', '.ps1', '.cmd')):
        raise HTTPException(status_code=400, detail="Only executable files supported")

    # Save to temp file
    file_size = 0
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as tmp:
            content = await file.read()
            file_size = len(content)
            tmp.write(content)
            tmp_path = tmp.name
            
        # Run dynamic analysis (Safe or Real based on sandbox param)
        events = await dynamic_analyzer.analyze_file(tmp_path, duration, sandbox_mode=sandbox)
        
        # Cleanup
        try:
            os.unlink(tmp_path)
        except:
            pass
            
        # Scan captured events
        results = engine.scan_events(events) if events else []
        
        # Persist to DB
        is_malicious = len(results) > 0
        threat_level = ThreatLevel.CLEAN
        
        # Determine max threat level
        if is_malicious:
            threat_level = ThreatLevel.LOW # Default
            for m in results:
                lvl = m.get("level", "medium")
                if lvl == "critical":
                    threat_level = ThreatLevel.CRITICAL
                    break
                if lvl == "high":
                    threat_level = ThreatLevel.MALICIOUS
                elif lvl == "medium" and threat_level != ThreatLevel.MALICIOUS:
                    threat_level = ThreatLevel.SUSPICIOUS

        # Create Task Record
        task_id = str(uuid.uuid4())
        db_task = ScanTask(
            task_id=task_id,
            target_path=file.filename,
            target_type="file",
            scan_type="dynamic", # Mark as dynamic scan
            status=ScanStatus.COMPLETED,
            total_files=1,
            scanned_files=1,
            detected_files=1 if is_malicious else 0,
            started_at=datetime.now(),
            completed_at=datetime.now()
        )
        db.add(db_task)
        db.commit()
        db.refresh(db_task)
        
        # Create Result Record
        matched_rule_names = [r.get("title") for r in results]
        
        db_result = ScanResult(
            task_id=db_task.id,
            file_path=file.filename,
            file_name=file.filename,
            file_size=file_size,
            file_hash="dynamic_analysis", # Hash not calculated here for speed
            threat_level=threat_level,
            is_malicious=is_malicious,
            matched_rules=str(matched_rule_names)
        )
        db.add(db_result)
        db.commit()

        return {
            "filename": file.filename,
            "mode": "simulated_sandbox" if sandbox else "real_execution",
            "total_events": len(events),
            "matches_count": len(results),
            "captured_events_preview": events[:5], # Show first 5 events for debug
            "matches": results,
            "task_id": task_id # Return task ID so frontend can link if needed
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Dynamic scan failed: {str(e)}")
