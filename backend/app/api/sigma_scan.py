from fastapi import APIRouter, HTTPException, UploadFile, File, Depends, BackgroundTasks
from typing import List, Dict, Any
from pydantic import BaseModel, Field, validator
import json
import yaml
import re
import hashlib
from app.services.sigma_service import get_sigma_engine
from app.services.dynamic_analyzer import DynamicAnalyzer
from app.services.virustotal_service import get_vt_client
from app.core.sigma_engine import SigmaEngine
from app.core.database import get_db
from app.core.config import settings
from sqlalchemy.orm import Session
from app.models.scan import ScanTask, ScanResult, ScanStatus, ThreatLevel
import shutil
import tempfile
import os
import uuid
from datetime import datetime

router = APIRouter()
dynamic_analyzer = DynamicAnalyzer()
vt_client = get_vt_client()

class SigmaScanRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(..., max_items=10000, description="Maximum 10000 events per request")
    
    @validator('events')
    def validate_events(cls, v):
        if len(v) > 10000:
            raise ValueError("Maximum 10000 events allowed per request")
        if not v:
            raise ValueError("Events list cannot be empty")
        return v

class VirusTotalScanRequest(BaseModel):
    file_hash: str = Field(..., min_length=32, max_length=64, description="SHA256 (64 chars), SHA1 (40 chars), or MD5 (32 chars)")
    use_cache: bool = True
    
    @validator('file_hash')
    def validate_hash(cls, v):
        # Validate hash format: should be hex string
        if not re.match(r'^[a-fA-F0-9]{32,64}$', v):
            raise ValueError("Invalid hash format. Must be SHA256 (64 chars), SHA1 (40 chars), or MD5 (32 chars)")
        return v.lower()  # Normalize to lowercase

class SigmaScanResult(BaseModel):
    total_events: int
    matches: List[Dict[str, Any]]

@router.post("/events", response_model=SigmaScanResult)
async def scan_events(
    request: SigmaScanRequest,
    engine: SigmaEngine = Depends(get_sigma_engine),
    db: Session = Depends(get_db)
):
    """
    Scan a list of events (dicts) against Sigma rules.
    Maximum 10000 events per request to prevent performance issues.
    """
    try:
        # Validate events are dictionaries
        for i, event in enumerate(request.events):
            if not isinstance(event, dict):
                raise HTTPException(
                    status_code=400, 
                    detail=f"Event at index {i} must be a dictionary, got {type(event).__name__}"
                )
        
        results = engine.scan_events(request.events)
        
        # Save to DB
        is_malicious = len(results) > 0
        threat_level = ThreatLevel.CLEAN
        if is_malicious:
            threat_level = ThreatLevel.SUSPICIOUS
            # Simple heuristic for threat level
            for match in results:
                for m in match.get("matches", []):
                    if m.get("level") == "critical":
                        threat_level = ThreatLevel.CRITICAL
                    elif m.get("level") == "high" and threat_level != ThreatLevel.CRITICAL:
                        threat_level = ThreatLevel.MALICIOUS
        
        task_id = str(uuid.uuid4())
        db_task = ScanTask(
            task_id=task_id,
            target_path="Manual Events Input",
            target_type="events",
            scan_type="dynamic",
            status=ScanStatus.COMPLETED,
            progress=100.0,
            total_files=1,
            scanned_files=1,
            detected_files=1 if is_malicious else 0,
            started_at=datetime.now(),
            completed_at=datetime.now()
        )
        db.add(db_task)
        db.commit()
        db.refresh(db_task)
        
        matched_rule_names = []
        for match in results:
            for m in match.get("matches", []):
                matched_rule_names.append(m.get("title", "Unknown"))
                
        db_result = ScanResult(
            task_id=db_task.id,
            file_path="events.json",
            file_name="events.json",
            file_size=len(str(request.events)),
            file_hash="manual_input",
            threat_level=threat_level,
            is_malicious=is_malicious,
            matched_rules=str(matched_rule_names)
        )
        db.add(db_result)
        db.commit()

        return {
            "total_events": len(request.events),
            "matches": results
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Event scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.post("/file")
async def scan_log_file(
    file: UploadFile = File(...),
    engine: SigmaEngine = Depends(get_sigma_engine),
    db: Session = Depends(get_db)
):
    """
    Scan an uploaded log file (JSON, JSONL, YAML).
    Maximum file size: 100MB to prevent memory issues.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    # Check file size before reading
    if file.size and file.size > settings.MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413, 
            detail=f"File too large. Maximum size: {settings.MAX_FILE_SIZE / (1024*1024):.0f}MB"
        )
    
    content = await file.read()
    file_size = len(content)
    file_hash = hashlib.sha256(content).hexdigest()
    
    # Double-check content size
    if len(content) > settings.MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413, 
            detail=f"File too large. Maximum size: {settings.MAX_FILE_SIZE / (1024*1024):.0f}MB"
        )
    
    events = []
    filename = file.filename or "unknown"
    
    # Sanitize filename
    filename = os.path.basename(filename)
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    try:
        if filename.lower().endswith('.json'):
            try:
                # Try parsing as list of dicts
                events = json.loads(content)
                if not isinstance(events, list):
                    # Maybe it's a single dict
                    events = [events]
            except json.JSONDecodeError:
                # Try JSONL
                events = []
                for line_num, line in enumerate(content.decode('utf-8', errors='replace').splitlines(), 1):
                    if line.strip():
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse JSONL line {line_num}: {e}")
                            # Skip invalid lines but continue processing
                            continue
                        
        elif filename.lower().endswith(('.yml', '.yaml')):
            try:
                data = yaml.safe_load(content)
                if data is None:
                    events = []
                elif isinstance(data, list):
                    events = data
                else:
                    events = [data]
            except yaml.YAMLError as e:
                raise HTTPException(status_code=400, detail=f"Invalid YAML format: {str(e)}")
        else:
            # Treat as text lines, wrap in simple event
            lines = content.decode('utf-8', errors='replace').splitlines()
            events = [{"message": line} for line in lines if line.strip()]
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File parsing failed: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Failed to parse file: {str(e)}")
    
    # Limit number of events to prevent performance issues
    MAX_EVENTS = 50000
    if len(events) > MAX_EVENTS:
        logger.warning(f"File contains {len(events)} events, limiting to {MAX_EVENTS}")
        events = events[:MAX_EVENTS]
        
    if not events:
        return {
            "filename": filename,
            "total_events": 0,
            "matches_count": 0,
            "matches": []
        }
    
    # Validate events are dictionaries
    validated_events = []
    for i, event in enumerate(events):
        if not isinstance(event, dict):
            logger.warning(f"Skipping invalid event at index {i}: not a dictionary")
            continue
        validated_events.append(event)
    
    if not validated_events:
        raise HTTPException(status_code=400, detail="No valid events found in file")
        
    try:
        results = engine.scan_events(validated_events)
        
        # Save to DB
        is_malicious = len(results) > 0
        threat_level = ThreatLevel.CLEAN
        if is_malicious:
            threat_level = ThreatLevel.SUSPICIOUS
            for match in results:
                for m in match.get("matches", []):
                    if m.get("level") == "critical":
                        threat_level = ThreatLevel.CRITICAL
                    elif m.get("level") == "high" and threat_level != ThreatLevel.CRITICAL:
                        threat_level = ThreatLevel.MALICIOUS
        
        task_id = str(uuid.uuid4())
        db_task = ScanTask(
            task_id=task_id,
            target_path=filename,
            target_type="file",
            scan_type="dynamic",
            status=ScanStatus.COMPLETED,
            progress=100.0,
            total_files=1,
            scanned_files=1,
            detected_files=1 if is_malicious else 0,
            started_at=datetime.now(),
            completed_at=datetime.now()
        )
        db.add(db_task)
        db.commit()
        db.refresh(db_task)
        
        matched_rule_names = []
        for match in results:
            for m in match.get("matches", []):
                matched_rule_names.append(m.get("title", "Unknown"))
                
        db_result = ScanResult(
            task_id=db_task.id,
            file_path=filename,
            file_name=filename,
            file_size=file_size,
            file_hash=file_hash,
            threat_level=threat_level,
            is_malicious=is_malicious,
            matched_rules=str(matched_rule_names)
        )
        db.add(db_result)
        db.commit()
        
    except Exception as e:
        logger.error(f"Sigma scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    
    return {
        "filename": filename,
        "total_events": len(validated_events),
        "matches_count": len(results),
        "matches": results,
        "task_id": task_id
    }

@router.post("/reload")
async def reload_rules(engine: SigmaEngine = Depends(get_sigma_engine)):
    """
    Reload Sigma rules from disk.
    """
    engine.reload_rules()
    return {"message": f"Rules reloaded. Active rules: {len(engine.rules)}"}


@router.post("/virustotal", response_model=SigmaScanResult)
async def scan_with_virustotal(
    request: VirusTotalScanRequest,
    engine: SigmaEngine = Depends(get_sigma_engine),
    db: Session = Depends(get_db)
):
    """
    使用 VirusTotal 公共 API 获取沙箱行为（process/file/registry/network），
    然后在本地运行 Sigma 规则匹配。
    需要有效的 VirusTotal API 密钥。
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        behaviour = vt_client.fetch_behaviour_summary(request.file_hash, use_cache=request.use_cache)
        if not behaviour:
            raise HTTPException(
                status_code=404,
                detail="VirusTotal behaviour data not found or not accessible for this hash. "
                       "The file may not have been analyzed by VirusTotal, or the API key may be invalid.",
            )

        events = vt_client.normalize_behaviour(behaviour)
        if not events:
            # Return empty result if no events were extracted
            return {
                "total_events": 0,
                "matches": [],
            }
        
        # Limit events to prevent performance issues
        MAX_EVENTS = 50000
        if len(events) > MAX_EVENTS:
            logger.warning(f"VT returned {len(events)} events, limiting to {MAX_EVENTS}")
            events = events[:MAX_EVENTS]
        
        results = engine.scan_events(events)
        
        # Save to DB
        is_malicious = len(results) > 0
        threat_level = ThreatLevel.CLEAN
        if is_malicious:
            threat_level = ThreatLevel.SUSPICIOUS
            for match in results:
                for m in match.get("matches", []):
                    if m.get("level") == "critical":
                        threat_level = ThreatLevel.CRITICAL
                    elif m.get("level") == "high" and threat_level != ThreatLevel.CRITICAL:
                        threat_level = ThreatLevel.MALICIOUS
        
        task_id = str(uuid.uuid4())
        db_task = ScanTask(
            task_id=task_id,
            target_path=f"VT:{request.file_hash}",
            target_type="virustotal",
            scan_type="dynamic",
            status=ScanStatus.COMPLETED,
            progress=100.0,
            total_files=1,
            scanned_files=1,
            detected_files=1 if is_malicious else 0,
            started_at=datetime.now(),
            completed_at=datetime.now()
        )
        db.add(db_task)
        db.commit()
        db.refresh(db_task)
        
        matched_rule_names = []
        for match in results:
            for m in match.get("matches", []):
                matched_rule_names.append(m.get("title", "Unknown"))
                
        db_result = ScanResult(
            task_id=db_task.id,
            file_path=request.file_hash,
            file_name=f"VT:{request.file_hash}",
            file_size=0,
            file_hash=request.file_hash,
            threat_level=threat_level,
            is_malicious=is_malicious,
            matched_rules=str(matched_rule_names)
        )
        db.add(db_result)
        db.commit()

        return {
            "total_events": len(events),
            "matches": results,
        }
    except HTTPException:
        raise
    except RuntimeError as e:
        # Handle VT API errors
        logger.error(f"VirusTotal API error: {e}")
        raise HTTPException(
            status_code=503,
            detail=f"VirusTotal API error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"VirusTotal scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/dynamic")
async def dynamic_scan(
    file: UploadFile = File(...),
    engine: SigmaEngine = Depends(get_sigma_engine),
    db: Session = Depends(get_db)
):
    """
    Upload an executable and perform safe static analysis.
    This method does NOT execute files - it only extracts strings and generates simulated events.
    Maximum file size: 100MB.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    # Validate file extension
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    
    filename = os.path.basename(file.filename)
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)  # Sanitize filename
    
    if not filename.lower().endswith(('.exe', '.bat', '.ps1', '.cmd', '.dll', '.scr')):
        raise HTTPException(
            status_code=400, 
            detail="Only executable files supported (.exe, .bat, .ps1, .cmd, .dll, .scr)"
        )

    # Check file size before reading
    if file.size and file.size > settings.MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413, 
            detail=f"File too large. Maximum size: {settings.MAX_FILE_SIZE / (1024*1024):.0f}MB"
        )

    # Save to temp file
    file_size = 0
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}") as tmp:
            content = await file.read()
            file_size = len(content)
            
            # Double-check content size
            if file_size > settings.MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=413, 
                    detail=f"File too large. Maximum size: {settings.MAX_FILE_SIZE / (1024*1024):.0f}MB"
                )
            
            tmp.write(content)
            tmp_path = tmp.name
        
        # Calculate file hash for tracking
        file_hash = hashlib.sha256(content).hexdigest()
            
        # Run safe static analysis (only string extraction, no execution)
        events = await dynamic_analyzer.analyze_file(tmp_path)
        
        # Scan captured events
        results = engine.scan_events(events) if events else []
        
        # Persist to DB
        is_malicious = len(results) > 0
        threat_level = ThreatLevel.CLEAN
        
        # Determine max threat level from matched rules
        if is_malicious:
            threat_level = ThreatLevel.SUSPICIOUS  # Default
            for match in results:
                # Extract level from matches structure
                match_data = match.get("matches", [])
                if match_data:
                    for rule_match in match_data:
                        lvl = rule_match.get("level", "medium")
                        if lvl == "critical":
                            threat_level = ThreatLevel.CRITICAL
                            break
                        elif lvl == "high":
                            threat_level = ThreatLevel.MALICIOUS
                        elif lvl == "medium" and threat_level not in [ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL]:
                            threat_level = ThreatLevel.SUSPICIOUS
                    if threat_level == ThreatLevel.CRITICAL:
                        break

        # Create Task Record
        task_id = str(uuid.uuid4())
        db_task = ScanTask(
            task_id=task_id,
            target_path=filename,
            target_type="file",
            scan_type="dynamic",  # Mark as dynamic scan
            status=ScanStatus.COMPLETED,
            progress=100.0,
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
        matched_rule_names = []
        for match in results:
            match_data = match.get("matches", [])
            for rule_match in match_data:
                matched_rule_names.append(rule_match.get("title", "Unknown"))
        
        db_result = ScanResult(
            task_id=db_task.id,
            file_path=filename,
            file_name=filename,
            file_size=file_size,
            file_hash=file_hash,
            threat_level=threat_level,
            is_malicious=is_malicious,
            matched_rules=str(matched_rule_names) if matched_rule_names else ""
        )
        db.add(db_result)
        db.commit()

        return {
            "filename": filename,
            "mode": "simulated_sandbox",
            "total_events": len(events),
            "matches_count": len(results),
            "captured_events_preview": events[:5] if events else [],  # Show first 5 events for debug
            "matches": results,
            "task_id": task_id,  # Return task ID so frontend can link if needed
            "file_hash": file_hash
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Dynamic scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Dynamic scan failed: {str(e)}")
    finally:
        # Ensure cleanup of temp file
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception as e:
                logger.warning(f"Failed to delete temp file {tmp_path}: {e}")
