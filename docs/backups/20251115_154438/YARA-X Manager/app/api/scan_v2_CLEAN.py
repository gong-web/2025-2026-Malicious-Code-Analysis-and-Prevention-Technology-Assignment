from fastapi import APIRouter, UploadFile, HTTPException, File, Depends
from fastapi.responses import JSONResponse
from typing import List
from sqlalchemy.orm import Session
from app.db import get_db
from app.sql_models import Sample, Scan, Rule
from pathlib import Path
import os
import json
from datetime import datetime, timezone
import yara
import hashlib

# 新的扫描API，兼容前端需求
router = APIRouter(prefix="/scan", tags=["scan"])

@router.post("/file")
async def scan_single_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    上传并立即扫描单个文件
    """
    debug_log = []
    matches = []
    
    try:
        # 1. 读取文件数据
        data = await file.read()
        sample_hash = hashlib.sha256(data).hexdigest()
        debug_log.append(f"File uploaded: {file.filename}, SHA256: {sample_hash}")
        
        # 2. 保存样本文件
        from app.storage import save_sample
        sample_path = save_sample(data, file.filename)
        debug_log.append(f"Sample saved to: {sample_path}")
        debug_log.append(f"File exists: {os.path.exists(str(sample_path))}")
        debug_log.append(f"File size: {os.path.getsize(str(sample_path))} bytes")
        
        # 3. 创建样本记录
        sample = Sample(
            filename=file.filename,
            path=str(sample_path)
        )
        db.add(sample)
        db.commit()
        db.refresh(sample)
        sample_id = sample.id
        debug_log.append(f"Sample DB record created: ID={sample_id}")
        
        # 4. 获取所有活动规则
        rules = db.query(Rule).filter(Rule.active == True).all()
        debug_log.append(f"Found {len(rules)} active rules")
        
        if not rules:
            return {
                "task_id": str(sample_id),
                "filename": file.filename,
                "hash": sample_hash,
                "is_malicious": False,
                "matches": [],
                "message": "No active rules to scan with",
                "debug_log": debug_log
            }
        
        # 5. 准备规则路径并去重
        rule_paths = [r.path for r in rules]
        unique_rule_paths = []
        seen_paths = set()
        
        for path in rule_paths:
            normalized_path = os.path.normpath(path)
            if normalized_path not in seen_paths and os.path.exists(normalized_path):
                unique_rule_paths.append(normalized_path)
                seen_paths.add(normalized_path)
        
        debug_log.append(f"Unique valid rule paths: {len(unique_rule_paths)}")
        
        if not unique_rule_paths:
            debug_log.append("ERROR: No valid rule files found!")
            return {
                "task_id": str(sample_id),
                "filename": file.filename,
                "hash": sample_hash,
                "is_malicious": False,
                "matches": [],
                "message": "No valid rule files",
                "debug_log": debug_log
            }
        
        # 6. 构建规则字典
        rules_dict = {}
        for idx, rule_path in enumerate(unique_rule_paths):
            # 使用文件名作为命名空间，确保唯一
            namespace = os.path.splitext(os.path.basename(rule_path))[0]
            if namespace in rules_dict:
                namespace = f"{namespace}_{idx}"
            rules_dict[namespace] = rule_path
        
        debug_log.append(f"Rules dict keys (first 5): {list(rules_dict.keys())[:5]}")
        
        # 7. 编译YARA规则
        try:
            compiled_rules = yara.compile(filepaths=rules_dict)
            debug_log.append("YARA rules compiled successfully")
        except Exception as compile_error:
            error_msg = f"YARA compile error: {compile_error}"
            debug_log.append(error_msg)
            print(error_msg)
            return {
                "task_id": str(sample_id),
                "filename": file.filename,
                "hash": sample_hash,
                "is_malicious": False,
                "matches": [],
                "message": "Rule compilation failed",
                "debug_log": debug_log
            }
        
        # 8. 扫描文件
        try:
            scan_path_str = str(sample_path)
            debug_log.append(f"Starting YARA scan on: {scan_path_str}")
            
            yara_matches = compiled_rules.match(scan_path_str)
            debug_log.append(f"YARA scan completed. Found {len(yara_matches)} matches")
            
            # 9. 处理匹配结果
            for match in yara_matches:
                debug_log.append(f"Match: {match.rule} (namespace: {match.namespace})")
                
                # 提取匹配的字符串信息
                matched_strings = []
                for string_match in match.strings:
                    matched_strings.append({
                        "identifier": string_match.identifier,
                        "instances": [
                            {
                                "offset": instance[0],
                                "length": instance[1],
                                "matched_data": instance[2].decode('utf-8', errors='ignore')[:100]
                            }
                            for instance in string_match.instances
                        ]
                    })
                
                matches.append({
                    "rule": match.rule,
                    "namespace": match.namespace if match.namespace else "default",
                    "tags": list(match.tags) if match.tags else [],
                    "meta": dict(match.meta) if match.meta else {},
                    "strings": matched_strings
                })
                
        except Exception as scan_error:
            error_msg = f"YARA scan error: {scan_error}"
            debug_log.append(error_msg)
            print(error_msg)
            import traceback
            traceback.print_exc()
        
        # 10. 保存扫描结果到数据库
        scan_result = {
            "matches": matches,
            "hash": sample_hash,
            "scanned_with": len(unique_rule_paths),
            "engine": "yara-python"
        }
        
        scan = Scan(
            filename=file.filename,
            status="done",
            result=json.dumps(scan_result),
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=datetime.now(timezone.utc).isoformat()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        is_malicious = len(matches) > 0
        debug_log.append(f"Scan completed: is_malicious={is_malicious}, matches={len(matches)}")
        
        # 打印调试日志
        for msg in debug_log:
            print(f"[SCAN] {msg}")
        
        # 11. 返回结果
        return {
            "task_id": str(sample_id),
            "scan_id": scan.id,
            "filename": file.filename,
            "hash": sample_hash,
            "is_malicious": is_malicious,
            "matches": matches,
            "status": "completed",
            "scanned_rules": len(unique_rule_paths),
            "debug_log": debug_log
        }
        
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        debug_log.append(error_msg)
        print(error_msg)
        import traceback
        traceback.print_exc()
        
        raise HTTPException(500, {
            "message": f"Scan failed: {str(e)}",
            "debug_log": debug_log
        })

@router.get("/")
async def list_scans(db: Session = Depends(get_db)):
    """
    获取所有扫描任务列表
    """
    scans = db.query(Scan).all()
    return [
        {
            "task_id": str(s.id),
            "target_path": s.filename,
            "scan_type": "file",
            "status": s.status,
            "detected_files": 1 if s.result and "matches" in s.result else 0,
            "created_at": s.started_at,
            "completed_at": s.finished_at
        }
        for s in scans
    ]

@router.get("/{task_id}/results")
async def get_scan_results(task_id: str, db: Session = Depends(get_db)):
    """
    获取扫描结果详情
    """
    try:
        scan_id = int(task_id)
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        
        if not scan:
            raise HTTPException(404, "scan not found")
        
        results = []
        if scan.result:
            try:
                result_data = json.loads(scan.result)
                matches = result_data.get('matches', [])
                for match in matches:
                    results.append({
                        "file_path": scan.filename,
                        "rule_name": match.get('rule', 'unknown'),
                        "severity": "high",
                        "description": f"Matched rule: {match.get('rule', 'unknown')}"
                    })
            except:
                pass
        
        return results
        
    except ValueError:
        raise HTTPException(400, "invalid task_id")

@router.delete("/{task_id}")
async def delete_scan(task_id: str, db: Session = Depends(get_db)):
    """
    删除扫描任务
    """
    try:
        scan_id = int(task_id)
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        
        if not scan:
            raise HTTPException(404, "scan not found")
        
        db.delete(scan)
        db.commit()
        
        return {"message": "Scan deleted successfully"}
        
    except ValueError:
        raise HTTPException(400, "invalid task_id")
