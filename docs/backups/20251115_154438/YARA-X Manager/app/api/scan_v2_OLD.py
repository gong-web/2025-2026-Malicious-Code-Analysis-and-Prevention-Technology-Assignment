from fastapi import APIRouter, UploadFile, HTTPException, File, Depends
from fastapi.responses import JSONResponse
from typing import List
from sqlalchemy.orm import Session
from app.db import get_db
from app.sql_models import Sample, Scan, Rule
from app.tasks import download_and_register, run_scan
from pathlib import Path
import shutil

# 新的扫描API，兼容前端需求
router = APIRouter(prefix="/scan", tags=["scan"])

@router.post("/file")
async def scan_single_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    上传并立即扫描单个文件
    """
    try:
        # 保存文件
        data = await file.read()
        
        # 直接保存样本
        from app.storage import save_sample
        import hashlib
        
        sample_hash = hashlib.sha256(data).hexdigest()
        sample_path = save_sample(data, file.filename)
        
        # 创建样本记录
        sample = Sample(
            filename=file.filename,
            path=str(sample_path)
        )
        db.add(sample)
        db.commit()
        db.refresh(sample)
        sample_id = sample.id
        
        # 获取所有活动规则
        rules = db.query(Rule).filter(Rule.active == True).all()
        if not rules:
            return {
                "task_id": str(sample_id),
                "filename": file.filename,
                "hash": sample_hash,
                "is_malicious": False,
                "matches": [],
                "message": "No active rules to scan with"
            }
        
        rule_paths = [r.path for r in rules]
        
        # 使用Python yara库进行扫描
        from datetime import datetime, timezone
        import json
        import yara
        import os
        
        matches = []
        debug_log = []
        try:
            # 去重规则路径并编译
            unique_rule_paths = list(set([os.path.normpath(p) for p in rule_paths if os.path.exists(p)]))
            
            debug_log.append(f"Found {len(unique_rule_paths)} unique valid rules from {len(rule_paths)} total")
            debug_log.append(f"Sample file path: {sample_path}")
            debug_log.append(f"File exists: {os.path.exists(str(sample_path))}")
            debug_log.append(f"File size: {os.path.getsize(str(sample_path)) if os.path.exists(str(sample_path)) else 'N/A'}")
            
            for msg in debug_log:
                print(f"[SCAN DEBUG] {msg}")
            
            if unique_rule_paths:
                # 构建规则字典，使用文件名作为命名空间
                rules_dict = {}
                for rule_path in unique_rule_paths:
                    # 使用文件名（不带扩展名）作为唯一标识
                    namespace = os.path.splitext(os.path.basename(rule_path))[0]
                    # 如果命名空间已存在，添加路径hash确保唯一性
                    if namespace in rules_dict:
                        namespace = f"{namespace}_{abs(hash(rule_path)) % 10000}"
                    rules_dict[namespace] = rule_path
                
                print(f"[SCAN DEBUG] Compiling {len(rules_dict)} rules: {list(rules_dict.keys())[:5]}...")
                print(f"[SCAN DEBUG] First 3 rule paths: {list(rules_dict.values())[:3]}")
                
                # 验证每个规则文件是否可读
                for namespace, path in list(rules_dict.items())[:3]:
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            print(f"[SCAN DEBUG] Rule {namespace}: {len(content)} bytes, contains 'rule': {'rule ' in content}")
                    except Exception as e:
                        print(f"[SCAN DEBUG] Error reading {namespace}: {e}")
                
                compiled_rules = yara.compile(filepaths=rules_dict)
                print(f"[SCAN DEBUG] Rules compiled successfully")
                
                # 扫描文件
                scan_path_str = str(sample_path)
                print(f"[SCAN DEBUG] Starting YARA match on {scan_path_str}")
                print(f"[SCAN DEBUG] File exists before scan: {os.path.exists(scan_path_str)}")
                print(f"[SCAN DEBUG] File size before scan: {os.path.getsize(scan_path_str) if os.path.exists(scan_path_str) else 'N/A'}")
                
                # 测试一个已知有效的规则
                test_rule_content = """
                rule TestRule {
                    strings:
                        $test = "MZ"
                    condition:
                        $test at 0
                }
                """
                test_rules = yara.compile(source=test_rule_content)
                test_matches = test_rules.match(scan_path_str)
                print(f"[SCAN DEBUG] Test rule (MZ at 0) matched: {len(test_matches) > 0}")
                
                yara_matches = compiled_rules.match(scan_path_str)
                print(f"[SCAN DEBUG] Scan complete. Found {len(yara_matches)} matches")
                
                if len(yara_matches) == 0:
                    print(f"[SCAN DEBUG] No matches! Compiled rules count: {len(rules_dict)}")
                    print(f"[SCAN DEBUG] Sample exists: {os.path.exists(scan_path_str)}")
                    print(f"[SCAN DEBUG] Sample size: {os.path.getsize(scan_path_str)}")
                
                # 转换匹配结果 - 包含完整的元数据和匹配字符串
                for match in yara_matches:
                    print(f"[SCAN DEBUG] Match: {match.rule}")
                    print(f"[SCAN DEBUG] Meta: {dict(match.meta)}")
                    print(f"[SCAN DEBUG] Tags: {list(match.tags)}")
                    print(f"[SCAN DEBUG] Namespace: {match.namespace}")
                    
                    # 提取匹配的字符串信息
                    matched_strings = []
                    for string_match in match.strings:
                        matched_strings.append({
                            "identifier": string_match.identifier,
                            "instances": [
                                {
                                    "offset": instance[0],
                                    "length": instance[1],
                                    "matched_data": instance[2].decode('utf-8', errors='ignore')[:100]  # 前100字符
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
        except Exception as e:
            error_msg = f"YARA scan error: {e}"
            print(error_msg)
            debug_log.append(error_msg)
            import traceback
            traceback.print_exc()
            debug_log.append(traceback.format_exc())
        
        scan_result = {
            "matches": matches,
            "hash": sample_hash,
            "scanned_with": len(rule_paths),
            "engine": "yara-python"
        }
        
        # 创建扫描记录
        scan = Scan(
            filename=file.filename,
            status="done",
            result=json.dumps(scan_result),
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=datetime.now(timezone.utc).isoformat()
        )
        db.add(scan)
        db.commit()
        
        is_malicious = len(matches) > 0
        
        # 保存调试日志到数据库或返回给前端
        result = {
            "task_id": str(sample_id),
            "filename": file.filename,
            "hash": sample_hash,
            "is_malicious": is_malicious,
            "matches": matches,
            "status": "completed",
            "scanned_rules": len(rule_paths),
            "debug_log": debug_log  # 总是返回调试信息
        }
        
        print(f"[SCAN RESULT] is_malicious={is_malicious}, matches={len(matches)}, debug_log_lines={len(debug_log)}")
        
        return result
        
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        raise HTTPException(500, f"Scan failed: {str(e)}\n{error_detail}")

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
                import json
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
