"""
扫描任务 API - 适配 data.sqlite 数据库
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db
from app.api.models_shared import Rule, Sample, Scan
from pydantic import BaseModel
import hashlib
import os
import json
import yara
from datetime import datetime
from pathlib import Path

router = APIRouter()

# 样本目录
SAMPLES_DIR = Path("data/samples")
SAMPLES_DIR.mkdir(parents=True, exist_ok=True)


@router.post("/file")
async def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """扫描上传的文件"""
    
    # 读取文件
    content = await file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    
    # 保存样本
    sample_path = SAMPLES_DIR / f"{file_hash}_{file.filename}"
    with open(sample_path, 'wb') as f:
        f.write(content)
    
    # 检查samples表是否已存在
    existing_sample = db.query(Sample).filter(Sample.filename == file.filename).first()
    if not existing_sample:
        new_sample = Sample(
            filename=file.filename,
            path=str(sample_path)
        )
        db.add(new_sample)
        db.commit()
    
    # 获取所有活动规则
    rules = db.query(Rule).filter(Rule.active == True).all()
    
    if not rules:
        # 查询总规则数
        from sqlalchemy import func
        total_rules = db.query(func.count(Rule.id)).scalar()
        raise HTTPException(
            status_code=400,
            detail=f"当前没有活动的YARA规则 (共 {total_rules} 条规则，全部禁用)。请先在规则管理中启用至少一个规则。"
        )
    
    # 编译规则
    rule_sources = {}
    for rule in rules:
        if os.path.exists(rule.path):
            try:
                with open(rule.path, 'r', encoding='utf-8') as f:
                    rule_sources[rule.name] = f.read()
            except Exception as e:
                print(f"[WARNING] 无法读取规则 {rule.name}: {e}")
                continue
        else:
            print(f"[WARNING] 规则文件不存在: {rule.path}")
    
    if not rule_sources:
        raise HTTPException(
            status_code=500,
            detail=f"无法加载任何YARA规则文件 (找到 {len(rules)} 条活动规则，但文件不存在或读取失败)"
        )
    
    # 执行扫描
    try:
        print(f"[SCAN] 编译 {len(rule_sources)} 条规则...")
        compiled_rules = yara.compile(sources=rule_sources)
        
        print(f"[SCAN] 扫描文件: {file.filename} ({len(content)} 字节)")
        matches = compiled_rules.match(data=content)
        
        print(f"[SCAN] 完成扫描，匹配 {len(matches)} 条规则")
    except Exception as e:
        print(f"[SCAN ERROR] {type(e).__name__}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"YARA扫描失败: {str(e)}")
    
    # 处理匹配结果
    match_list = []
    for match in matches:
        match_info = {
            "rule": match.rule,
            "namespace": match.namespace or "",
            "tags": list(match.tags) if match.tags else [],
            "meta": dict(match.meta) if match.meta else {},
            "strings": [
                {
                    "identifier": s.identifier,
                    "instances": len(s.instances)
                } for s in match.strings
            ]
        }
        match_list.append(match_info)
    
    is_malicious = len(match_list) > 0
    
    # 保存扫描记录
    started_at = datetime.now().isoformat()
    finished_at = datetime.now().isoformat()
    
    result_data = {
        "is_malicious": is_malicious,
        "matches": match_list,
        "sample_hash": file_hash,
        "scanned_rules": len(rule_sources)
    }
    
    new_scan = Scan(
        filename=file.filename,
        status="done",
        result=json.dumps(result_data),
        started_at=started_at,
        finished_at=finished_at
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    return {
        "scan_id": new_scan.id,
        "filename": file.filename,
        "file_hash": file_hash,
        "is_malicious": is_malicious,
        "threat_level": "malicious" if is_malicious else "clean",
        "status": "done",
        "matches": match_list,
        "match_count": len(match_list),
        "scanned_rules": len(rule_sources),
        "started_at": started_at,
        "finished_at": finished_at
    }


@router.get("/samples")
async def list_samples(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """获取样本列表"""
    samples = db.query(Sample).offset(skip).limit(limit).all()
    
    result = []
    for sample in samples:
        file_exists = os.path.exists(sample.path)
        file_size = os.path.getsize(sample.path) if file_exists else 0
        
        result.append({
            "id": sample.id,
            "filename": sample.filename,
            "path": sample.path,
            "file_exists": file_exists,
            "file_size": file_size
        })
    
    return result


@router.delete("/samples/{sample_id}")
async def delete_sample(sample_id: int, db: Session = Depends(get_db)):
    """删除样本"""
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample:
        raise HTTPException(status_code=404, detail="样本未找到")
    
    # 删除文件
    if os.path.exists(sample.path):
        try:
            os.remove(sample.path)
        except:
            pass
    
    db.delete(sample)
    db.commit()
    
    return {"message": "样本已删除"}


@router.get("/scans")
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """获取扫描记录列表"""
    scans = db.query(Scan).order_by(Scan.id.desc()).offset(skip).limit(limit).all()
    
    result = []
    for scan in scans:
        result_data = json.loads(scan.result) if scan.result else {}
        result.append({
            "id": scan.id,
            "filename": scan.filename,
            "status": scan.status,
            "is_malicious": result_data.get("is_malicious", False),
            "match_count": len(result_data.get("matches", [])),
            "started_at": scan.started_at,
            "finished_at": scan.finished_at
        })
    
    return result
