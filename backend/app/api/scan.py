"""
扫描任务 API - 适配 data.sqlite 数据库
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db
from app.api.models_shared import Rule, Sample, Scan
from app.models.rule import SigmaRule, RuleStatus
import hashlib
import os
import json
import yara
import yaml
from datetime import datetime
from pathlib import Path

from app.core.yara_ext import get_default_externals, build_externals
from app.core.yara_cache import get_cache_path, try_load, save
from app.core.config import settings
from app.core.sigma_engine import compile_sigma_rule
from app.core.event_normalizer import normalize_events
from app.core.log_parser import parse_text_to_events

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
        # 根据文件类型对规则进行简单筛选，减少无关模块编译
        is_pe = len(content) >= 2 and content[0:2] == b"MZ"
        is_elf = len(content) >= 4 and content[0:4] == b"\x7fELF"
        filtered_sources = {}
        for name, src in rule_sources.items():
            try:
                if 'import "pe"' in src and not is_pe:
                    continue
                if 'import "elf"' in src and not is_elf:
                    continue
                filtered_sources[name] = src
            except Exception:
                filtered_sources[name] = src

        group_key = "pe" if is_pe else ("elf" if is_elf else "generic")
        cache_path = get_cache_path(Path(settings.YARA_COMPILED_DIR), group_key, filtered_sources)
        compiled_rules = try_load(cache_path)
        if compiled_rules is None:
            try:
                print(f"[SCAN] 编译 {len(filtered_sources)} 条规则...")
                compiled_rules = yara.compile(
                    sources=filtered_sources,
                    externals=get_default_externals(),
                )
                try:
                    save(compiled_rules, cache_path)
                except Exception:
                    pass
            except Exception:
                print("[SCAN] 规则筛选编译失败，回退到全量规则...")
                compiled_rules = yara.compile(
                    sources=rule_sources,
                    externals=get_default_externals(),
                )
        
        print(f"[SCAN] 扫描文件: {file.filename} ({len(content)} 字节)")
        matches = compiled_rules.match(
            data=content,
            externals=build_externals(
                filename=file.filename,
                filepath=sample_path,
                data=content,
            ),
        )
        
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
        "scanned_rules": len(filtered_sources)
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


@router.post("/events")
async def scan_events(file: UploadFile = File(...), db: Session = Depends(get_db)):
    raw = (await file.read()).decode("utf-8", errors="ignore")
    events = []
    try:
        if raw.strip().startswith("["):
            import json as _json
            events = _json.loads(raw)
        else:
            events = [__import__("json").loads(line) for line in raw.splitlines() if line.strip()]
    except Exception:
        raise HTTPException(status_code=400, detail="JSON 格式错误，请提供 JSON 数组或 NDJSON")

    # 规范化事件字段，提升规则命中率
    events = normalize_events(events)

    rules = db.query(SigmaRule).filter(SigmaRule.rule_status == RuleStatus.ACTIVE).all()
    compiled = []
    for r in rules:
        try:
            compiled.append(compile_sigma_rule(r.content))
        except Exception:
            continue

    matches = []
    for cr in compiled:
        hit_idx = []
        for idx, ev in enumerate(events):
            try:
                if cr.match_event(ev):
                    hit_idx.append(idx)
            except Exception:
                continue
        if hit_idx:
            matches.append({
                "rule": cr.name,
                "rule_id": cr.rule_id,
                "count": len(hit_idx),
                "event_indexes": hit_idx[:50]
            })

    started_at = datetime.now().isoformat()
    finished_at = datetime.now().isoformat()
    result_data = {
        "is_malicious": len(matches) > 0,
        "matches": matches,
        "scanned_rules": len(compiled)
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
        "is_malicious": result_data["is_malicious"],
        "status": "done",
        "matches": matches,
        "match_count": len(matches),
        "scanned_rules": len(compiled),
        "started_at": started_at,
        "finished_at": finished_at
    }


@router.post("/logs")
async def scan_logs(file: UploadFile = File(...), db: Session = Depends(get_db)):
    text = (await file.read()).decode("utf-8", errors="ignore")
    lines = [l.strip() for l in text.splitlines() if l.strip()]

    rules = db.query(SigmaRule).filter(SigmaRule.rule_status == RuleStatus.ACTIVE).all()
    if not rules:
        raise HTTPException(status_code=400, detail="当前没有活动的Sigma规则")

    matches = []
    for r in rules:
        try:
            data = yaml.safe_load(r.content)
            detection = data.get("detection", {})
            cond = detection.get("condition", "")
            keywords = detection.get("keywords", [])
            hit_lines = []
            if keywords and cond.strip() == "keywords":
                kw = [str(k).lower() for k in keywords]
                for idx, line in enumerate(lines):
                    low = line.lower()
                    if any(k in low for k in kw):
                        hit_lines.append({"line_no": idx + 1, "text": line})
            if hit_lines:
                matches.append({
                    "rule": r.title or r.name,
                    "rule_id": r.rule_id or "",
                    "count": len(hit_lines),
                    "lines": hit_lines[:25]
                })
        except Exception:
            continue

    events = parse_text_to_events(text)
    events = normalize_events(events)

    compiled = []
    for r in rules:
        try:
            compiled.append(compile_sigma_rule(r.content))
        except Exception:
            continue

    for cr in compiled:
        hit_idx = []
        for idx, ev in enumerate(events):
            try:
                if cr.match_event(ev):
                    hit_idx.append(idx)
            except Exception:
                continue
        if hit_idx:
            matches.append({
                "rule": cr.name,
                "rule_id": cr.rule_id,
                "count": len(hit_idx),
                "event_indexes": hit_idx[:50]
            })

    started_at = datetime.now().isoformat()
    finished_at = datetime.now().isoformat()
    result_data = {
        "is_malicious": len(matches) > 0,
        "matches": matches,
        "scanned_rules": len(rules)
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
        "is_malicious": result_data["is_malicious"],
        "status": "done",
        "matches": matches,
        "match_count": len(matches),
        "scanned_rules": len(rules),
        "started_at": started_at,
        "finished_at": finished_at
    }


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
