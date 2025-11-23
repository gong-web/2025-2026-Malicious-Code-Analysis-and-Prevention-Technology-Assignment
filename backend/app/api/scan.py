"""
扫描任务 API
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db
from app.models.scan import ScanTask, ScanResult, ScanStatus, ThreatLevel
from app.models.rule import YaraRule
from pydantic import BaseModel
import uuid
import yara
import hashlib
import os
from datetime import datetime

router = APIRouter()

# 全局缓存编译后的规则
_compiled_rules_cache = None
_rules_cache_timestamp = None


# Pydantic 模型
class ScanCreate(BaseModel):
    target_path: str
    scan_type: str = "full"
    rule_ids: Optional[List[int]] = None


class ScanResponse(BaseModel):
    id: int
    task_id: str
    target_path: str
    status: ScanStatus
    progress: float
    total_files: int
    scanned_files: int
    detected_files: int
    created_at: str
    
    class Config:
        from_attributes = True


class ScanResultResponse(BaseModel):
    id: int
    file_path: str
    file_name: str
    file_hash: Optional[str]
    threat_level: ThreatLevel
    is_malicious: bool
    matched_rules: Optional[str]
    
    class Config:
        from_attributes = True


def get_compiled_rules(db: Session, force_reload: bool = False):
    """获取编译后的规则（带缓存）"""
    global _compiled_rules_cache, _rules_cache_timestamp
    
    current_time = datetime.now()
    
    # 如果缓存存在且未过期（5分钟内），直接返回
    if not force_reload and _compiled_rules_cache and _rules_cache_timestamp:
        cache_age = (current_time - _rules_cache_timestamp).total_seconds()
        if cache_age < 300:  # 5分钟缓存
            return _compiled_rules_cache
    
    # 获取所有活动的 YARA 规则
    rules = db.query(YaraRule).limit(10000).all()
    
    if not rules:
        raise HTTPException(status_code=400, detail="没有可用的 YARA 规则")
    
    # 编译规则
    rule_dict = {}
    for rule in rules:
        if rule.content:
            try:
                rule_dict[rule.name] = rule.content
            except Exception:
                continue
    
    if not rule_dict:
        raise HTTPException(status_code=500, detail="所有规则编译失败")
    
    try:
        compiled_rules = yara.compile(sources=rule_dict)
        _compiled_rules_cache = compiled_rules
        _rules_cache_timestamp = current_time
        return compiled_rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"规则编译失败: {str(e)}")


@router.post("/", response_model=ScanResponse)
async def create_scan_task(scan: ScanCreate, db: Session = Depends(get_db)):
    """创建扫描任务"""
    
    # 验证目标路径
    if not os.path.exists(scan.target_path):
        raise HTTPException(status_code=400, detail="目标路径不存在")
    
    # 生成任务 ID
    task_id = str(uuid.uuid4())
    
    # 确定目标类型
    target_type = "directory" if os.path.isdir(scan.target_path) else "file"
    
    # 创建任务
    db_task = ScanTask(
        task_id=task_id,
        target_path=scan.target_path,
        target_type=target_type,
        scan_type=scan.scan_type,
        use_rules=str(scan.rule_ids) if scan.rule_ids else None,
        status=ScanStatus.PENDING
    )
    
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    
    # TODO: 这里应该启动后台任务进行实际扫描
    # 可以使用 Celery 或其他任务队列
    
    return db_task


@router.get("/", response_model=List[ScanResponse])
async def list_scan_tasks(
    skip: int = 0,
    limit: int = 100,
    status: Optional[ScanStatus] = None,
    db: Session = Depends(get_db)
):
    """获取扫描任务列表"""
    query = db.query(ScanTask)
    
    if status:
        query = query.filter(ScanTask.status == status)
    
    tasks = query.order_by(ScanTask.created_at.desc()).offset(skip).limit(limit).all()
    return tasks


@router.get("/{task_id}", response_model=ScanResponse)
async def get_scan_task(task_id: str, db: Session = Depends(get_db)):
    """获取扫描任务详情"""
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务未找到")
    return task


@router.get("/{task_id}/results", response_model=List[ScanResultResponse])
async def get_scan_results(task_id: str, db: Session = Depends(get_db)):
    """获取扫描结果"""
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务未找到")
    
    results = db.query(ScanResult).filter(ScanResult.task_id == task.id).all()
    return results


@router.post("/file")
def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """扫描上传的文件"""
    
    try:
        # 读取文件内容
        content = file.file.read()
        
        # 计算文件哈希
        file_hash = hashlib.sha256(content).hexdigest()
        
        # 获取编译后的规则（使用缓存）
        compiled_rules = get_compiled_rules(db)
        
        # 扫描文件
        matches = compiled_rules.match(data=content)
        
        # 判断威胁级别
        threat_level = ThreatLevel.CLEAN
        is_malicious = len(matches) > 0
        
        if is_malicious:
            threat_level = ThreatLevel.MALICIOUS
        
        # 生成任务
        task_id = str(uuid.uuid4())
        db_task = ScanTask(
            task_id=task_id,
            target_path=file.filename,
            target_type="file",
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
        
        # 保存结果
        matched_rule_names = [m.rule for m in matches]
        
        result = ScanResult(
            task_id=db_task.id,
            file_path=file.filename,
            file_name=file.filename,
            file_size=len(content),
            file_hash=file_hash,
            threat_level=threat_level,
            is_malicious=is_malicious,
            matched_rules=str(matched_rule_names)
        )
        db.add(result)
        db.commit()
        
        return {
            "task_id": task_id,
            "file_name": file.filename,
            "file_hash": file_hash,
            "is_malicious": is_malicious,
            "threat_level": threat_level,
            "matched_rules": matched_rule_names
        }
    
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = f"扫描失败: {str(e)}\n{traceback.format_exc()}"
        raise HTTPException(status_code=500, detail=error_detail)


@router.delete("/{task_id}")
async def delete_scan_task(task_id: str, db: Session = Depends(get_db)):
    """删除扫描任务"""
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务未找到")
    
    db.delete(task)
    db.commit()
    
    return {"message": "任务已删除"}
