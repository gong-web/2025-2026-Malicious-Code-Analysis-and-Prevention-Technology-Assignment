"""
检测报告 API
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, Integer
from typing import List, Dict, Any
from app.core.database import get_db
from app.models.scan import ScanTask, ScanResult, ThreatLevel
from app.models.rule import YaraRule
from pydantic import BaseModel
from datetime import datetime, timedelta

router = APIRouter()


class ReportStats(BaseModel):
    """统计数据"""
    total_scans: int
    total_files_scanned: int
    total_threats_detected: int
    clean_files: int
    malicious_files: int
    suspicious_files: int


@router.get("/stats")
async def get_statistics(db: Session = Depends(get_db)) -> ReportStats:
    """获取统计数据"""
    
    # 总扫描任务数
    total_scans = db.query(func.count(ScanTask.id)).scalar()
    
    # 总扫描文件数
    total_files = db.query(func.sum(ScanTask.scanned_files)).scalar() or 0
    
    # 威胁检测数
    total_threats = db.query(func.sum(ScanTask.detected_files)).scalar() or 0
    
    # 按威胁级别统计
    clean = db.query(func.count(ScanResult.id)).filter(
        ScanResult.threat_level == ThreatLevel.CLEAN
    ).scalar()
    
    malicious = db.query(func.count(ScanResult.id)).filter(
        ScanResult.threat_level == ThreatLevel.MALICIOUS
    ).scalar()
    
    suspicious = db.query(func.count(ScanResult.id)).filter(
        ScanResult.threat_level == ThreatLevel.SUSPICIOUS
    ).scalar()
    
    return ReportStats(
        total_scans=total_scans,
        total_files_scanned=total_files,
        total_threats_detected=total_threats,
        clean_files=clean,
        malicious_files=malicious,
        suspicious_files=suspicious
    )


@router.get("/recent")
async def get_recent_detections(limit: int = 10, db: Session = Depends(get_db)):
    """获取最近的检测结果"""
    
    results = db.query(ScanResult).filter(
        ScanResult.is_malicious == True
    ).order_by(
        ScanResult.scanned_at.desc()
    ).limit(limit).all()
    
    return [{
        "id": r.id,
        "file_name": r.file_name,
        "file_hash": r.file_hash,
        "threat_level": r.threat_level,
        "matched_rules": r.matched_rules,
        "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None
    } for r in results]


@router.get("/top-threats")
async def get_top_threats(limit: int = 10, db: Session = Depends(get_db)):
    """获取最常见的威胁"""
    
    # 按文件哈希分组,统计出现次数
    results = db.query(
        ScanResult.file_hash,
        ScanResult.file_name,
        func.count(ScanResult.id).label('count')
    ).filter(
        ScanResult.is_malicious == True
    ).group_by(
        ScanResult.file_hash,
        ScanResult.file_name
    ).order_by(
        func.count(ScanResult.id).desc()
    ).limit(limit).all()
    
    return [{
        "file_hash": r.file_hash,
        "file_name": r.file_name,
        "detection_count": r.count
    } for r in results]


@router.get("/rule-effectiveness")
async def get_rule_effectiveness(db: Session = Depends(get_db)):
    """获取规则有效性统计"""
    
    rules = db.query(YaraRule).all()
    
    effectiveness = []
    for rule in rules:
        # 计算该规则的命中次数
        # 这是一个简化实现,实际需要解析 matched_rules JSON
        effectiveness.append({
            "rule_name": rule.name,
            "category": rule.category,
            "match_count": rule.match_count,
            "false_positive_count": rule.false_positive_count,
            "accuracy": (
                (rule.match_count - rule.false_positive_count) / rule.match_count * 100
                if rule.match_count > 0 else 0
            )
        })
    
    # 按命中次数排序
    effectiveness.sort(key=lambda x: x['match_count'], reverse=True)
    
    return effectiveness[:20]


@router.get("/timeline")
async def get_detection_timeline(days: int = 7, db: Session = Depends(get_db)):
    """获取检测时间线"""
    
    start_date = datetime.now() - timedelta(days=days)
    
    # 按日期分组统计
    results = db.query(
        func.date(ScanResult.scanned_at).label('date'),
        func.count(ScanResult.id).label('total'),
        func.sum(func.cast(ScanResult.is_malicious, Integer)).label('malicious')
    ).filter(
        ScanResult.scanned_at >= start_date
    ).group_by(
        func.date(ScanResult.scanned_at)
    ).all()
    
    timeline = []
    for r in results:
        timeline.append({
            "date": r.date.isoformat() if r.date else None,
            "total_scans": r.total,
            "malicious_detections": r.malicious or 0,
            "clean_files": r.total - (r.malicious or 0)
        })
    
    return timeline


@router.get("/export/{task_id}")
async def export_report(task_id: str, db: Session = Depends(get_db)):
    """导出扫描报告"""
    
    task = db.query(ScanTask).filter(ScanTask.task_id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务未找到")
    
    results = db.query(ScanResult).filter(ScanResult.task_id == task.id).all()
    
    report = {
        "task_info": {
            "task_id": task.task_id,
            "target_path": task.target_path,
            "scan_type": task.scan_type,
            "status": task.status,
            "created_at": task.created_at.isoformat() if task.created_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None
        },
        "statistics": {
            "total_files": task.total_files,
            "scanned_files": task.scanned_files,
            "detected_files": task.detected_files,
            "clean_files": task.scanned_files - task.detected_files
        },
        "results": [{
            "file_path": r.file_path,
            "file_name": r.file_name,
            "file_hash": r.file_hash,
            "threat_level": r.threat_level,
            "is_malicious": r.is_malicious,
            "matched_rules": r.matched_rules,
            "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None
        } for r in results]
    }
    
    return report
