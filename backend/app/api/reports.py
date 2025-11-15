"""
检测报告 API
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Dict, Any
from app.core.database import get_db
from app.api.models_shared import Scan, Rule
from pydantic import BaseModel
from datetime import datetime, timedelta
import json

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
async def get_statistics(db: Session = Depends(get_db)) -> Dict[str, int]:
    """获取统计数据"""
    try:
        # 使用本地定义的Scan模型
        total_scans = db.query(func.count(Scan.id)).scalar() or 0
        
        # 统计恶意扫描 (通过解析result JSON)
        all_scans = db.query(Scan).all()
        malicious_count = 0
        for scan in all_scans:
            if scan.result:
                result_data = json.loads(scan.result)
                if result_data.get("is_malicious", False):
                    malicious_count += 1
        
        clean_count = total_scans - malicious_count
        active_rules = db.query(func.count(Rule.id)).filter(Rule.active == True).scalar() or 0
        
        return {
            "total_scans": total_scans,
            "malicious_count": malicious_count,
            "clean_count": clean_count,
            "active_rules": active_rules
        }
    except Exception as e:
        print(f"Error in get_statistics: {e}")
        import traceback
        traceback.print_exc()
        # 如果出错，返回默认值
        return {
            "total_scans": 0,
            "malicious_count": 0,
            "clean_count": 0,
            "active_rules": 0
        }


@router.get("/recent")
async def get_recent_scans(limit: int = 20, db: Session = Depends(get_db)):
    """获取最近的扫描记录"""
    try:
        scans = db.query(Scan).order_by(Scan.id.desc()).limit(limit).all()
        
        results = []
        for scan in scans:
            # 解析result JSON
            result_data = json.loads(scan.result) if scan.result else {}
            is_malicious = result_data.get("is_malicious", False)
            matches = result_data.get("matches", [])
            
            results.append({
                "id": scan.id,
                "filename": scan.filename,
                "is_malicious": is_malicious,
                "match_count": len(matches),
                "scan_time": scan.started_at,
                "status": scan.status,
                "matches": matches
            })
        
        return results
    except Exception as e:
        print(f"Error in get_recent_scans: {e}")
        return []


@router.get("/{scan_id}")
async def get_scan_report(scan_id: int, db: Session = Depends(get_db)):
    """获取单个扫描报告详情"""
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="扫描记录未找到")
        
        # 解析result JSON
        result_data = json.loads(scan.result) if scan.result else {}
        is_malicious = result_data.get("is_malicious", False)
        matches = result_data.get("matches", [])
        
        # 获取样本hash (如果存在)
        sample_hash = result_data.get("sample_hash", "N/A")
        
        # 获取所有规则用于计算
        active_rules = db.query(Rule).filter(Rule.active == True).all()
        total_rules = len(active_rules)
        
        return {
            "id": scan.id,
            "filename": scan.filename,
            "sample_hash": sample_hash,
            "scan_time": scan.started_at,
            "is_malicious": is_malicious,
            "total_rules": total_rules,
            "scanned_rules": total_rules,  # 假设所有激活规则都被使用
            "match_count": len(matches),
            "matches": matches,
            "status": scan.status
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in get_scan_report: {e}")
        raise HTTPException(status_code=500, detail="获取扫描报告失败")
