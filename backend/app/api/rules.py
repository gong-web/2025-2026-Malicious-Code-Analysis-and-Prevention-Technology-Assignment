"""
YARA 规则管理 API - 适配 data.sqlite 数据库
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db
from app.api.models_shared import Rule
from pydantic import BaseModel
import yara
import os
import shutil
from pathlib import Path

from app.core.yara_ext import get_default_externals
from app.core.config import settings
from app.services.rule_validator import RuleValidator

router = APIRouter()

# API请求模型
class ToggleRequest(BaseModel):
    """规则启用/禁用请求"""
    active: bool

# API响应模型
class RuleResponse(BaseModel):
    id: int
    name: str
    path: str
    active: bool
    file_exists: bool = False
    author: Optional[str] = None
    description: Optional[str] = None
    date: Optional[str] = None
    version: Optional[str] = None
    tags: List[str] = []

# 规则目录
RULES_DIR = Path(settings.YARA_RULES_DIR)
RULES_DIR.mkdir(parents=True, exist_ok=True)


@router.get("/")
async def list_rules(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """获取规则列表"""
    rules = db.query(Rule).offset(skip).limit(limit).all()
    
    result = []
    for rule in rules:
        # 检查文件是否存在
        file_exists = os.path.exists(rule.path)
        
        # 尝试解析规则元数据
        metadata = {"author": None, "description": None, "date": None, "version": None, "tags": []}
        if file_exists:
            try:
                with open(rule.path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # 简单解析meta字段
                    for line in content.split('\n'):
                        if 'author' in line and '=' in line:
                            metadata['author'] = line.split('=')[1].strip().strip('"')
                        elif 'description' in line and '=' in line:
                            metadata['description'] = line.split('=')[1].strip().strip('"')
                        elif 'date' in line and '=' in line:
                            metadata['date'] = line.split('=')[1].strip().strip('"')
                        elif 'version' in line and '=' in line:
                            metadata['version'] = line.split('=')[1].strip().strip('"')
            except:
                pass
        
        result.append(RuleResponse(
            id=rule.id,
            name=rule.name,
            path=rule.path,
            active=rule.active,
            file_exists=file_exists,
            **metadata
        ))
    
    return result


@router.get("/{rule_id}")
async def get_rule(rule_id: int, db: Session = Depends(get_db)):
    """获取单个规则详情"""
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="规则未找到")
    
    file_exists = os.path.exists(rule.path)
    metadata = {"author": None, "description": None, "date": None, "version": None, "tags": []}
    
    if file_exists:
        try:
            with open(rule.path, 'r', encoding='utf-8') as f:
                content = f.read()
                for line in content.split('\n'):
                    if 'author' in line and '=' in line:
                        metadata['author'] = line.split('=')[1].strip().strip('"')
                    elif 'description' in line and '=' in line:
                        metadata['description'] = line.split('=')[1].strip().strip('"')
                    elif 'date' in line and '=' in line:
                        metadata['date'] = line.split('=')[1].strip().strip('"')
                    elif 'version' in line and '=' in line:
                        metadata['version'] = line.split('=')[1].strip().strip('"')
        except:
            pass
    
    return RuleResponse(
        id=rule.id,
        name=rule.name,
        path=rule.path,
        active=rule.active,
        file_exists=file_exists,
        **metadata
    )


@router.delete("/{rule_id}")
async def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    """删除规则"""
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="规则未找到")
    
    # 删除文件
    if os.path.exists(rule.path):
        try:
            os.remove(rule.path)
        except:
            pass
    
    db.delete(rule)
    db.commit()
    
    return {"message": "规则已删除"}


@router.patch("/{rule_id}/toggle")
async def toggle_rule(
    rule_id: int,
    data: ToggleRequest,
    db: Session = Depends(get_db)
):
    """切换规则启用/禁用状态"""
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="规则未找到")
    
    old_state = rule.active
    rule.active = data.active
    db.commit()
    db.refresh(rule)
    
    print(f"[RULE] ID={rule_id}, {rule.name}: {old_state} → {rule.active}")
    
    return {
        "message": "状态已更新",
        "id": rule.id,
        "name": rule.name,
        "active": rule.active,
        "old_active": old_state
    }


@router.post("/upload")
async def upload_rule_files(files: List[UploadFile] = File(...), db: Session = Depends(get_db)):
    """上传YARA规则文件(支持多文件)"""
    uploaded = []
    errors = []
    
    for file in files:
        try:
            # 验证文件扩展名
            if not (file.filename.endswith('.yar') or file.filename.endswith('.yara')):
                errors.append(f"{file.filename}: 不支持的文件格式")
                continue
            
            # 读取内容
            content = await file.read()
            content_str = content.decode('utf-8')
            
            # 验证YARA语法
            v = RuleValidator().validate_yara_rule(content_str)
            if not v.get("valid"):
                errors.append(f"{file.filename}: YARA语法错误 - {v.get('error')}")
                continue
            
            # 提取规则名
            rule_name = file.filename.replace('.yar', '').replace('.yara', '')
            
            # 检查是否已存在
            existing = db.query(Rule).filter(Rule.name == rule_name).first()
            if existing:
                errors.append(f"{file.filename}: 规则名已存在")
                continue
            
            # 保存文件
            file_path = RULES_DIR / file.filename
            with open(file_path, 'wb') as f:
                f.write(content)
            
            # 添加到数据库
            new_rule = Rule(
                name=rule_name,
                path=str(file_path),
                active=True,
                version="1.0",
                revision=1,
                compile_time_ms=v.get("compile_time_ms", 0),
                complexity_score=v.get("complexity_score", 0)
            )
            db.add(new_rule)
            db.commit()
            db.refresh(new_rule)
            
            uploaded.append({
                "id": new_rule.id,
                "name": rule_name,
                "path": str(file_path)
            })
        
        except Exception as e:
            errors.append(f"{file.filename}: {str(e)}")
    
    return {
        "uploaded": len(uploaded),
        "failed": len(errors),
        "rules": uploaded,
        "errors": errors
    }


@router.post("/import/db")
async def import_from_db(db: Session = Depends(get_db)):
    bases = [Path("db/yara_rules_all/core-organized"), Path("db/class-lab-yararules")]
    imported = []
    errors = []
    for base in bases:
        if not base.exists():
            continue
        for p in base.rglob("*.yar"):
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                v = RuleValidator().validate_yara_rule(content)
                if not v.get("valid"):
                    errors.append(f"{p.name}: {v.get('error')}")
                    continue
                name = p.stem
                if db.query(Rule).filter(Rule.name == name).first():
                    continue
                dst = RULES_DIR / p.name
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(content, encoding="utf-8")
                r = Rule(
                    name=name,
                    path=str(dst),
                    active=True,
                    version="1.0",
                    revision=1,
                    compile_time_ms=v.get("compile_time_ms", 0),
                    complexity_score=v.get("complexity_score", 0)
                )
                db.add(r)
                db.commit()
                db.refresh(r)
                imported.append(name)
            except Exception as e:
                errors.append(f"{p.name}: {str(e)}")
    return {"imported": len(imported), "failed": len(errors), "errors": errors}
