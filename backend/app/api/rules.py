"""
YARA 规则管理 API
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from app.core.database import get_db
from app.models.rule import YaraRule, RuleStatus, RuleSeverity
from pydantic import BaseModel, Field, field_serializer
import yara
import os
from pathlib import Path
import logging

router = APIRouter()


# Pydantic 模型
class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    content: str
    category: Optional[str] = None
    tags: Optional[str] = None
    severity: RuleSeverity = RuleSeverity.MEDIUM
    author: Optional[str] = None
    version: Optional[str] = "1.0"


class RuleUpdate(BaseModel):
    description: Optional[str] = None
    content: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[str] = None
    severity: Optional[RuleSeverity] = None
    status: Optional[RuleStatus] = None


class RuleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: RuleSeverity
    status: RuleStatus
    author: Optional[str] = None
    version: Optional[str] = None
    match_count: int
    created_at: datetime
    
    @field_serializer('created_at')
    def serialize_datetime(self, dt: datetime, _info):
        return dt.isoformat() if dt else None
    
    class Config:
        from_attributes = True


@router.get("/", response_model=List[RuleResponse])
async def list_rules(
    skip: int = 0,
    limit: int = 10000,
    category: Optional[str] = None,
    status: Optional[RuleStatus] = None,
    db: Session = Depends(get_db)
):
    """获取 YARA 规则列表"""
    query = db.query(YaraRule)
    
    if category:
        query = query.filter(YaraRule.category == category)
    if status:
        query = query.filter(YaraRule.status == status)
    
    rules = query.offset(skip).limit(limit).all()
    return rules


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: int, db: Session = Depends(get_db)):
    """获取单个 YARA 规则"""
    rule = db.query(YaraRule).filter(YaraRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="规则未找到")
    return rule


@router.post("/", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(rule: RuleCreate, db: Session = Depends(get_db)):
    """创建新的 YARA 规则"""
    
    # 检查规则名称是否已存在
    existing = db.query(YaraRule).filter(YaraRule.name == rule.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="规则名称已存在")
    
    # 验证 YARA 规则语法
    try:
        yara.compile(source=rule.content)
    except yara.SyntaxError as e:
        raise HTTPException(status_code=400, detail=f"YARA 规则语法错误: {str(e)}")
    
    # 创建规则
    db_rule = YaraRule(**rule.dict())
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    
    return db_rule


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(rule_id: int, rule: RuleUpdate, db: Session = Depends(get_db)):
    """更新 YARA 规则"""
    db_rule = db.query(YaraRule).filter(YaraRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="规则未找到")
    
    # 如果更新了内容,验证语法
    if rule.content:
        try:
            yara.compile(source=rule.content)
        except yara.SyntaxError as e:
            raise HTTPException(status_code=400, detail=f"YARA 规则语法错误: {str(e)}")
    
    # 更新字段
    for key, value in rule.dict(exclude_unset=True).items():
        setattr(db_rule, key, value)
    
    db.commit()
    db.refresh(db_rule)
    
    return db_rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    """删除 YARA 规则"""
    db_rule = db.query(YaraRule).filter(YaraRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="规则未找到")
    
    db.delete(db_rule)
    db.commit()
    
    return None


@router.post("/upload")
async def upload_rule_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """上传 YARA 规则文件"""
    
    # 读取文件内容
    content = await file.read()
    try:
        content = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="文件必须是 UTF-8 编码")
    
    # 验证语法
    try:
        yara.compile(source=content)
    except yara.SyntaxError as e:
        raise HTTPException(status_code=400, detail=f"YARA 规则语法错误: {str(e)}")
    
    # 提取规则名称 (安全实现)
    safe_filename = os.path.basename(file.filename)
    rule_name = safe_filename.replace('.yar', '').replace('.yara', '')
    
    # 检查是否已存在
    existing = db.query(YaraRule).filter(YaraRule.name == rule_name).first()
    if existing:
        # 自动重命名策略：添加随机后缀或时间戳，或者直接报错
        # 为了用户体验，我们选择报错，让用户知道
        raise HTTPException(status_code=400, detail=f"规则名称 '{rule_name}' 已存在，请重命名文件后再上传")
    
    # 创建规则
    db_rule = YaraRule(
        name=rule_name,
        content=content,
        status=RuleStatus.ACTIVE,
        category="uploaded" # 标记来源
    )
    db.add(db_rule)
    db.commit()
    
    return {"message": "规则上传成功", "rule_id": db_rule.id}


import os

@router.post("/{rule_id}/compile")
async def compile_rule(rule_id: int, db: Session = Depends(get_db)):
    """编译 YARA 规则"""
    db_rule = db.query(YaraRule).filter(YaraRule.id == rule_id).first()
    if not db_rule:
        raise HTTPException(status_code=404, detail="规则未找到")
    
    try:
        compiled = yara.compile(source=db_rule.content)
        db_rule.is_compiled = True
        db.commit()
        
        return {"message": "规则编译成功"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"编译失败: {str(e)}")

import logging
logger = logging.getLogger(__name__)

@router.post("/sync")
async def sync_local_rules(db: Session = Depends(get_db)):
    """
    同步本地规则目录 (data/yara_rules) 到数据库
    """
    import sys
    
    # 1. 路径寻找策略 (Path Discovery Strategy)
    # 我们尝试多个可能的位置来寻找 data/yara_rules
    
    current_file = Path(__file__).resolve()
    # backend/app/api/rules.py
    
    possible_paths = [
        # 1. 标准开发环境: 项目根目录/data
        current_file.parents[3] / "data" / "yara_rules",
        # 2. 相对当前工作目录
        Path(os.getcwd()) / "data" / "yara_rules",
        # 3. 相对当前工作目录的上一级 (如果是在 backend 目录运行)
        Path(os.getcwd()).parent / "data" / "yara_rules",
        # 4. 硬编码常见路径 (针对本环境)
        Path("e:/2025-2026-Malicious-Code-Analysis-and-Prevention-Technology-Assignment/data/yara_rules")
    ]
    
    rules_path = None
    checked_paths = []
    
    for p in possible_paths:
        checked_paths.append(str(p))
        if p.exists() and p.is_dir():
            rules_path = p
            break
            
    if not rules_path:
        # 记录详细错误并返回
        msg = f"未找到规则目录。已尝试路径: {checked_paths}. 当前工作目录: {os.getcwd()}"
        print(msg) # 打印到控制台以便调试
        raise HTTPException(status_code=404, detail=msg)
             
    print(f"Syncing rules from: {rules_path}")
    
    added_count = 0
    updated_count = 0
    errors = []
    
    try:
        for root, _, files in os.walk(rules_path):
            for file in files:
                if file.endswith(('.yar', '.yara')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        # 基础语法验证
                        try:
                            yara.compile(source=content)
                        except yara.SyntaxError as e:
                            errors.append(f"{file}: Syntax Error")
                            continue
                            
                        # 规则名称处理
                        rule_name = os.path.splitext(file)[0]
                        # 移除特殊字符，防止数据库错误
                        rule_name = "".join(c for c in rule_name if c.isalnum() or c in ('_', '-', ' '))
                        if len(rule_name) > 250:
                            rule_name = rule_name[:250]
                        
                        # 查重
                        existing = db.query(YaraRule).filter(YaraRule.name == rule_name).first()
                        
                        if existing:
                            if existing.content != content:
                                existing.content = content
                                existing.updated_at = datetime.now()
                                updated_count += 1
                        else:
                            new_rule = YaraRule(
                                name=rule_name,
                                content=content,
                                category="imported",
                                status=RuleStatus.ACTIVE,
                                description=f"Imported from {file}"
                            )
                            db.add(new_rule)
                            added_count += 1
                            
                    except Exception as e:
                        errors.append(f"{file}: {str(e)}")
        
        db.commit()
        
    except Exception as e:
        db.rollback()
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"数据库同步失败: {str(e)}")
    
    return {
        "message": "同步完成",
        "path_used": str(rules_path),
        "added": added_count,
        "updated": updated_count,
        "errors_count": len(errors),
        "sample_errors": errors[:5] # 只返回前5个错误避免报文过大
    }
