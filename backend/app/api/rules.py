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
    content = content.decode('utf-8')
    
    # 验证语法
    try:
        yara.compile(source=content)
    except yara.SyntaxError as e:
        raise HTTPException(status_code=400, detail=f"YARA 规则语法错误: {str(e)}")
    
    # 提取规则名称 (简单实现)
    rule_name = file.filename.replace('.yar', '').replace('.yara', '')
    
    # 检查是否已存在
    existing = db.query(YaraRule).filter(YaraRule.name == rule_name).first()
    if existing:
        raise HTTPException(status_code=400, detail="规则名称已存在")
    
    # 创建规则
    db_rule = YaraRule(
        name=rule_name,
        content=content,
        status=RuleStatus.ACTIVE
    )
    db.add(db_rule)
    db.commit()
    
    return {"message": "规则上传成功", "rule_id": db_rule.id}


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
