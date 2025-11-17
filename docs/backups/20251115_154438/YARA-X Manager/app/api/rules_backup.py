from fastapi import APIRouter, UploadFile, HTTPException, Form, File, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List
from pathlib import Path
from app.db import get_db
from app.sql_models import Rule
from app.tasks import validate_and_store_rule
from app.storage import delete_rule
router = APIRouter(prefix="/rules", tags=["rules"])
@router.post("/upload")
async def upload_rules(files: List[UploadFile] = File(...), db: Session = Depends(get_db)):
    """
    上传YARA规则文件
    """
    task_ids = []
    uploaded_rules = []
    
    for file in files:
        try:
            content = (await file.read()).decode("utf-8")
            
            # 尝试使用Celery任务
            try:
                task = validate_and_store_rule.apply_async(args=[content, file.filename])
                task_ids.append(task.id)
                
                # 等待任务完成(超时3秒)
                result = task.get(timeout=3)
                if result.get('success'):
                    uploaded_rules.append(result.get('rule'))
            except Exception as task_error:
                # 如果Celery失败,直接保存规则(跳过验证)
                from app.storage import save_rule
                
                # 简单验证:检查是否包含 'rule' 关键字
                if 'rule ' not in content:
                    raise HTTPException(400, f"Invalid YARA rule in {file.filename}: No 'rule' keyword found")
                
                # 保存规则文件
                rule_path = save_rule(content, file.filename)
                
                # 提取规则名称 - 使用文件名作为基础以避免重复
                base_name = file.filename.replace('.yar', '').replace('.yara', '')
                rule_name = base_name
                
                # 尝试从内容中提取规则名
                if 'rule ' in content:
                    try:
                        extracted_name = content.split('rule ')[1].split('{')[0].strip()
                        # 如果提取的名称不同,组合使用以确保唯一性
                        if extracted_name and extracted_name != base_name:
                            rule_name = f"{base_name}_{extracted_name}"
                        else:
                            rule_name = extracted_name or base_name
                    except:
                        pass
                
                # 检查是否已存在同名规则
                existing_rule = db.query(Rule).filter(Rule.name == rule_name).first()
                if existing_rule:
                    # 如果存在，添加时间戳后缀
                    import time
                    rule_name = f"{rule_name}_{int(time.time())}"
                
                # 创建规则记录
                rule = Rule(
                    name=rule_name,
                    path=str(rule_path),
                    active=True
                )
                db.add(rule)
                db.commit()
                db.refresh(rule)
                uploaded_rules.append({
                    'id': rule.id,
                    'name': rule.name,
                    'path': rule.path,
                    'active': rule.active
                })
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(400, f"Failed to upload {file.filename}: {str(e)}")
    
    return {
        "task_ids": task_ids,
        "message": f"Successfully uploaded {len(uploaded_rules)} rules",
        "rules": uploaded_rules
    }

@router.get("/")
def list_rules(db: Session = Depends(get_db)):
    import os
    from datetime import datetime
    
    rows = db.query(Rule).all()
    result = []
    for r in rows:
        # 尝试从规则文件读取元数据
        description = ""
        author = ""
        created_at = "2025-11-12"
        
        if r.path and os.path.exists(r.path):
            try:
                with open(r.path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # 简单解析 YARA 规则的 meta 部分
                    if 'meta:' in content:
                        for line in content.split('\n'):
                            if 'description' in line and '=' in line:
                                description = line.split('=')[1].strip(' "')
                            elif 'author' in line and '=' in line:
                                author = line.split('=')[1].strip(' "')
                            elif 'date' in line and '=' in line:
                                created_at = line.split('=')[1].strip(' "')
            except:
                pass
            
            # 如果没有从文件读取到时间,使用文件创建时间
            if created_at == "2025-11-12":
                created_at = datetime.fromtimestamp(os.path.getctime(r.path)).strftime("%Y-%m-%d")
        
        result.append({
            "id": r.id,
            "name": r.name,
            "active": r.active,
            "path": r.path,
            "description": description,
            "author": author,
            "created_at": created_at
        })
    
    return result

@router.post("/toggle/{ids}")
def toggle_rules(ids: str, db: Session = Depends(get_db)):
    id_list = [int(id) for id in ids.split(",")]
    rules = db.query(Rule).filter(Rule.id.in_(id_list)).all()
    for rule in rules:
        rule.active = not rule.active
    db.commit()
    return {"message": f"Toggled {len(rules)} rules", "updated": len(rules)}

@router.post("/delete/{ids}")
def delete_rules(ids: str, db: Session = Depends(get_db)):
    id_list = [int(id) for id in ids.split(",")]
    rules = db.query(Rule).filter(Rule.id.in_(id_list)).all()
    for rule in rules:
        db.delete(rule)
        delete_rule(Path(rule.path))
    db.commit()
    return {"message": "Rules deleted successfully"}

@router.get("/{rule_id}/content")
def get_rule_content(rule_id: int, db: Session = Depends(get_db)):
    """
    获取指定规则的完整内容
    """
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    
    if not rule.path or not Path(rule.path).exists():
        raise HTTPException(404, "Rule file not found")
    
    try:
        with open(rule.path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 解析规则元数据
        meta = {}
        if 'meta:' in content:
            in_meta = False
            for line in content.split('\n'):
                if 'meta:' in line:
                    in_meta = True
                    continue
                if in_meta:
                    if 'strings:' in line or 'condition:' in line:
                        break
                    if '=' in line:
                        key = line.split('=')[0].strip()
                        value = line.split('=')[1].strip(' "')
                        meta[key] = value
        
        return {
            "id": rule.id,
            "name": rule.name,
            "content": content,
            "meta": meta,
            "active": rule.active,
            "path": rule.path
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to read rule content: {str(e)}")
