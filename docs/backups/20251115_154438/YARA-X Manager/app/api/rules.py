from fastapi import APIRouter, UploadFile, HTTPException, Form, File, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from pathlib import Path
import re
import os
from app.db import get_db
from app.sql_models import Rule
from app.storage import save_rule, delete_rule
from app.config import RULES_DIR

router = APIRouter(prefix="/api/rules", tags=["规则管理"])

def parse_yara_rule(content: str) -> dict:
    """解析YARA规则文件，提取元数据"""
    metadata = {
        'name': '',
        'description': '',
        'author': '',
        'date': '',
        'version': '',
        'reference': '',
        'tags': []
    }
    
    try:
        # 提取规则名称
        name_match = re.search(r'rule\s+(\w+)', content)
        if name_match:
            metadata['name'] = name_match.group(1)
        
        # 提取tags（规则名后的标签）
        tags_match = re.search(r'rule\s+\w+\s*:\s*([\w\s]+)\s*\{', content)
        if tags_match:
            metadata['tags'] = [t.strip() for t in tags_match.group(1).split()]
        
        # 提取meta部分
        meta_match = re.search(r'meta:\s*\n(.*?)\n\s*(strings:|condition:)', content, re.DOTALL)
        if meta_match:
            meta_content = meta_match.group(1)
            
            # 解析meta字段
            for line in meta_content.split('\n'):
                line = line.strip()
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip(' "\'')
                    
                    if key in metadata:
                        metadata[key] = value
    except Exception as e:
        print(f"解析YARA规则出错: {e}")
    
    return metadata

@router.post("/upload")
async def upload_rules(files: List[UploadFile] = File(...), db: Session = Depends(get_db)):
    """上传YARA规则文件"""
    uploaded_rules = []
    errors = []
    
    for file in files:
        try:
            # 只接受.yar和.yara文件
            if not file.filename.endswith(('.yar', '.yara')):
                errors.append(f"{file.filename}: 不是有效的YARA规则文件")
                continue
            
            content = (await file.read()).decode("utf-8")
            
            # 验证规则内容
            if 'rule ' not in content:
                errors.append(f"{file.filename}: 无效的YARA规则（缺少'rule'关键字）")
                continue
            
            # 解析规则元数据
            metadata = parse_yara_rule(content)
            rule_name = metadata['name'] or file.filename.replace('.yar', '').replace('.yara', '')
            
            # 检查规则是否已存在
            existing_rule = db.query(Rule).filter(Rule.name == rule_name).first()
            if existing_rule:
                # 更新现有规则
                rule_path = save_rule(content, file.filename)
                existing_rule.path = str(rule_path)
                existing_rule.active = True
                db.commit()
                db.refresh(existing_rule)
                
                uploaded_rules.append({
                    'id': existing_rule.id,
                    'name': existing_rule.name,
                    'description': metadata['description'],
                    'author': metadata['author'],
                    'path': existing_rule.path,
                    'active': existing_rule.active,
                    'updated': True
                })
            else:
                # 创建新规则
                rule_path = save_rule(content, file.filename)
                
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
                    'description': metadata['description'],
                    'author': metadata['author'],
                    'path': rule.path,
                    'active': rule.active,
                    'updated': False
                })
                
        except Exception as e:
            errors.append(f"{file.filename}: {str(e)}")
    
    return {
        "success": True,
        "message": f"成功上传 {len(uploaded_rules)} 个规则",
        "uploaded": uploaded_rules,
        "errors": errors
    }

@router.get("/")
def list_rules(db: Session = Depends(get_db)):
    """获取所有YARA规则列表"""
    rules = db.query(Rule).all()
    result = []
    
    for rule in rules:
        rule_info = {
            'id': rule.id,
            'name': rule.name,
            'path': rule.path,
            'active': rule.active,
            'description': '',
            'author': '',
            'date': '',
            'tags': [],
            'file_exists': False
        }
        
        # 读取规则文件内容并解析
        if rule.path and os.path.exists(rule.path):
            rule_info['file_exists'] = True
            try:
                with open(rule.path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    metadata = parse_yara_rule(content)
                    rule_info.update({
                        'description': metadata['description'],
                        'author': metadata['author'],
                        'date': metadata['date'],
                        'tags': metadata['tags']
                    })
            except Exception as e:
                print(f"读取规则文件失败 {rule.path}: {e}")
        
        result.append(rule_info)
    
    return result

@router.get("/{rule_id}")
def get_rule(rule_id: int, db: Session = Depends(get_db)):
    """获取单个规则详情"""
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "规则不存在")
    
    rule_detail = {
        'id': rule.id,
        'name': rule.name,
        'path': rule.path,
        'active': rule.active,
        'content': '',
        'metadata': {}
    }
    
    # 读取规则内容
    if rule.path and os.path.exists(rule.path):
        try:
            with open(rule.path, 'r', encoding='utf-8') as f:
                content = f.read()
                rule_detail['content'] = content
                rule_detail['metadata'] = parse_yara_rule(content)
        except Exception as e:
            raise HTTPException(500, f"读取规则文件失败: {str(e)}")
    else:
        raise HTTPException(404, "规则文件不存在")
    
    return rule_detail

@router.get("/{rule_id}/content")
def get_rule_content(rule_id: int, db: Session = Depends(get_db)):
    """获取规则的原始内容"""
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "规则不存在")
    
    if not rule.path or not os.path.exists(rule.path):
        raise HTTPException(404, "规则文件不存在")
    
    try:
        with open(rule.path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        metadata = parse_yara_rule(content)
        
        return {
            'content': content,
            'metadata': metadata
        }
    except Exception as e:
        raise HTTPException(500, f"读取规则文件失败: {str(e)}")

@router.put("/{rule_id}/toggle")
def toggle_rule(rule_id: int, db: Session = Depends(get_db)):
    """启用/禁用规则"""
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "规则不存在")
    
    rule.active = not rule.active
    db.commit()
    
    return {
        "success": True,
        "message": f"规则已{'启用' if rule.active else '禁用'}",
        "active": rule.active
    }

@router.delete("/{rule_id}")
def delete_rule_endpoint(rule_id: int, db: Session = Depends(get_db)):
    """删除规则"""
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "规则不存在")
    
    try:
        # 删除文件
        if rule.path and os.path.exists(rule.path):
            os.remove(rule.path)
        
        # 删除数据库记录
        db.delete(rule)
        db.commit()
        
        return {
            "success": True,
            "message": "规则删除成功"
        }
    except Exception as e:
        raise HTTPException(500, f"删除规则失败: {str(e)}")
