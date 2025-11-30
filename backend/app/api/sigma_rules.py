from fastapi import APIRouter, HTTPException, UploadFile, File, Depends
from typing import List, Optional
from pathlib import Path
import yaml
import os
import logging
from app.services.sigma_service import get_sigma_engine
from app.core.sigma_engine import SigmaEngine

logger = logging.getLogger(__name__)

router = APIRouter()

# Sigma规则目录
SIGMA_RULES_DIR = Path(os.getenv("SIGMA_RULES_DIR", "data/sigma_rules"))
CUSTOM_RULES_DIR = SIGMA_RULES_DIR / "custom"

# 确保自定义目录存在
CUSTOM_RULES_DIR.mkdir(parents=True, exist_ok=True)

@router.get("/")
async def list_sigma_rules(
    skip: int = 0,
    limit: int = 100,
    level: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None # 'system' or 'custom'
):
    """获取Sigma规则列表"""
    try:
        rules = []
        rule_id = 1
        
        if not SIGMA_RULES_DIR.exists():
            return []
        
        for rule_file in SIGMA_RULES_DIR.rglob("*.yml"):
            # Determine source based on path
            is_custom = "custom" in rule_file.parts
            rule_source = "custom" if is_custom else "system"
            
            if source and source != rule_source:
                continue

            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_data = yaml.safe_load(f)
                    
                    if rule_data:
                        rule = {
                            "id": rule_id,
                            "title": rule_data.get("title", rule_file.stem),
                            "description": rule_data.get("description", ""),
                            "level": rule_data.get("level", "medium"),
                            "status": rule_data.get("status", "stable"),
                            "author": rule_data.get("author", ""),
                            "references": rule_data.get("references", []),
                            "tags": rule_data.get("tags", []),
                            "filename": rule_file.name,
                            "source": rule_source,
                            "relative_path": str(rule_file.relative_to(SIGMA_RULES_DIR))
                        }
                        
                        # 过滤条件
                        if level and rule["level"] != level:
                            continue
                        if status and rule["status"] != status:
                            continue
                            
                        rules.append(rule)
                        rule_id += 1
            except Exception as e:
                print(f"解析Sigma规则失败 {rule_file}: {e}")
                continue
        
        # 分页
        return rules[skip:skip + limit]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取Sigma规则列表失败: {str(e)}")


@router.get("/{rule_id}")
async def get_sigma_rule(rule_id: int):
    """获取指定Sigma规则详情"""
    try:
        rules = await list_sigma_rules(limit=10000)
        for rule in rules:
            if rule["id"] == rule_id:
                # 读取完整内容
                rule_file = SIGMA_RULES_DIR / rule["filename"]
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule["content"] = f.read()
                return rule
        
        raise HTTPException(status_code=404, detail="Sigma规则不存在")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取Sigma规则失败: {str(e)}")


@router.post("/")
async def create_sigma_rule(
    title: str,
    content: str,
    description: Optional[str] = None,
    level: str = "medium",
    status: str = "test",
    engine: SigmaEngine = Depends(get_sigma_engine)
):
    """创建新的Sigma规则 (保存到 data/sigma_rules/custom)"""
    try:
        # 确保目录存在
        CUSTOM_RULES_DIR.mkdir(parents=True, exist_ok=True)
        
        # 验证YAML格式
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as e:
             raise HTTPException(status_code=400, detail=f"无效的YAML格式: {str(e)}")

        # 生成文件名 (安全处理)
        safe_title = "".join([c for c in title if c.isalnum() or c in (' ', '_', '-')]).strip()
        filename = f"{safe_title.replace(' ', '_').lower()}.yml"
        rule_file = CUSTOM_RULES_DIR / filename
        
        # 检查文件是否已存在
        if rule_file.exists():
            raise HTTPException(status_code=400, detail="规则文件已存在")
        
        # 保存规则
        with open(rule_file, 'w', encoding='utf-8') as f:
            f.write(content)
            
        # 自动重载引擎
        engine.reload_rules()
        
        return {"message": "Sigma规则创建成功", "filename": filename, "path": f"custom/{filename}"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"创建Sigma规则失败: {str(e)}")


@router.put("/{rule_id}")
async def update_sigma_rule(
    rule_id: int,
    content: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    engine: SigmaEngine = Depends(get_sigma_engine)
):
    """更新Sigma规则 (仅允许更新 custom 目录下的规则)"""
    try:
        # 获取现有规则信息以定位文件
        target_rule = None
        rule_id_counter = 1
        for rule_file in SIGMA_RULES_DIR.rglob("*.yml"):
            if rule_id_counter == rule_id:
                target_rule = rule_file
                break
            rule_id_counter += 1
            
        if not target_rule:
             raise HTTPException(status_code=404, detail="规则未找到")
             
        # 检查权限：只允许修改 custom 目录下的
        if "custom" not in target_rule.parts:
             raise HTTPException(status_code=403, detail="不允许修改系统内置规则")

        # 验证YAML
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as e:
             raise HTTPException(status_code=400, detail=f"无效的YAML格式: {str(e)}")

        # 更新规则内容
        with open(target_rule, 'w', encoding='utf-8') as f:
            f.write(content)
            
        # 自动重载引擎
        engine.reload_rules()
        
        return {"message": "Sigma规则更新成功"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"更新Sigma规则失败: {str(e)}")


@router.delete("/{rule_id}")
async def delete_sigma_rule(rule_id: int, engine: SigmaEngine = Depends(get_sigma_engine)):
    """删除Sigma规则 (仅允许删除 custom 目录下的规则)"""
    try:
        target_rule = None
        rule_id_counter = 1
        for rule_file in SIGMA_RULES_DIR.rglob("*.yml"):
            if rule_id_counter == rule_id:
                target_rule = rule_file
                break
            rule_id_counter += 1
            
        if not target_rule:
             raise HTTPException(status_code=404, detail="规则未找到")
             
        # 检查权限
        if "custom" not in target_rule.parts:
             raise HTTPException(status_code=403, detail="不允许删除系统内置规则")
        
        # 删除文件
        target_rule.unlink()
        
        # 自动重载引擎
        engine.reload_rules()
        
        return {"message": "Sigma规则删除成功"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"删除Sigma规则失败: {str(e)}")


@router.post("/upload")
async def upload_sigma_rule(file: UploadFile = File(...), engine: SigmaEngine = Depends(get_sigma_engine)):
    """上传Sigma规则文件 (保存到 data/sigma_rules/custom)"""
    try:
        # 检查文件扩展名
        if not file.filename.endswith(('.yml', '.yaml')):
            raise HTTPException(status_code=400, detail="只支持.yml或.yaml文件")
        
        # 确保目录存在
        CUSTOM_RULES_DIR.mkdir(parents=True, exist_ok=True)
        
        # 安全文件名处理 (防止 ../../ 攻击)
        safe_filename = os.path.basename(file.filename)
        
        # 保存文件
        file_path = CUSTOM_RULES_DIR / safe_filename
        content = await file.read()
        
        # 验证YAML格式
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"无效的YAML格式: {str(e)}")
        
        with open(file_path, 'wb') as f:
            f.write(content)
            
        # 自动重载引擎
        engine.reload_rules()
        
        return {"message": "Sigma规则上传成功", "filename": safe_filename}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"上传Sigma规则失败: {str(e)}")


@router.get("/stats/summary")
async def get_sigma_stats():
    """获取Sigma规则统计信息"""
    try:
        rules = await list_sigma_rules(limit=10000)
        
        stats = {
            "total": len(rules),
            "by_level": {},
            "by_status": {}
        }
        
        for rule in rules:
            # 按级别统计
            level = rule["level"]
            stats["by_level"][level] = stats["by_level"].get(level, 0) + 1
            
            # 按状态统计
            status = rule["status"]
            stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
        
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取统计信息失败: {str(e)}")
