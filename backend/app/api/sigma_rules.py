from fastapi import APIRouter, HTTPException, UploadFile, File
from typing import List, Optional
from pathlib import Path
import yaml
import os

router = APIRouter()

# Sigma规则目录
SIGMA_RULES_DIR = Path(os.getenv("SIGMA_RULES_DIR", "data/sigma_rules"))

@router.get("/")
async def list_sigma_rules(
    skip: int = 0,
    limit: int = 100,
    level: Optional[str] = None,
    status: Optional[str] = None
):
    """获取Sigma规则列表"""
    try:
        rules = []
        rule_id = 1
        
        if not SIGMA_RULES_DIR.exists():
            return []
        
        for rule_file in SIGMA_RULES_DIR.glob("*.yml"):
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
                            "filename": rule_file.name
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
    status: str = "test"
):
    """创建新的Sigma规则"""
    try:
        # 确保目录存在
        SIGMA_RULES_DIR.mkdir(parents=True, exist_ok=True)
        
        # 生成文件名
        filename = f"{title.replace(' ', '_').lower()}.yml"
        rule_file = SIGMA_RULES_DIR / filename
        
        # 检查文件是否已存在
        if rule_file.exists():
            raise HTTPException(status_code=400, detail="规则文件已存在")
        
        # 保存规则
        with open(rule_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return {"message": "Sigma规则创建成功", "filename": filename}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"创建Sigma规则失败: {str(e)}")


@router.put("/{rule_id}")
async def update_sigma_rule(
    rule_id: int,
    content: str,
    title: Optional[str] = None,
    description: Optional[str] = None
):
    """更新Sigma规则"""
    try:
        # 获取现有规则
        rule = await get_sigma_rule(rule_id)
        rule_file = SIGMA_RULES_DIR / rule["filename"]
        
        # 更新规则内容
        with open(rule_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return {"message": "Sigma规则更新成功"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"更新Sigma规则失败: {str(e)}")


@router.delete("/{rule_id}")
async def delete_sigma_rule(rule_id: int):
    """删除Sigma规则"""
    try:
        # 获取规则信息
        rule = await get_sigma_rule(rule_id)
        rule_file = SIGMA_RULES_DIR / rule["filename"]
        
        # 删除文件
        rule_file.unlink()
        
        return {"message": "Sigma规则删除成功"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"删除Sigma规则失败: {str(e)}")


@router.post("/upload")
async def upload_sigma_rule(file: UploadFile = File(...)):
    """上传Sigma规则文件"""
    try:
        # 检查文件扩展名
        if not file.filename.endswith(('.yml', '.yaml')):
            raise HTTPException(status_code=400, detail="只支持.yml或.yaml文件")
        
        # 确保目录存在
        SIGMA_RULES_DIR.mkdir(parents=True, exist_ok=True)
        
        # 保存文件
        file_path = SIGMA_RULES_DIR / file.filename
        content = await file.read()
        
        # 验证YAML格式
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"无效的YAML格式: {str(e)}")
        
        with open(file_path, 'wb') as f:
            f.write(content)
        
        return {"message": "Sigma规则上传成功", "filename": file.filename}
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
