import sys
import os
import re
import logging

# 添加 backend 目录到路径，以便导入 app 模块
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.rule import YaraRule, RuleSeverity
from app.core.config import settings

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_severity(content: str, rule_name: str = "") -> str:
    """
    从内容解析严重程度 (与 API 逻辑同步)
    """
    # 1. 字符串匹配
    str_patterns = [
        r'severity\s*=\s*[\'"](\w+)[\'"]',
        r'level\s*=\s*[\'"](\w+)[\'"]',
        r'threat_level\s*=\s*[\'"](\w+)[\'"]'
    ]
    
    for pattern in str_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            val = match.group(1).lower()
            if "critical" in val: return RuleSeverity.CRITICAL
            if "high" in val: return RuleSeverity.HIGH
            if "medium" in val: return RuleSeverity.MEDIUM
            if "low" in val: return RuleSeverity.LOW

    # 2. 分数匹配
    score_match = re.search(r'score\s*=\s*(\d+)', content)
    if score_match:
        try:
            score = int(score_match.group(1))
            if score >= 80: return RuleSeverity.CRITICAL
            if score >= 70: return RuleSeverity.HIGH
            if score >= 40: return RuleSeverity.MEDIUM
            return RuleSeverity.LOW
        except:
            pass

    # 3. weight 匹配
    weight_match = re.search(r'weight\s*=\s*(\d+)', content)
    if weight_match:
        try:
            weight = int(weight_match.group(1))
            if weight >= 8: return RuleSeverity.CRITICAL
            if weight >= 5: return RuleSeverity.HIGH
            if weight >= 3: return RuleSeverity.MEDIUM
            # weight 低的默认为 MEDIUM (积分类规则)
            return RuleSeverity.MEDIUM 
        except:
            pass
            
    # 4. 启发式匹配
    name_lower = rule_name.lower()
    if name_lower:
        if "apt" in name_lower: return RuleSeverity.HIGH
        if "ransom" in name_lower: return RuleSeverity.CRITICAL
        if "malware" in name_lower: return RuleSeverity.HIGH
        if "exploit" in name_lower: return RuleSeverity.HIGH
        if "cve" in name_lower: return RuleSeverity.HIGH
        if "hacktool" in name_lower: return RuleSeverity.MEDIUM
        if "pua" in name_lower: return RuleSeverity.MEDIUM
        if "adware" in name_lower: return RuleSeverity.LOW

    return RuleSeverity.MEDIUM

def fix_rules():
    logger.info("开始修复 YARA 规则威胁等级 (增强版)...")
    
    # 连接数据库
    engine = create_engine(settings.DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    
    try:
        rules = session.query(YaraRule).all()
        logger.info(f"找到 {len(rules)} 条规则")
        
        updated_count = 0
        
        for rule in rules:
            # 强制重新计算
            new_severity = parse_severity(rule.content, rule.name)
            
            if rule.severity != new_severity:
                # logger.info(f"Update {rule.name}: {rule.severity} -> {new_severity}")
                rule.severity = new_severity
                updated_count += 1
        
        session.commit()
        logger.info(f"修复完成! 共更新了 {updated_count} 条规则的威胁等级。")
        
    except Exception as e:
        logger.error(f"修复过程中出错: {e}")
        session.rollback()
    finally:
        session.close()

if __name__ == "__main__":
    fix_rules()
