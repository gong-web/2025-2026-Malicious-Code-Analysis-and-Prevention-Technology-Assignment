#!/usr/bin/env python3
"""
演示脚本 - 创建示例 YARA 规则
"""

import os
import sys

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import SessionLocal
from app.models.rule import YaraRule, RuleStatus, RuleSeverity


def create_sample_rules():
    """创建示例规则"""
    db = SessionLocal()
    
    sample_rules = [
        {
            "name": "TestRule_HelloWorld",
            "description": "测试规则 - 检测包含 Hello World 的文件",
            "content": """rule TestRule_HelloWorld
{
    meta:
        description = "检测包含 Hello World 的文件"
        author = "YARA-X Manager"
        date = "2025-11-02"
    
    strings:
        $hello = "Hello World" nocase
    
    condition:
        $hello
}""",
            "category": "test",
            "tags": "test,demo",
            "severity": RuleSeverity.LOW,
            "status": RuleStatus.ACTIVE,
            "author": "Demo",
            "version": "1.0"
        },
        {
            "name": "Suspicious_PE_File",
            "description": "检测可疑的 PE 文件",
            "content": """rule Suspicious_PE_File
{
    meta:
        description = "检测可疑的 PE 可执行文件"
        author = "YARA-X Manager"
    
    strings:
        $mz = { 4D 5A }
        $pe = "PE" nocase
    
    condition:
        $mz at 0 and $pe
}""",
            "category": "malware",
            "tags": "pe,suspicious",
            "severity": RuleSeverity.MEDIUM,
            "status": RuleStatus.ACTIVE,
            "author": "Demo",
            "version": "1.0"
        },
        {
            "name": "Generic_Malware_Strings",
            "description": "通用恶意软件字符串检测",
            "content": """rule Generic_Malware_Strings
{
    meta:
        description = "检测常见恶意软件字符串"
        author = "YARA-X Manager"
    
    strings:
        $str1 = "cmd.exe" nocase
        $str2 = "powershell" nocase
        $str3 = "download" nocase
        $str4 = "execute" nocase
    
    condition:
        2 of them
}""",
            "category": "malware",
            "tags": "generic,strings",
            "severity": RuleSeverity.HIGH,
            "status": RuleStatus.TESTING,
            "author": "Demo",
            "version": "1.0"
        }
    ]
    
    try:
        for rule_data in sample_rules:
            # 检查是否已存在
            existing = db.query(YaraRule).filter(
                YaraRule.name == rule_data["name"]
            ).first()
            
            if existing:
                print(f"⚠️  规则已存在,跳过: {rule_data['name']}")
                continue
            
            # 创建规则
            rule = YaraRule(**rule_data)
            db.add(rule)
            db.commit()
            print(f"✅ 创建示例规则: {rule_data['name']}")
        
        print(f"\n🎉 完成! 共创建 {len(sample_rules)} 条示例规则")
        
    except Exception as e:
        print(f"❌ 错误: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    print("正在创建示例 YARA 规则...\n")
    create_sample_rules()
