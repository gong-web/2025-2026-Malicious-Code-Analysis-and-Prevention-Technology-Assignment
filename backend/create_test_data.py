"""
创建测试数据脚本
用于生成样本、规则和扫描记录,以便测试前端功能
"""

import sys
import os
from pathlib import Path
from datetime import datetime

# 添加项目路径
project_root = Path(__file__).parent.parent / "YARA-X Manager"
sys.path.insert(0, str(project_root))

from app.db import SessionLocal, engine, Base
from app.sql_models import Sample, Rule, Scan

def create_test_samples():
    """创建测试样本"""
    db = SessionLocal()
    
    # 创建测试样本目录
    samples_dir = project_root / "data" / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)
    
    test_samples = [
        {
            "filename": "malware_test.exe",
            "content": b"This is a fake malware sample for testing",
            "size": 42
        },
        {
            "filename": "suspicious_script.ps1",
            "content": b"Write-Host 'Test PowerShell script'",
            "size": 35
        },
        {
            "filename": "normal_file.txt",
            "content": b"This is a normal text file",
            "size": 26
        }
    ]
    
    for sample_data in test_samples:
        # 创建文件
        file_path = samples_dir / sample_data["filename"]
        file_path.write_bytes(sample_data["content"])
        
        # 检查是否已存在
        existing = db.query(Sample).filter(Sample.filename == sample_data["filename"]).first()
        if not existing:
            sample = Sample(
                filename=sample_data["filename"],
                path=str(file_path)
            )
            db.add(sample)
            print(f"✓ 创建样本: {sample_data['filename']}")
        else:
            print(f"- 样本已存在: {sample_data['filename']}")
    
    db.commit()
    db.close()
    print(f"\n样本文件保存在: {samples_dir}")

def create_test_rules():
    """创建测试规则"""
    db = SessionLocal()
    
    # 创建测试规则目录
    rules_dir = project_root / "data" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    
    test_rules = [
        {
            "name": "test_malware_detection",
            "content": """rule test_malware_detection
{
    meta:
        description = "Test rule for malware detection"
        author = "Test User"
        date = "2025-11-12"
    
    strings:
        $str1 = "malware" nocase
        $str2 = "virus" nocase
    
    condition:
        any of them
}
""",
            "active": True
        },
        {
            "name": "test_suspicious_behavior",
            "content": """rule test_suspicious_behavior
{
    meta:
        description = "Test rule for suspicious behavior"
        author = "Test User"
        date = "2025-11-12"
    
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $cmd3 = "suspicious" nocase
    
    condition:
        any of them
}
""",
            "active": True
        },
        {
            "name": "test_inactive_rule",
            "content": """rule test_inactive_rule
{
    meta:
        description = "Inactive test rule"
        author = "Test User"
        date = "2025-11-12"
    
    strings:
        $test = "inactive"
    
    condition:
        $test
}
""",
            "active": False
        }
    ]
    
    for rule_data in test_rules:
        # 创建规则文件
        file_path = rules_dir / f"{rule_data['name']}.yar"
        file_path.write_text(rule_data["content"], encoding="utf-8")
        
        # 检查是否已存在
        existing = db.query(Rule).filter(Rule.name == rule_data["name"]).first()
        if not existing:
            rule = Rule(
                name=rule_data["name"],
                path=str(file_path),
                active=rule_data["active"]
            )
            db.add(rule)
            print(f"✓ 创建规则: {rule_data['name']} (active={rule_data['active']})")
        else:
            print(f"- 规则已存在: {rule_data['name']}")
    
    db.commit()
    db.close()
    print(f"\n规则文件保存在: {rules_dir}")

def create_test_scans():
    """创建测试扫描记录"""
    db = SessionLocal()
    
    # 获取样本
    samples = db.query(Sample).all()
    if not samples:
        print("⚠ 没有找到样本,请先运行 create_test_samples()")
        db.close()
        return
    
    test_scans = [
        {
            "filename": samples[0].filename if samples else "test.exe",
            "status": "done",
            "result": '{"matches": [{"rule": "test_malware_detection", "strings": ["malware"], "offset": 0}]}',
            "started_at": "2025-11-12 10:00:00",
            "finished_at": "2025-11-12 10:00:05"
        },
        {
            "filename": samples[1].filename if len(samples) > 1 else "test2.ps1",
            "status": "done",
            "result": '{"matches": [{"rule": "test_suspicious_behavior", "strings": ["powershell"], "offset": 10}]}',
            "started_at": "2025-11-12 10:05:00",
            "finished_at": "2025-11-12 10:05:03"
        },
        {
            "filename": samples[2].filename if len(samples) > 2 else "test3.txt",
            "status": "done",
            "result": '{"matches": []}',
            "started_at": "2025-11-12 10:10:00",
            "finished_at": "2025-11-12 10:10:02"
        }
    ]
    
    for scan_data in test_scans:
        # 检查是否已存在
        existing = db.query(Scan).filter(Scan.filename == scan_data["filename"]).first()
        if not existing:
            scan = Scan(
                filename=scan_data["filename"],
                status=scan_data["status"],
                result=scan_data["result"],
                started_at=scan_data["started_at"],
                finished_at=scan_data["finished_at"]
            )
            db.add(scan)
            print(f"✓ 创建扫描记录: {scan_data['filename']} ({scan_data['status']})")
        else:
            print(f"- 扫描记录已存在: {scan_data['filename']}")
    
    db.commit()
    db.close()

def main():
    """主函数"""
    print("=" * 60)
    print("YARA-X Manager - 创建测试数据")
    print("=" * 60)
    
    # 确保数据库表存在
    print("\n1. 初始化数据库...")
    Base.metadata.create_all(bind=engine)
    print("✓ 数据库表已创建")
    
    # 创建测试数据
    print("\n2. 创建测试样本...")
    create_test_samples()
    
    print("\n3. 创建测试规则...")
    create_test_rules()
    
    print("\n4. 创建测试扫描记录...")
    create_test_scans()
    
    # 显示统计信息
    print("\n" + "=" * 60)
    print("数据创建完成! 统计信息:")
    print("=" * 60)
    
    db = SessionLocal()
    sample_count = db.query(Sample).count()
    rule_count = db.query(Rule).count()
    scan_count = db.query(Scan).count()
    active_rules = db.query(Rule).filter(Rule.active == True).count()
    db.close()
    
    print(f"样本数量: {sample_count}")
    print(f"规则数量: {rule_count} (活动: {active_rules})")
    print(f"扫描记录: {scan_count}")
    print("\n✓ 所有测试数据已创建!")
    print("\n下一步:")
    print("1. 启动后端服务: cd 'YARA-X Manager' && python -m app.main")
    print("2. 访问 http://localhost:8000/docs 查看API文档")
    print("3. 访问 http://localhost:3000 测试前端功能")

if __name__ == "__main__":
    main()
