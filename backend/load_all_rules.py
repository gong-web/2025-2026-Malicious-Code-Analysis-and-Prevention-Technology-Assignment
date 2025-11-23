"""
批量加载 data/rules 目录下的所有 YARA 规则到数据库
"""

import os
import sys
from pathlib import Path
from sqlalchemy.orm import Session

# 添加项目根目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent))

from app.core.database import SessionLocal, engine
from app.models.rule import YaraRule, RuleStatus, RuleSeverity, Base
import yara


def init_database():
    """初始化数据库表"""
    print("正在初始化数据库...")
    Base.metadata.create_all(bind=engine)
    print("数据库初始化完成！")


def load_rules_from_directory(directory: str, db: Session):
    """
    从指定目录加载所有 .yar 和 .yara 文件
    """
    rules_dir = Path(directory)
    
    if not rules_dir.exists():
        print(f"错误: 目录 {directory} 不存在")
        return
    
    # 获取所有 YARA 规则文件
    yara_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
    
    print(f"\n找到 {len(yara_files)} 个 YARA 规则文件")
    print("=" * 60)
    
    success_count = 0
    skip_count = 0
    error_count = 0
    
    for yara_file in yara_files:
        rule_name = yara_file.stem  # 文件名（不含扩展名）
        
        try:
            # 检查规则是否已存在
            existing = db.query(YaraRule).filter(YaraRule.name == rule_name).first()
            if existing:
                print(f"⏩ 跳过 (已存在): {rule_name}")
                skip_count += 1
                continue
            
            # 读取规则内容
            with open(yara_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 验证 YARA 规则语法
            try:
                yara.compile(source=content)
            except yara.SyntaxError as e:
                print(f"❌ 语法错误: {rule_name} - {str(e)[:50]}")
                error_count += 1
                continue
            
            # 根据文件名推断类别和严重程度
            category = "general"
            severity = RuleSeverity.MEDIUM
            
            if "apt_" in rule_name.lower():
                category = "APT"
                severity = RuleSeverity.HIGH
            elif "ransom" in rule_name.lower():
                category = "Ransomware"
                severity = RuleSeverity.CRITICAL
            elif "crime_" in rule_name.lower():
                category = "Crime"
                severity = RuleSeverity.MEDIUM
            elif "exploit_" in rule_name.lower() or "expl_" in rule_name.lower():
                category = "Exploit"
                severity = RuleSeverity.HIGH
            elif "rat_" in rule_name.lower():
                category = "RAT"
                severity = RuleSeverity.HIGH
            elif "malw_" in rule_name.lower():
                category = "Malware"
                severity = RuleSeverity.MEDIUM
            elif "gen_" in rule_name.lower():
                category = "Generic"
                severity = RuleSeverity.LOW
            elif "webshell" in rule_name.lower():
                category = "Webshell"
                severity = RuleSeverity.HIGH
            elif "toolkit" in rule_name.lower():
                category = "Toolkit"
                severity = RuleSeverity.MEDIUM
            elif "pua_" in rule_name.lower():
                category = "PUA"
                severity = RuleSeverity.LOW
            
            # 创建规则记录
            db_rule = YaraRule(
                name=rule_name,
                description=f"从 {yara_file.name} 加载",
                content=content,
                category=category,
                severity=severity,
                status=RuleStatus.ACTIVE,
                author="Auto-imported",
                version="1.0"
            )
            
            db.add(db_rule)
            db.commit()
            
            print(f"✅ 成功: {rule_name} ({category}, {severity.value})")
            success_count += 1
            
        except Exception as e:
            print(f"❌ 错误: {rule_name} - {str(e)[:50]}")
            error_count += 1
            db.rollback()
    
    print("\n" + "=" * 60)
    print(f"✅ 成功加载: {success_count} 个规则")
    print(f"⏩ 已存在跳过: {skip_count} 个规则")
    print(f"❌ 失败: {error_count} 个规则")
    print(f"📊 总计: {len(yara_files)} 个文件")
    print("=" * 60)


def main():
    """主函数"""
    # 初始化数据库
    init_database()
    
    # 获取数据库会话
    db = SessionLocal()
    
    try:
        # 规则目录（相对于项目根目录）
        project_root = Path(__file__).parent.parent
        rules_directory = project_root / "data" / "rules"
        
        print(f"\n📂 规则目录: {rules_directory}")
        
        # 加载规则
        load_rules_from_directory(str(rules_directory), db)
        
        # 统计信息
        total_rules = db.query(YaraRule).count()
        active_rules = db.query(YaraRule).filter(YaraRule.status == RuleStatus.ACTIVE).count()
        
        print(f"\n📈 数据库统计:")
        print(f"   总规则数: {total_rules}")
        print(f"   活动规则: {active_rules}")
        
    except Exception as e:
        print(f"\n❌ 发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
    
    finally:
        db.close()
        print("\n✅ 规则加载完成！")


if __name__ == "__main__":
    main()
