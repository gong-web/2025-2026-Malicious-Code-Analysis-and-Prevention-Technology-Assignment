#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库查询脚本
查看规则数据库的统计信息
"""

import sqlite3
from pathlib import Path

def get_database_stats():
    """获取数据库统计信息"""
    db_path = Path("rules_database.db")
    if not db_path.exists():
        print("数据库文件不存在！")
        return
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # 总规则数
    cursor.execute("SELECT COUNT(*) FROM rules")
    total_rules = cursor.fetchone()[0]
    
    # 按类型统计
    cursor.execute("SELECT rule_type, COUNT(*) FROM rules GROUP BY rule_type")
    by_type = dict(cursor.fetchall())
    
    # 按分类统计（前10）
    cursor.execute("""
        SELECT category, COUNT(*) as cnt 
        FROM rules 
        GROUP BY category 
        ORDER BY cnt DESC 
        LIMIT 10
    """)
    by_category = cursor.fetchall()
    
    # 按平台统计
    cursor.execute("""
        SELECT platform, COUNT(*) as cnt 
        FROM rule_metadata 
        WHERE platform IS NOT NULL AND platform != 'unknown'
        GROUP BY platform 
        ORDER BY cnt DESC
    """)
    by_platform = cursor.fetchall()
    
    # 按威胁类型统计
    cursor.execute("""
        SELECT threat_type, COUNT(*) as cnt 
        FROM rule_metadata 
        WHERE threat_type IS NOT NULL AND threat_type != 'unknown'
        GROUP BY threat_type 
        ORDER BY cnt DESC
        LIMIT 10
    """)
    by_threat = cursor.fetchall()
    
    # 索引统计
    cursor.execute("SELECT COUNT(*) FROM rule_index")
    total_indexes = cursor.fetchone()[0]
    
    print("=" * 80)
    print("规则数据库统计信息")
    print("=" * 80)
    print(f"\n总规则数: {total_rules}")
    print(f"\n按类型统计:")
    for rule_type, count in by_type.items():
        print(f"  - {rule_type}: {count}")
    
    print(f"\n按分类统计 (前10):")
    for category, count in by_category:
        print(f"  - {category}: {count}")
    
    print(f"\n按平台统计:")
    for platform, count in by_platform:
        print(f"  - {platform}: {count}")
    
    print(f"\n按威胁类型统计 (前10):")
    for threat_type, count in by_threat:
        print(f"  - {threat_type}: {count}")
    
    print(f"\n索引条目数: {total_indexes}")
    
    conn.close()

if __name__ == "__main__":
    get_database_stats()

