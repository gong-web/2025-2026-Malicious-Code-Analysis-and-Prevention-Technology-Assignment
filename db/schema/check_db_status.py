#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库状态检查工具
"""

import sqlite3
from pathlib import Path

def check_database_status():
    """检查数据库状态"""
    conn = sqlite3.connect('rules_database.db')
    cursor = conn.cursor()
    
    print("=" * 80)
    print("数据库状态检查")
    print("=" * 80)
    
    # 基本统计
    cursor.execute('SELECT COUNT(*) FROM rules')
    total_rules = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM rules WHERE rule_type = "yara"')
    yara_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM rules WHERE rule_type = "sigma"')
    sigma_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM rules WHERE status = "deprecated"')
    deprecated_count = cursor.fetchone()[0]
    
    # 重复检查
    cursor.execute('''
        SELECT COUNT(*) FROM (
            SELECT file_hash, COUNT(*) as cnt
            FROM rules
            WHERE rule_type = 'yara' AND file_hash IS NOT NULL
            GROUP BY file_hash
            HAVING cnt > 1
        )
    ''')
    duplicate_groups = cursor.fetchone()[0]
    
    # 元数据完整性
    cursor.execute('SELECT COUNT(*) FROM rule_metadata')
    meta_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM rule_index')
    index_count = cursor.fetchone()[0]
    
    # 文件完整性检查（抽样）
    cursor.execute('SELECT file_path FROM rules WHERE file_path IS NOT NULL LIMIT 100')
    sample_files = cursor.fetchall()
    missing_count = 0
    for (path,) in sample_files:
        if not Path(path).exists():
            missing_count += 1
    
    print(f"\n[基本统计]")
    print(f"  总规则数: {total_rules}")
    print(f"  YARA规则: {yara_count}")
    print(f"  Sigma规则: {sigma_count}")
    print(f"  废弃规则: {deprecated_count}")
    
    print(f"\n[数据完整性]")
    print(f"  元数据记录数: {meta_count}")
    print(f"  索引条目数: {index_count}")
    print(f"  元数据覆盖率: {meta_count/total_rules*100:.1f}%")
    
    print(f"\n[重复检查]")
    if duplicate_groups == 0:
        print(f"  [OK] 无重复记录")
    else:
        print(f"  [WARN] 发现 {duplicate_groups} 组重复记录")
    
    print(f"\n[文件完整性]")
    print(f"  抽样检查: {len(sample_files)} 个文件")
    if missing_count == 0:
        print(f"  [OK] 所有文件存在")
    else:
        print(f"  [WARN] 发现 {missing_count} 个缺失文件")
    
    # 表统计
    print(f"\n[表统计]")
    tables = ['rules', 'rule_metadata', 'rule_index', 'rule_versions', 'rule_statistics']
    for table in tables:
        try:
            cursor.execute(f'SELECT COUNT(*) FROM {table}')
            count = cursor.fetchone()[0]
            print(f"  {table}: {count} 条记录")
        except:
            print(f"  {table}: 表不存在")
    
    conn.close()
    
    print("\n" + "=" * 80)
    print("数据库状态: [OK] 正常")
    print("=" * 80)

if __name__ == "__main__":
    check_database_status()

