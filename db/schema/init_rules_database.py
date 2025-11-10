#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
杀毒软件规则数据库初始化脚本
创建SQLite数据库并建立表结构
"""

import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime
import json

class RulesDatabaseManager:
    """规则数据库管理器"""
    
    def __init__(self, db_path: str = "rules_database.db"):
        self.db_path = Path(db_path)
        self.conn = None
        
    def connect(self):
        """连接数据库"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")  # 启用WAL模式提高性能
        self.conn.row_factory = sqlite3.Row  # 返回字典格式
        return self.conn
    
    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()
    
    def init_database(self):
        """初始化数据库表结构"""
        conn = self.connect()
        cursor = conn.cursor()
        
        print("=" * 80)
        print("初始化规则数据库")
        print("=" * 80)
        
        # 1. 规则主表
        print("\n[1/5] 创建规则主表...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                rule_type TEXT NOT NULL CHECK(rule_type IN ('yara', 'sigma')),
                category TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT,
                status TEXT DEFAULT 'active' CHECK(status IN ('active', 'disabled', 'deprecated')),
                priority INTEGER DEFAULT 5 CHECK(priority >= 1 AND priority <= 10),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP,
                version TEXT,
                UNIQUE(rule_name, rule_type, file_path)
            )
        ''')
        
        # 2. 规则元数据表
        print("[2/5] 创建规则元数据表...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rule_metadata (
                rule_id INTEGER PRIMARY KEY,
                description TEXT,
                author TEXT,
                source TEXT,
                mitre_attack_tags TEXT,
                platform TEXT,
                threat_type TEXT,
                false_positive_rate REAL DEFAULT 0.0 CHECK(false_positive_rate >= 0 AND false_positive_rate <= 1),
                detection_rate REAL DEFAULT 0.0 CHECK(detection_rate >= 0 AND detection_rate <= 1),
                FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
            )
        ''')
        
        # 3. 规则版本历史表
        print("[3/5] 创建规则版本历史表...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rule_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL,
                version TEXT NOT NULL,
                file_hash TEXT,
                change_log TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
            )
        ''')
        
        # 4. 规则索引表
        print("[4/5] 创建规则索引表...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rule_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL,
                keyword TEXT NOT NULL,
                index_type TEXT NOT NULL CHECK(index_type IN ('name', 'tag', 'category', 'platform', 'threat')),
                FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
            )
        ''')
        
        # 5. 规则使用统计表
        print("[5/5] 创建规则使用统计表...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rule_statistics (
                rule_id INTEGER PRIMARY KEY,
                scan_count INTEGER DEFAULT 0,
                match_count INTEGER DEFAULT 0,
                false_positive_count INTEGER DEFAULT 0,
                last_used TIMESTAMP,
                last_matched TIMESTAMP,
                FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
            )
        ''')
        
        # 创建索引
        print("\n创建索引...")
        indexes = [
            ("idx_rule_type", "rules", "rule_type"),
            ("idx_category", "rules", "category"),
            ("idx_status", "rules", "status"),
            ("idx_priority", "rules", "priority"),
            ("idx_rule_name", "rules", "rule_name"),
            ("idx_keyword", "rule_index", "keyword"),
            ("idx_index_type", "rule_index", "index_type"),
        ]
        
        for idx_name, table, column in indexes:
            try:
                cursor.execute(f'CREATE INDEX IF NOT EXISTS {idx_name} ON {table}({column})')
            except sqlite3.OperationalError:
                pass
        
        conn.commit()
        print("\n数据库初始化完成！")
        
        # 显示表信息
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print(f"\n已创建 {len(tables)} 个表:")
        for table in tables:
            print(f"  - {table[0]}")
        
        return True
    
    def get_stats(self):
        """获取数据库统计信息"""
        conn = self.connect()
        cursor = conn.cursor()
        
        stats = {}
        
        # 规则总数
        cursor.execute("SELECT COUNT(*) FROM rules")
        stats['total_rules'] = cursor.fetchone()[0]
        
        # 按类型统计
        cursor.execute("SELECT rule_type, COUNT(*) FROM rules GROUP BY rule_type")
        stats['by_type'] = dict(cursor.fetchall())
        
        # 按状态统计
        cursor.execute("SELECT status, COUNT(*) FROM rules GROUP BY status")
        stats['by_status'] = dict(cursor.fetchall())
        
        # 按分类统计（Top 10）
        cursor.execute("SELECT category, COUNT(*) FROM rules GROUP BY category ORDER BY COUNT(*) DESC LIMIT 10")
        stats['top_categories'] = dict(cursor.fetchall())
        
        return stats


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='初始化规则数据库')
    parser.add_argument('--db', default='rules_database.db', help='数据库文件路径')
    parser.add_argument('--stats', action='store_true', help='显示数据库统计信息')
    args = parser.parse_args()
    
    manager = RulesDatabaseManager(args.db)
    
    if args.stats:
        if not manager.db_path.exists():
            print(f"数据库文件不存在: {args.db}")
            return
        stats = manager.get_stats()
        print("\n数据库统计信息:")
        print(f"  总规则数: {stats['total_rules']}")
        print(f"  按类型: {stats['by_type']}")
        print(f"  按状态: {stats['by_status']}")
        print(f"  主要分类: {stats['top_categories']}")
    else:
        manager.init_database()
    
    manager.close()


if __name__ == "__main__":
    main()


