#!/usr/bin/env python3
"""
YARA 规则加载器
用于批量导入 YARA 规则到数据库
"""

import os
import sys
import argparse
import yara
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# 添加父目录到路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app.models.rule import YaraRule, RuleStatus, RuleSeverity
from backend.app.core.database import Base


class YaraLoader:
    """YARA 规则加载器"""
    
    def __init__(self, database_url: str):
        self.engine = create_engine(database_url)
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine)
        self.db = SessionLocal()
    
    def load_rule_file(self, file_path: Path) -> bool:
        """
        加载单个 YARA 规则文件
        
        Args:
            file_path: 规则文件路径
            
        Returns:
            是否加载成功
        """
        try:
            # 读取规则内容
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 验证规则语法
            try:
                yara.compile(source=content)
            except yara.SyntaxError as e:
                print(f"❌ 规则语法错误 [{file_path.name}]: {e}")
                return False
            
            # 提取规则名称
            rule_name = file_path.stem
            
            # 检查是否已存在
            existing = self.db.query(YaraRule).filter(
                YaraRule.name == rule_name
            ).first()
            
            if existing:
                print(f"⚠️  规则已存在,跳过 [{rule_name}]")
                return False
            
            # 创建规则
            rule = YaraRule(
                name=rule_name,
                content=content,
                status=RuleStatus.ACTIVE,
                severity=RuleSeverity.MEDIUM,
                category=self._extract_category(file_path)
            )
            
            self.db.add(rule)
            self.db.commit()
            
            print(f"✅ 成功导入规则 [{rule_name}]")
            return True
            
        except Exception as e:
            print(f"❌ 导入失败 [{file_path.name}]: {e}")
            self.db.rollback()
            return False
    
    def load_directory(self, directory: Path, recursive: bool = True) -> dict:
        """
        批量加载目录中的 YARA 规则
        
        Args:
            directory: 规则目录
            recursive: 是否递归扫描子目录
            
        Returns:
            统计信息
        """
        stats = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'skipped': 0
        }
        
        # 获取所有 .yar 和 .yara 文件
        pattern = '**/*.yar*' if recursive else '*.yar*'
        rule_files = list(directory.glob(pattern))
        
        print(f"\n📂 扫描目录: {directory}")
        print(f"📄 找到 {len(rule_files)} 个规则文件\n")
        
        for file_path in rule_files:
            stats['total'] += 1
            result = self.load_rule_file(file_path)
            if result:
                stats['success'] += 1
            else:
                stats['skipped'] += 1
        
        return stats
    
    def _extract_category(self, file_path: Path) -> str:
        """从文件路径提取分类"""
        # 尝试从父目录名提取分类
        parent_dir = file_path.parent.name
        if parent_dir and parent_dir != '.':
            return parent_dir
        return 'general'
    
    def close(self):
        """关闭数据库连接"""
        self.db.close()


def main():
    parser = argparse.ArgumentParser(
        description='YARA 规则加载器 - 批量导入规则到数据库'
    )
    parser.add_argument(
        '-i', '--input',
        type=str,
        required=True,
        help='规则文件或目录路径'
    )
    parser.add_argument(
        '-d', '--database',
        type=str,
        default='sqlite:///./yara_manager.db',
        help='数据库连接 URL (默认: sqlite:///./yara_manager.db)'
    )
    parser.add_argument(
        '-r', '--recursive',
        action='store_true',
        help='递归扫描子目录'
    )
    
    args = parser.parse_args()
    
    # 验证输入路径
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"❌ 错误: 路径不存在 [{input_path}]")
        sys.exit(1)
    
    # 创建加载器
    loader = YaraLoader(args.database)
    
    try:
        if input_path.is_file():
            # 加载单个文件
            loader.load_rule_file(input_path)
        else:
            # 加载目录
            stats = loader.load_directory(input_path, args.recursive)
            
            # 打印统计信息
            print("\n" + "="*50)
            print("📊 导入统计:")
            print(f"  总计: {stats['total']}")
            print(f"  成功: {stats['success']}")
            print(f"  跳过: {stats['skipped']}")
            print(f"  失败: {stats['failed']}")
            print("="*50)
    
    finally:
        loader.close()


if __name__ == '__main__':
    main()
