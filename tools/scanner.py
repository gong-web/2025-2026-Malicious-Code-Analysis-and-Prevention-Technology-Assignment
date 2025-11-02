#!/usr/bin/env python3
"""
文件扫描工具
使用 YARA 规则扫描文件或目录
"""

import os
import sys
import argparse
import yara
import hashlib
from pathlib import Path
from typing import List, Dict

# 添加父目录到路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app.core.database import SessionLocal
from backend.app.models.rule import YaraRule


class Scanner:
    """文件扫描器"""
    
    def __init__(self, rule_path: str = None):
        """
        初始化扫描器
        
        Args:
            rule_path: YARA 规则文件路径 (可选,否则从数据库加载)
        """
        self.rules = None
        
        if rule_path:
            self.load_rules_from_file(rule_path)
        else:
            self.load_rules_from_db()
    
    def load_rules_from_file(self, rule_path: str):
        """从文件加载 YARA 规则"""
        try:
            self.rules = yara.compile(filepath=rule_path)
            print(f"✅ 从文件加载规则: {rule_path}")
        except Exception as e:
            print(f"❌ 加载规则失败: {e}")
            sys.exit(1)
    
    def load_rules_from_db(self):
        """从数据库加载 YARA 规则"""
        try:
            db = SessionLocal()
            rules = db.query(YaraRule).filter(
                YaraRule.status == 'active'
            ).all()
            
            if not rules:
                print("⚠️  数据库中没有活动的 YARA 规则")
                sys.exit(1)
            
            # 编译规则
            rule_dict = {rule.name: rule.content for rule in rules}
            self.rules = yara.compile(sources=rule_dict)
            
            print(f"✅ 从数据库加载 {len(rules)} 条规则")
            
        except Exception as e:
            print(f"❌ 从数据库加载规则失败: {e}")
            sys.exit(1)
        finally:
            db.close()
    
    def scan_file(self, file_path: Path) -> Dict:
        """
        扫描单个文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            扫描结果
        """
        try:
            # 计算文件哈希
            file_hash = self._calculate_hash(file_path)
            
            # 扫描文件
            matches = self.rules.match(filepath=str(file_path))
            
            result = {
                'file_path': str(file_path),
                'file_name': file_path.name,
                'file_size': file_path.stat().st_size,
                'file_hash': file_hash,
                'is_malicious': len(matches) > 0,
                'matched_rules': [m.rule for m in matches],
                'threat_level': 'malicious' if matches else 'clean'
            }
            
            return result
            
        except Exception as e:
            print(f"❌ 扫描文件失败 [{file_path}]: {e}")
            return None
    
    def scan_directory(self, directory: Path, recursive: bool = True) -> List[Dict]:
        """
        扫描目录
        
        Args:
            directory: 目录路径
            recursive: 是否递归扫描
            
        Returns:
            扫描结果列表
        """
        results = []
        
        # 获取所有文件
        if recursive:
            files = [f for f in directory.rglob('*') if f.is_file()]
        else:
            files = [f for f in directory.glob('*') if f.is_file()]
        
        print(f"\n📂 扫描目录: {directory}")
        print(f"📄 找到 {len(files)} 个文件\n")
        
        for file_path in files:
            result = self.scan_file(file_path)
            if result:
                results.append(result)
                
                # 打印结果
                if result['is_malicious']:
                    print(f"🚨 恶意文件: {result['file_name']}")
                    print(f"   匹配规则: {', '.join(result['matched_rules'])}")
                else:
                    print(f"✅ 安全文件: {result['file_name']}")
        
        return results
    
    def _calculate_hash(self, file_path: Path) -> str:
        """计算文件 SHA256 哈希"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description='文件扫描工具 - 使用 YARA 规则检测恶意代码'
    )
    parser.add_argument(
        '-t', '--target',
        type=str,
        required=True,
        help='扫描目标 (文件或目录)'
    )
    parser.add_argument(
        '-r', '--rules',
        type=str,
        help='YARA 规则文件路径 (不指定则从数据库加载)'
    )
    parser.add_argument(
        '--recursive',
        action='store_true',
        help='递归扫描子目录'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='输出结果到 JSON 文件'
    )
    
    args = parser.parse_args()
    
    # 验证目标路径
    target_path = Path(args.target)
    if not target_path.exists():
        print(f"❌ 错误: 路径不存在 [{target_path}]")
        sys.exit(1)
    
    # 创建扫描器
    scanner = Scanner(args.rules)
    
    # 执行扫描
    if target_path.is_file():
        result = scanner.scan_file(target_path)
        if result:
            results = [result]
        else:
            results = []
    else:
        results = scanner.scan_directory(target_path, args.recursive)
    
    # 统计结果
    total = len(results)
    malicious = sum(1 for r in results if r['is_malicious'])
    clean = total - malicious
    
    print("\n" + "="*50)
    print("📊 扫描统计:")
    print(f"  总文件数: {total}")
    print(f"  安全文件: {clean}")
    print(f"  恶意文件: {malicious}")
    print("="*50)
    
    # 保存结果
    if args.output:
        import json
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n💾 结果已保存到: {args.output}")


if __name__ == '__main__':
    main()
