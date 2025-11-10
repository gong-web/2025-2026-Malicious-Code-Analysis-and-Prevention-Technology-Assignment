#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则导入脚本
将现有的YARA和Sigma规则导入到数据库中
"""

import sqlite3
import hashlib
import yaml
from pathlib import Path
from datetime import datetime
import json
import re

class RulesImporter:
    """规则导入器"""
    
    def __init__(self, db_path: str = "rules_database.db"):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.imported_count = 0
        self.skipped_count = 0
        
    def close(self):
        """关闭数据库连接"""
        self.conn.close()
    
    def calculate_file_hash(self, file_path: Path) -> str:
        """计算文件哈希"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def extract_yara_metadata(self, file_path: Path) -> dict:
        """提取YARA规则元数据"""
        metadata = {
            'description': '',
            'author': '',
            'source': 'yara-rules',
            'mitre_attack_tags': [],
            'platform': 'all',
            'threat_type': 'unknown'
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # 提取meta部分
            meta_match = re.search(r'meta:\s*\n((?:\s+.*\n)*)', content)
            if meta_match:
                meta_content = meta_match.group(1)
                # 提取description
                desc_match = re.search(r'description\s*=\s*["\']([^"\']+)["\']', meta_content)
                if desc_match:
                    metadata['description'] = desc_match.group(1)
                
                # 提取author
                author_match = re.search(r'author\s*=\s*["\']([^"\']+)["\']', meta_content)
                if author_match:
                    metadata['author'] = author_match.group(1)
            
            # 从文件路径推断分类和平台
            path_parts = file_path.parts
            if 'windows' in str(file_path).lower():
                metadata['platform'] = 'windows'
            elif 'linux' in str(file_path).lower():
                metadata['platform'] = 'linux'
            elif 'macos' in str(file_path).lower():
                metadata['platform'] = 'macos'
            
            # 推断威胁类型
            if 'malware' in str(file_path).lower():
                metadata['threat_type'] = 'malware'
            elif 'apt' in str(file_path).lower():
                metadata['threat_type'] = 'apt'
            elif 'ransomware' in str(file_path).lower():
                metadata['threat_type'] = 'ransomware'
            elif 'cve' in str(file_path).lower():
                metadata['threat_type'] = 'cve'
                
        except Exception as e:
            print(f"  警告: 无法解析YARA规则 {file_path}: {e}")
        
        return metadata
    
    def extract_sigma_metadata(self, file_path: Path) -> dict:
        """提取Sigma规则元数据"""
        metadata = {
            'description': '',
            'author': '',
            'source': 'sigmahq',
            'mitre_attack_tags': [],
            'platform': 'unknown',
            'threat_type': 'unknown'
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)
            
            if rule_data:
                metadata['description'] = rule_data.get('description', '')
                metadata['author'] = rule_data.get('author', 'Unknown')
                
                # 提取MITRE ATT&CK标签
                tags = rule_data.get('tags', [])
                attack_tags = [tag for tag in tags if tag.startswith('attack.')]
                metadata['mitre_attack_tags'] = json.dumps(attack_tags)
                
                # 提取平台信息
                logsource = rule_data.get('logsource', {})
                product = logsource.get('product', 'unknown')
                if product == 'windows':
                    metadata['platform'] = 'windows'
                elif product == 'linux':
                    metadata['platform'] = 'linux'
                elif product == 'macos':
                    metadata['platform'] = 'macos'
                else:
                    metadata['platform'] = product
                
                # 推断威胁类型
                title = rule_data.get('title', '').lower()
                if 'malware' in title:
                    metadata['threat_type'] = 'malware'
                elif 'apt' in title:
                    metadata['threat_type'] = 'apt'
                elif 'ransomware' in title:
                    metadata['threat_type'] = 'ransomware'
                    
        except Exception as e:
            print(f"  警告: 无法解析Sigma规则 {file_path}: {e}")
        
        return metadata
    
    def import_yara_rule(self, file_path: Path, category: str = None):
        """导入YARA规则"""
        if not file_path.exists():
            return False
        
        rule_name = file_path.stem
        file_hash = self.calculate_file_hash(file_path)
        
        # 计算相对路径，处理绝对路径和相对路径
        try:
            relative_path = str(file_path.relative_to(Path.cwd()))
        except ValueError:
            # 如果是绝对路径，使用绝对路径
            relative_path = str(file_path)
        
        # 如果没有指定分类，从路径推断
        if not category:
            path_parts = file_path.parts
            if len(path_parts) > 1:
                # 查找organized目录的位置
                if 'organized' in path_parts:
                    org_idx = path_parts.index('organized')
                    if org_idx + 1 < len(path_parts):
                        category = path_parts[org_idx + 1]
                    else:
                        category = 'unknown'
                elif 'rules_repo' in path_parts:
                    repo_idx = path_parts.index('rules_repo')
                    if repo_idx + 1 < len(path_parts):
                        category = path_parts[repo_idx + 1]
                    else:
                        category = 'unknown'
                else:
                    category = path_parts[-2] if len(path_parts) > 1 else 'unknown'
            else:
                category = 'unknown'
        
        cursor = self.conn.cursor()
        
        # 检查是否已存在
        cursor.execute('''
            SELECT id FROM rules 
            WHERE rule_name = ? AND rule_type = ? AND file_path = ?
        ''', (rule_name, 'yara', relative_path))
        
        if cursor.fetchone():
            self.skipped_count += 1
            return False
        
        # 提取元数据
        metadata = self.extract_yara_metadata(file_path)
        
        # 插入规则
        cursor.execute('''
            INSERT INTO rules (rule_name, rule_type, category, file_path, file_hash, status, priority)
            VALUES (?, ?, ?, ?, ?, 'active', 5)
        ''', (rule_name, 'yara', category, relative_path, file_hash))
        
        rule_id = cursor.lastrowid
        
        # 插入元数据
        # 确保mitre_attack_tags是JSON字符串
        mitre_tags = metadata['mitre_attack_tags']
        if isinstance(mitre_tags, list):
            mitre_tags_json = json.dumps(mitre_tags)
        elif isinstance(mitre_tags, str):
            mitre_tags_json = mitre_tags
        else:
            mitre_tags_json = '[]'
        
        cursor.execute('''
            INSERT INTO rule_metadata 
            (rule_id, description, author, source, mitre_attack_tags, platform, threat_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule_id,
            metadata['description'],
            metadata['author'],
            metadata['source'],
            mitre_tags_json,
            metadata['platform'],
            metadata['threat_type']
        ))
        
        # 创建索引
        keywords = [rule_name, category, metadata['platform'], metadata['threat_type']]
        for keyword in keywords:
            if keyword and keyword != 'unknown':
                # 确保keyword是字符串
                keyword_str = str(keyword).lower()
                cursor.execute('''
                    INSERT INTO rule_index (rule_id, keyword, index_type)
                    VALUES (?, ?, ?)
                ''', (rule_id, keyword_str, 'name'))
        
        self.conn.commit()
        self.imported_count += 1
        return True
    
    def import_sigma_rule(self, file_path: Path, category: str = None):
        """导入Sigma规则"""
        if not file_path.exists():
            return False
        
        rule_name = file_path.stem
        file_hash = self.calculate_file_hash(file_path)
        
        # 计算相对路径，处理绝对路径和相对路径
        try:
            relative_path = str(file_path.relative_to(Path.cwd()))
        except ValueError:
            # 如果是绝对路径，使用绝对路径
            relative_path = str(file_path)
        
        # 如果没有指定分类，从路径推断
        if not category:
            path_parts = file_path.parts
            if len(path_parts) > 1:
                # 查找rules目录的位置
                if 'rules' in path_parts:
                    rules_idx = path_parts.index('rules')
                    if rules_idx + 1 < len(path_parts):
                        # 取rules后面的路径作为分类
                        category = '/'.join(path_parts[rules_idx + 1:-1])
                    else:
                        category = 'unknown'
                else:
                    category = '/'.join(path_parts[-3:-1]) if len(path_parts) > 2 else path_parts[-2]
            else:
                category = 'unknown'
        
        cursor = self.conn.cursor()
        
        # 检查是否已存在
        cursor.execute('''
            SELECT id FROM rules 
            WHERE rule_name = ? AND rule_type = ? AND file_path = ?
        ''', (rule_name, 'sigma', relative_path))
        
        if cursor.fetchone():
            self.skipped_count += 1
            return False
        
        # 提取元数据
        metadata = self.extract_sigma_metadata(file_path)
        
        # 插入规则
        cursor.execute('''
            INSERT INTO rules (rule_name, rule_type, category, file_path, file_hash, status, priority)
            VALUES (?, ?, ?, ?, ?, 'active', 5)
        ''', (rule_name, 'sigma', category, relative_path, file_hash))
        
        rule_id = cursor.lastrowid
        
        # 插入元数据
        # 确保mitre_attack_tags是JSON字符串
        mitre_tags = metadata['mitre_attack_tags']
        if isinstance(mitre_tags, list):
            mitre_tags_json = json.dumps(mitre_tags)
        elif isinstance(mitre_tags, str):
            mitre_tags_json = mitre_tags
        else:
            mitre_tags_json = '[]'
        
        cursor.execute('''
            INSERT INTO rule_metadata 
            (rule_id, description, author, source, mitre_attack_tags, platform, threat_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule_id,
            metadata['description'],
            metadata['author'],
            metadata['source'],
            mitre_tags_json,
            metadata['platform'],
            metadata['threat_type']
        ))
        
        # 创建索引
        keywords = [rule_name, category, metadata['platform'], metadata['threat_type']]
        for keyword in keywords:
            if keyword and keyword != 'unknown':
                # 确保keyword是字符串
                keyword_str = str(keyword).lower()
                cursor.execute('''
                    INSERT INTO rule_index (rule_id, keyword, index_type)
                    VALUES (?, ?, ?)
                ''', (rule_id, keyword_str, 'name'))
        
        self.conn.commit()
        self.imported_count += 1
        return True
    
    def import_directory(self, directory: Path, rule_type: str = 'auto', show_progress: bool = True):
        """导入目录中的所有规则"""
        if not directory.exists():
            print(f"目录不存在: {directory}")
            return
        
        print(f"\n导入目录: {directory}")
        
        if rule_type == 'auto':
            # 自动检测类型
            if 'sigma' in str(directory).lower():
                rule_type = 'sigma'
            else:
                rule_type = 'yara'
        
        if rule_type == 'yara':
            files = list(directory.rglob("*.yar")) + list(directory.rglob("*.yara"))
            import_func = self.import_yara_rule
        else:
            files = list(directory.rglob("*.yml"))
            import_func = self.import_sigma_rule
        
        print(f"找到 {len(files)} 个规则文件")
        
        # 使用tqdm显示进度（如果可用）
        try:
            from tqdm import tqdm
            file_iter = tqdm(files, desc="导入中", unit="文件")
        except ImportError:
            file_iter = files
            if show_progress and len(files) > 100:
                print("提示: 安装tqdm可显示进度条 (pip install tqdm)")
        
        for file_path in file_iter:
            try:
                import_func(file_path)
            except Exception as e:
                if show_progress:
                    print(f"  错误: 导入失败 {file_path}: {e}")
        
        print(f"导入完成: {self.imported_count} 个规则, {self.skipped_count} 个跳过")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='导入规则到数据库')
    parser.add_argument('--db', default='rules_database.db', help='数据库文件路径')
    parser.add_argument('--yara', help='YARA规则目录')
    parser.add_argument('--sigma', help='Sigma规则目录')
    parser.add_argument('--all', action='store_true', help='导入所有规则')
    args = parser.parse_args()
    
    importer = RulesImporter(args.db)
    
    if args.all:
        # 导入所有规则
        base_dir = Path('.')
        
        # 导入YARA规则
        yara_dirs = [
            base_dir / 'yara_rules' / 'organized',
            base_dir / 'yara_rules_additional' / 'organized'
        ]
        
        for yara_dir in yara_dirs:
            if yara_dir.exists():
                importer.import_directory(yara_dir, 'yara')
        
        # 导入Sigma规则
        sigma_dirs = [
            base_dir / 'sigma_all_rules' / 'rules',
            base_dir / 'sigma_all_rules' / 'rules-emerging-threats'
        ]
        
        for sigma_dir in sigma_dirs:
            if sigma_dir.exists():
                importer.import_directory(sigma_dir, 'sigma')
    
    elif args.yara:
        importer.import_directory(Path(args.yara), 'yara')
    
    elif args.sigma:
        importer.import_directory(Path(args.sigma), 'sigma')
    
    else:
        print("请指定要导入的规则目录或使用 --all 导入所有规则")
        print("示例:")
        print("  python import_rules.py --all")
        print("  python import_rules.py --yara yara_rules/organized")
        print("  python import_rules.py --sigma sigma_all_rules/rules")
        return
    
    print(f"\n总计: 导入 {importer.imported_count} 个规则, 跳过 {importer.skipped_count} 个规则")
    importer.close()


if __name__ == "__main__":
    main()

