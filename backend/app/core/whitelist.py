"""
白名单管理模块
支持自定义白名单（文本文件/JSON）和 NSRL 数据库
"""

import os
import json
import sqlite3
import logging
from typing import Set, Optional

logger = logging.getLogger(__name__)


class WhitelistManager:
    """白名单管理器（单例模式）"""
    
    _instance: Optional['WhitelistManager'] = None
    _whitelist_hashes: Set[str]
    _nsrl_db_path: Optional[str] = None
    _custom_whitelist_path: str = "whitelist.json"
    _text_whitelist_path: str = "whitelist.txt"

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(WhitelistManager, cls).__new__(cls)
            cls._instance._whitelist_hashes = set()
            cls._instance._load_custom_whitelist()
            cls._instance._load_text_whitelist()
            cls._instance._init_nsrl_db()
        return cls._instance

    def _load_text_whitelist(self):
        """从文本文件加载白名单（每行一个哈希，支持 # 注释）"""
        if os.path.exists(self._text_whitelist_path):
            try:
                with open(self._text_whitelist_path, 'r', encoding='utf-8') as f:
                    count = 0
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self._whitelist_hashes.add(line.upper())
                            count += 1
                logger.info(f"Loaded {count} hashes from text whitelist: {self._text_whitelist_path}")
            except Exception as e:
                logger.error(f"Failed to load text whitelist: {e}")

    def _load_custom_whitelist(self):
        """加载自定义白名单 (JSON)"""
        if os.path.exists(self._custom_whitelist_path):
            try:
                with open(self._custom_whitelist_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for hash_val in data:
                            if hash_val:
                                self._whitelist_hashes.add(str(hash_val).upper())
                        logger.info(f"Loaded {len(data)} hashes from JSON whitelist: {self._custom_whitelist_path}")
            except Exception as e:
                logger.error(f"Failed to load JSON whitelist: {e}")

    def _init_nsrl_db(self):
        """初始化 NSRL 数据库（如果存在）"""
        # 尝试查找 NSRL 数据库
        # 优先查找 NIST RDS 数据库，然后是本地生成的 nsrl.db
        possible_paths = [
            "RDS_2025.03.1_modern_minimal.db",
            "../RDS_2025.03.1_modern_minimal.db",
            "nsrl.db",
            "data/nsrl.db",
            "../data/nsrl.db"
        ]
        for path in possible_paths:
            if os.path.exists(path):
                self._nsrl_db_path = path
                logger.info(f"Found NSRL database at {path}")
                # 如果数据库较小 (<500MB)，尝试加载到内存 Set 以提高速度
                # 否则使用磁盘索引查询
                try:
                    size_mb = os.path.getsize(path) / (1024 * 1024)
                    if size_mb < 500:
                        logger.info(f"Database is small ({size_mb:.2f} MB), loading into memory...")
                        self._load_db_to_memory(path)
                    else:
                        logger.info(f"Database is large ({size_mb:.2f} MB), using disk-based lookup.")
                except Exception as e:
                    logger.error(f"Error checking DB size: {e}")
                break

    def _load_db_to_memory(self, db_path: str):
        """将小型数据库加载到内存 Set"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT sha256 FROM FILE")
            hashes = cursor.fetchall()
            count = 0
            for (h,) in hashes:
                if h:
                    self._whitelist_hashes.add(str(h).upper())
                    count += 1
            conn.close()
            logger.info(f"Loaded {count} hashes from NSRL DB into memory.")
        except Exception as e:
            logger.error(f"Failed to load NSRL DB to memory: {e}")

    def is_whitelisted(self, file_hash: str) -> bool:
        """检查文件哈希是否在白名单中"""
        if not file_hash:
            return False
        
        file_hash_upper = file_hash.upper()
        
        # 1. 检查内存中的自定义白名单 (O(1))
        if file_hash_upper in self._whitelist_hashes:
            return True
        
        # 2. 检查 NSRL 数据库 (如果存在且未加载到内存)
        if self._nsrl_db_path:
            return self._check_nsrl(file_hash_upper)
            
        return False

    def _check_nsrl(self, file_hash: str) -> bool:
        """查询 NSRL SQLite 数据库"""
        try:
            # 注意：在多线程环境中，SQLite 连接不能共享，需要每次创建或使用线程局部存储
            # 这里为了简单和安全，每次查询创建连接（对于 SQLite 来说开销相对较小，但高并发下建议优化）
            conn = sqlite3.connect(self._nsrl_db_path)
            cursor = conn.cursor()
            
            # 假设表名为 FILE，列名为 sha256 (根据 RDSv3 Minimal 结构调整)
            cursor.execute("SELECT 1 FROM FILE WHERE sha256 = ? LIMIT 1", (file_hash,))
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return True
                
            # 尝试小写查询（某些数据库可能使用小写）
            conn = sqlite3.connect(self._nsrl_db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM FILE WHERE sha256 = ? LIMIT 1", (file_hash.lower(),))
            result = cursor.fetchone()
            conn.close()
            
            return result is not None
            
        except Exception as e:
            logger.error(f"NSRL lookup error: {e}")
            return False

    def add(self, file_hash: str):
        """添加哈希到内存白名单（兼容旧接口）"""
        if file_hash:
            self._whitelist_hashes.add(file_hash.upper())
            self._save_custom_whitelist()

    def add_to_whitelist(self, file_hash: str):
        """添加哈希到内存白名单（新接口）"""
        self.add(file_hash)

    def remove(self, file_hash: str):
        """从白名单移除哈希"""
        if file_hash:
            self._whitelist_hashes.discard(file_hash.upper())
            self._save_custom_whitelist()

    def _save_custom_whitelist(self):
        """保存自定义白名单到 JSON 文件"""
        try:
            # 只保存非 NSRL 的哈希（如果 NSRL 已加载到内存，需要区分）
            # 这里简化处理，保存所有内存中的哈希
            with open(self._custom_whitelist_path, 'w', encoding='utf-8') as f:
                json.dump(sorted(self._whitelist_hashes), f, indent=2)
            logger.info(f"Saved {len(self._whitelist_hashes)} hashes to {self._custom_whitelist_path}")
        except Exception as e:
            logger.error(f"Failed to save custom whitelist: {e}")

    def reload(self):
        """重新加载白名单"""
        self._whitelist_hashes.clear()
        self._load_custom_whitelist()
        self._load_text_whitelist()
        # NSRL 数据库路径不变，如果之前已加载到内存，需要重新加载
        if self._nsrl_db_path:
            try:
                size_mb = os.path.getsize(self._nsrl_db_path) / (1024 * 1024)
                if size_mb < 500:
                    self._load_db_to_memory(self._nsrl_db_path)
            except Exception:
                pass


# 全局单例
whitelist_manager = WhitelistManager()

