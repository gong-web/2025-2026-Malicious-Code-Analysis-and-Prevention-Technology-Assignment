"""
初始化脚本
创建数据库表
"""

import sys
import os

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.database import init_db

if __name__ == "__main__":
    print("正在初始化数据库...")
    init_db()
    print("✅ 数据库初始化完成!")
