"""
整合数据库配置 - 支持YARA-X Manager和规则数据库
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from pathlib import Path
from contextlib import contextmanager

# YARA-X Manager 的SQLite数据库路径 (用于样本和扫描记录)
MANAGER_DB_PATH = Path(__file__).resolve().parent.parent / "data.sqlite"

# 规则数据库路径 (从远程仓库拉取的规则数据库)
RULES_DB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "db" / "schema" / "rules_database.db"

# 创建 Manager 数据库引擎
manager_engine = create_engine(
    f"sqlite:///{MANAGER_DB_PATH}",
    connect_args={"check_same_thread": False}
)

# 创建规则数据库引擎 (只读模式)
rules_engine = create_engine(
    f"sqlite:///{RULES_DB_PATH}",
    connect_args={"check_same_thread": False}
)

# 生成数据库会话工厂
ManagerSessionLocal = sessionmaker(
    bind=manager_engine,
    autocommit=False,
    autoflush=False
)

RulesSessionLocal = sessionmaker(
    bind=rules_engine,
    autocommit=False,
    autoflush=False
)

# Manager数据库的Base类
Base = declarative_base()

# Manager数据库会话生成器
def get_db():
    db = ManagerSessionLocal()
    try:
        yield db
    finally:
        db.close()

@contextmanager
def get_db_session():
    db = ManagerSessionLocal()
    try:
        yield db
    finally:
        db.close()

# 规则数据库会话生成器
@contextmanager
def get_rules_db_session():
    db = RulesSessionLocal()
    try:
        yield db
    finally:
        db.close()
