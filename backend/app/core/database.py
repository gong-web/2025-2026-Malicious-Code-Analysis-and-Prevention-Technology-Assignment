"""
数据库连接和会话管理
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

# 创建数据库引擎
connect_args = {}
engine_args = {}

if "sqlite" in settings.DATABASE_URL:
    # SQLite Optimization
    connect_args = {
        "check_same_thread": False,
        "timeout": 30  # Increase timeout to prevent lock errors
    }
else:
    # PostgreSQL/MySQL Optimization (Connection Pooling)
    engine_args = {
        "pool_size": 20,        # Base number of connections
        "max_overflow": 40,     # Max extra connections allowed
        "pool_timeout": 60,     # Wait time before giving up
        "pool_recycle": 1800    # Recycle connections every 30 min
    }

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    **engine_args
)

# 创建会话
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 创建基类
Base = declarative_base()


def get_db():
    """获取数据库会话"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """初始化数据库"""
    Base.metadata.create_all(bind=engine)
