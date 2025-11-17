"""
共享的数据库模型 - 适配 data.sqlite
"""

from sqlalchemy import Column, Integer, String, Text, Boolean
from app.core.database import Base

class Rule(Base):
    """规则表模型"""
    __tablename__ = "rules"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    path = Column(Text, nullable=False)
    active = Column(Boolean, default=True)
    version = Column(String, default="1.0")
    revision = Column(Integer, default=1)
    match_count = Column(Integer, default=0)
    false_positive_count = Column(Integer, default=0)
    compile_time_ms = Column(Integer, default=0)
    complexity_score = Column(Integer, default=0)
    avg_match_time_ms = Column(Integer, default=0)
    last_tested_at = Column(String)

class Sample(Base):
    """样本表模型"""
    __tablename__ = "samples"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False)
    path = Column(Text, nullable=False)

class Scan(Base):
    """扫描记录表模型"""
    __tablename__ = "scans"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False)
    status = Column(String, nullable=False)
    result = Column(Text)
    started_at = Column(String, nullable=False)
    finished_at = Column(String)
