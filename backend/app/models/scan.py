"""
扫描任务和结果数据模型
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Enum, Float, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class ScanStatus(str, enum.Enum):
    """扫描状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ThreatLevel(str, enum.Enum):
    """威胁级别"""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


class ScanTask(Base):
    """扫描任务模型"""
    __tablename__ = "scan_tasks"
    
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String(100), unique=True, index=True, nullable=False)
    
    # 扫描目标
    target_path = Column(String(1000), nullable=False)
    target_type = Column(String(50))  # file, directory
    
    # 扫描配置
    scan_type = Column(String(50))  # quick, full, custom
    use_rules = Column(Text)  # JSON list of rule IDs
    
    # 状态和进度
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    progress = Column(Float, default=0.0)
    
    # 统计信息
    total_files = Column(Integer, default=0)
    scanned_files = Column(Integer, default=0)
    detected_files = Column(Integer, default=0)
    
    # 时间信息
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # 关联结果
    results = relationship("ScanResult", back_populates="task", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<ScanTask(task_id='{self.task_id}', status='{self.status}')>"


class ScanResult(Base):
    """扫描结果模型"""
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False)
    
    # 文件信息
    file_path = Column(String(1000), nullable=False)
    file_name = Column(String(500))
    file_size = Column(Integer)
    file_hash = Column(String(64), index=True)  # SHA256
    
    # 检测结果
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.CLEAN)
    is_malicious = Column(Boolean, default=False)
    matched_rules = Column(Text)  # JSON list of matched rule names
    match_details = Column(Text)  # JSON detailed match info
    
    # 时间戳
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # 关联任务
    task = relationship("ScanTask", back_populates="results")
    
    def __repr__(self):
        return f"<ScanResult(file='{self.file_name}', threat='{self.threat_level}')>"
