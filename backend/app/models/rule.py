"""
YARA 规则数据模型
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Enum
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class RuleStatus(str, enum.Enum):
    """规则状态"""
    ACTIVE = "active"
    DISABLED = "disabled"
    TESTING = "testing"


class RuleSeverity(str, enum.Enum):
    """规则严重程度"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class YaraRule(Base):
    __tablename__ = "yara_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    description = Column(Text)
    content = Column(Text, nullable=False)
    
    # 分类和标签
    category = Column(String(100), index=True)
    tags = Column(String(500))
    
    # 严重程度和状态
    severity = Column(Enum(RuleSeverity), default=RuleSeverity.MEDIUM)
    status = Column(Enum(RuleStatus), default=RuleStatus.ACTIVE)
    
    # 作者和版本
    author = Column(String(100))
    version = Column(String(50))
    revision = Column(Integer, default=1)
    
    # 统计信息
    match_count = Column(Integer, default=0)
    false_positive_count = Column(Integer, default=0)
    compile_time_ms = Column(Integer, default=0)
    complexity_score = Column(Integer, default=0)
    avg_match_time_ms = Column(Integer, default=0)
    last_tested_at = Column(DateTime(timezone=True))
    
    # 时间戳
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # 是否已编译
    is_compiled = Column(Boolean, default=False)
    compiled_path = Column(String(500))
    
    def __repr__(self):
        return f"<YaraRule(name='{self.name}', category='{self.category}')>"


class SigmaRule(Base):
    __tablename__ = "sigma_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    title = Column(String(500))
    description = Column(Text)
    content = Column(Text, nullable=False)
    
    rule_id = Column(String(100), unique=True, index=True)
    status = Column(String(50))
    level = Column(String(50))
    
    logsource_product = Column(String(100), index=True)
    logsource_service = Column(String(100), index=True)
    logsource_category = Column(String(100), index=True)
    
    detection_selection = Column(Text)
    detection_condition = Column(String(500))
    
    date = Column(String(50))
    modified = Column(String(50))
    author = Column(String(200))
    
    references = Column(Text)
    tags = Column(Text)
    falsepositives = Column(Text)
    
    severity = Column(Enum(RuleSeverity), default=RuleSeverity.MEDIUM)
    rule_status = Column(Enum(RuleStatus), default=RuleStatus.ACTIVE)
    
    version = Column(String(50))
    revision = Column(Integer, default=1)
    
    match_count = Column(Integer, default=0)
    false_positive_count = Column(Integer, default=0)
    complexity_score = Column(Integer, default=0)
    last_tested_at = Column(DateTime(timezone=True))
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    def __repr__(self):
        return f"<SigmaRule(name='{self.name}', level='{self.level}', product='{self.logsource_product}')>"
