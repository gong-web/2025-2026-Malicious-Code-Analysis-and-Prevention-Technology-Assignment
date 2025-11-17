from sqlalchemy import Column, Integer, Text, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from app.db import Base
# Craete table tuple: sample 
class Sample(Base):
    __tablename__ = "samples"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    path = Column(Text, nullable=False)
# Craete table tuple: scan
class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    status = Column(String, nullable=False)
    result = Column(Text)
    started_at = Column(String, nullable=False)
    finished_at = Column(String)
# Craete table tuple: rule
class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    path = Column(Text, nullable=False)
    active = Column(Boolean, default=True)
