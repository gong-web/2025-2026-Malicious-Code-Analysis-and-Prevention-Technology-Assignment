from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from pathlib import Path
from contextlib import contextmanager
# SQLite file path
DB_PATH = Path(__file__).resolve().parent.parent / "data.sqlite"
# Connect with .sqlite and allow multi-threaded access to SQLite
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False}
)
# Generate database session factory
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False
)
# Base class for database tables
Base = declarative_base()
# Create a new session and use it, and finally close the database
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@contextmanager
def get_db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
