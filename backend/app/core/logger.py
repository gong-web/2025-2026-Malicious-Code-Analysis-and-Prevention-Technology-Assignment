import logging
import sys
from logging.handlers import TimedRotatingFileHandler
import os
from pathlib import Path

# Create logs directory if not exists
LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(exist_ok=True)

def setup_logging():
    """
    Configure unified logging system with rotation.
    """
    # 1. Define formatters
    detailed_formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 2. Define handlers
    
    # Console Handler (Stream)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(detailed_formatter)
    console_handler.setLevel(logging.INFO)
    
    # File Handler (Daily Rotation)
    # Rotates every midnight, keeps 30 days of logs
    file_handler = TimedRotatingFileHandler(
        filename=LOGS_DIR / "app.log",
        when="midnight",
        interval=1,
        backupCount=30,
        encoding="utf-8"
    )
    file_handler.setFormatter(detailed_formatter)
    file_handler.setLevel(logging.INFO)
    
    # Error File Handler (Separate file for errors)
    error_handler = TimedRotatingFileHandler(
        filename=LOGS_DIR / "error.log",
        when="midnight",
        interval=1,
        backupCount=30,
        encoding="utf-8"
    )
    error_handler.setFormatter(detailed_formatter)
    error_handler.setLevel(logging.ERROR)
    
    # 3. Configure Root Logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Remove existing handlers to avoid duplicates
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
        
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(error_handler)
    
    # 4. Silence noisy libraries
    logging.getLogger("uvicorn.access").handlers = [] # Let root logger handle it or keep it?
    # Uvicorn has its own logger config usually, but we can propagate
    
    logging.info("Logging system initialized.")

# Global logger instance for easy import (optional, standard logging.getLogger is preferred)
logger = logging.getLogger("app")
