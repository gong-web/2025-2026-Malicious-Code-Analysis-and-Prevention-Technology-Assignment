from app.db import get_db_session
from app.sql_models import Sample
from pathlib import Path
import os

# 获取最近上传的样本
with get_db_session() as db:
    samples = db.query(Sample).order_by(Sample.id.desc()).limit(5).all()
    print("Recent samples:")
    for s in samples:
        exists = os.path.exists(s.path)
        size = os.path.getsize(s.path) if exists else 0
        print(f"{s.id}: {s.filename}")
        print(f"  Path: {s.path}")
        print(f"  Exists: {exists}")
        print(f"  Size: {size}")
        print()
