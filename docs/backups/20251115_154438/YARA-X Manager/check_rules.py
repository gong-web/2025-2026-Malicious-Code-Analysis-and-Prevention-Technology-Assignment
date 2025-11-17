from app.db import get_db_session
from app.sql_models import Rule
import os

with get_db_session() as db:
    rules = db.query(Rule).filter(Rule.active==True).limit(10).all()
    print(f"Total active rules: {len(rules)}")
    for r in rules:
        exists = os.path.exists(r.path)
        print(f"{r.name}: {r.path}")
        print(f"  Exists: {exists}")
        if not exists:
            print(f"  ERROR: File not found!")
