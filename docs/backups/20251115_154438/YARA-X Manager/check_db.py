from app.db import get_db_session
from app.sql_models import Rule, Sample, Scan

with get_db_session() as db:
    rules_count = db.query(Rule).count()
    samples_count = db.query(Sample).count()
    scans_count = db.query(Scan).count()
    
    print(f"=== Database Statistics ===")
    print(f"Rules: {rules_count}")
    print(f"Samples: {samples_count}")
    print(f"Scans: {scans_count}")
    print(f"==========================")
