from app.core.database import SessionLocal
from app.models.scan import ScanTask

db = SessionLocal()
tasks = db.query(ScanTask).all()
print(f"Total tasks: {len(tasks)}")
for t in tasks:
    print(f"ID: {t.id}, TaskID: {t.task_id}, Type: {t.scan_type}, Path: {t.target_path}")
db.close()
