import json
from pathlib import Path
from datetime import datetime, timezone
from .celery_app import cel
from .storage import save_sample, delete_sample, save_rule
from .yara_interface import run_yara_json, _compile_rules
from .sql_models import Sample, Scan, Rule
from .db import get_db_session
# The following @func_name.task(bind=True): Register the function as a Celery task, and the setting of parameters allows us to access the status of tasks
# Receive uploaded files and register them in the database
@cel.task(bind=True)
def download_and_register(self, file_bytes: bytes, filename: str):
    p = save_sample(file_bytes, filename)
    with get_db_session() as db:
        s = Sample(filename=filename, path=str(p))
        db.add(s)
        db.commit()
        db.refresh(s)
        return {"id": s.id, "path": s.path}
# Perform YARA-X scan on the specified sample
@cel.task(bind=True)
def run_scan(self, sample_id: int, rule_paths: list[str]):
    with get_db_session() as db:
        sample = db.query(Sample).filter(Sample.id == sample_id).first()
        scan = Scan(
            filename=sample.filename,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        rules = [Path(p) for p in rule_paths]
        try:
            out = run_yara_json(rules, Path(sample.path))
            scan.status = "done"
            scan.result = json.dumps(out)
            scan.finished_at = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            scan.status = "error"
            scan.result = str(e)
            scan.finished_at = datetime.now(timezone.utc).isoformat()
        delete_sample(Path(sample.path))
        db.delete(sample)
        db.commit()
        return {"id": scan.id, "status": scan.status}
# Validate YARA-X rule syntax and store it in the database
@cel.task(bind=True)
def validate_and_store_rule(self, content: str, name: str):
    tmp = Path(f"/tmp/{name}.yar")
    tmp.write_text(content, encoding="utf-8")
    try:
        _compile_rules([tmp])
        p = save_rule(content, name)
        with get_db_session() as db:
            r = Rule(name=name, path=str(p), active=True)
            db.add(r)
            db.commit()
            db.refresh(r)
            return {"id": r.id, "name": r.name}
    finally:
        if tmp.exists():
            tmp.unlink()
