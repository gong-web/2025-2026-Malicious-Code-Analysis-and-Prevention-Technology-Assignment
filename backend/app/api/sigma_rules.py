from typing import List
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from pydantic import BaseModel
import os
import yaml
from app.core.database import get_db
from app.core.config import settings
from app.models.rule import SigmaRule, RuleStatus, RuleSeverity
from app.services.rule_validator import RuleValidator


router = APIRouter()
validator = RuleValidator()
SIGMA_DIR = Path(settings.SIGMA_RULES_DIR)
SIGMA_DIR.mkdir(parents=True, exist_ok=True)


class ToggleRequest(BaseModel):
    active: bool


@router.get("/")
async def list_sigma_rules(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    rules = db.query(SigmaRule).offset(skip).limit(limit).all()
    res = []
    for r in rules:
        path = SIGMA_DIR / f"{r.rule_id or r.name}.yml"
        res.append({
            "id": r.id,
            "name": r.name,
            "title": r.title or r.name,
            "rule_id": r.rule_id or "",
            "path": str(path),
            "status": r.status,
            "level": r.level,
            "active": r.rule_status == RuleStatus.ACTIVE,
        })
    return res


@router.post("/upload")
async def upload_sigma(files: List[UploadFile] = File(...), db: Session = Depends(get_db)):
    uploaded, errors = [], []
    for f in files:
        try:
            if not (f.filename.endswith(".yml") or f.filename.endswith(".yaml")):
                errors.append(f.filename + ": 不支持的文件格式")
                continue
            content = (await f.read()).decode("utf-8", errors="ignore")
            v = validator.validate_sigma_rule(content)
            if not v.get("valid"):
                errors.append(f.filename + ": " + str(v.get("error")))
                continue
            info = v["rule_info"]
            name = (info["title"] or Path(f.filename).stem).replace(" ", "_").lower()
            exists = db.query(SigmaRule).filter(
                (SigmaRule.rule_id == info["rule_id"]) | (SigmaRule.name == name)
            ).first()
            if exists:
                errors.append(f.filename + ": 规则已存在")
                continue
            file_path = SIGMA_DIR / f"{info['rule_id'] or name}.yml"
            with open(file_path, "w", encoding="utf-8") as out:
                out.write(content)
            db_rule = SigmaRule(
                name=name,
                title=info["title"],
                description=info["description"],
                content=content,
                rule_id=info["rule_id"],
                status=info["status"],
                level=info["level"],
                logsource_product=info["logsource_product"],
                logsource_service=info["logsource_service"],
                author=info["author"],
                date=info["date"],
                references=info["references"],
                tags=info["tags"],
                falsepositives=info["falsepositives"],
                severity=RuleSeverity.MEDIUM,
                rule_status=RuleStatus.ACTIVE,
                complexity_score=v.get("complexity_score", 0),
            )
            db.add(db_rule)
            db.commit()
            db.refresh(db_rule)
            uploaded.append({
                "id": db_rule.id,
                "name": name,
                "title": info["title"],
                "rule_id": info["rule_id"],
                "path": str(file_path),
                "status": info["status"],
                "level": info["level"],
                "active": True,
            })
        except Exception as e:
            errors.append(f.filename + ": " + str(e))
    return {"uploaded": len(uploaded), "failed": len(errors), "rules": uploaded, "errors": errors}


@router.post("/import/db")
async def import_from_db(db: Session = Depends(get_db)):
    bases = [Path("db/sigma_rules_flat")]
    imported, errors = [], []
    product_counts = {}
    service_counts = {}
    category_counts = {}
    selection_counts = {}
    for base in bases:
        if not base.exists():
            continue
        for p in base.rglob("*.yml"):
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                v = validator.validate_sigma_rule(content)
                if not v.get("valid"):
                    errors.append(f"{p.name}: {v.get('error')}")
                    continue
                info = v["rule_info"]
                name = (info["title"] or p.stem).replace(" ", "_").lower()
                if db.query(SigmaRule).filter(
                    (SigmaRule.rule_id == info["rule_id"]) | (SigmaRule.name == name)
                ).first():
                    continue
                dst = SIGMA_DIR / f"{info['rule_id'] or name}.yml"
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(content, encoding="utf-8")
                r = SigmaRule(
                    name=name,
                    title=info["title"],
                    description=info["description"],
                    content=content,
                    rule_id=info["rule_id"],
                    status=info["status"],
                    level=info["level"],
                    logsource_product=info["logsource_product"],
                    logsource_service=info["logsource_service"],
                    author=info["author"],
                    date=info["date"],
                    references=info["references"],
                    tags=info["tags"],
                    falsepositives=info["falsepositives"],
                    severity=RuleSeverity.MEDIUM,
                    rule_status=RuleStatus.ACTIVE,
                    complexity_score=v.get("complexity_score", 0),
                )
                db.add(r)
                db.commit()
                db.refresh(r)
                imported.append(name)

                prod = info.get("logsource_product") or ""
                serv = info.get("logsource_service") or ""
                cat = info.get("logsource_category") or ""
                if prod:
                    product_counts[prod] = product_counts.get(prod, 0) + 1
                if serv:
                    service_counts[serv] = service_counts.get(serv, 0) + 1
                if cat:
                    category_counts[cat] = category_counts.get(cat, 0) + 1

                try:
                    d = yaml.safe_load(content)
                    det = d.get("detection", {})
                    for k, vsel in det.items():
                        if k == "condition":
                            continue
                        if isinstance(vsel, dict):
                            for field in vsel.keys():
                                selection_counts[field] = selection_counts.get(field, 0) + 1
                except Exception:
                    pass
            except Exception as e:
                errors.append(f"{p.name}: {str(e)}")
    report = {
        "products": product_counts,
        "services": service_counts,
        "categories": category_counts,
        "top_fields": dict(sorted(selection_counts.items(), key=lambda x: x[1], reverse=True)[:20])
    }
    return {"imported": len(imported), "failed": len(errors), "errors": errors, "report": report}


@router.patch("/{rule_id}/toggle")
async def toggle_sigma(rule_id: int, data: ToggleRequest, db: Session = Depends(get_db)):
    r = db.query(SigmaRule).filter(SigmaRule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="规则未找到")
    old = r.rule_status
    r.rule_status = RuleStatus.ACTIVE if data.active else RuleStatus.DISABLED
    db.commit()
    db.refresh(r)
    return {"id": r.id, "name": r.name, "active": r.rule_status == RuleStatus.ACTIVE, "old_active": old == RuleStatus.ACTIVE}


@router.get("/report")
async def sigma_report(db: Session = Depends(get_db)):
    rules = db.query(SigmaRule).all()
    product_counts = {}
    service_counts = {}
    category_counts = {}
    selection_counts = {}
    for r in rules:
        prod = r.logsource_product or ""
        serv = r.logsource_service or ""
        cat = r.logsource_category or ""
        if prod:
            product_counts[prod] = product_counts.get(prod, 0) + 1
        if serv:
            service_counts[serv] = service_counts.get(serv, 0) + 1
        if cat:
            category_counts[cat] = category_counts.get(cat, 0) + 1
        try:
            d = yaml.safe_load(r.content)
            det = d.get("detection", {})
            for k, vsel in det.items():
                if k == "condition":
                    continue
                if isinstance(vsel, dict):
                    for field in vsel.keys():
                        selection_counts[field] = selection_counts.get(field, 0) + 1
        except Exception:
            pass
    report = {
        "products": product_counts,
        "services": service_counts,
        "categories": category_counts,
        "top_fields": dict(sorted(selection_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
        "total": len(rules)
    }
    return report
@router.delete("/{rule_id}")
async def delete_sigma(rule_id: int, db: Session = Depends(get_db)):
    r = db.query(SigmaRule).filter(SigmaRule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="规则未找到")
    file_path = SIGMA_DIR / f"{r.rule_id or r.name}.yml"
    if file_path.exists():
        try:
            os.remove(file_path)
        except:
            pass
    db.delete(r)
    db.commit()
    return {"message": "规则已删除"}