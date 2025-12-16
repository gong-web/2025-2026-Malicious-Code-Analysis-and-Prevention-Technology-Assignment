import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../backend")))

from app.core.database import SessionLocal
from app.models.rule import YaraRule, RuleStatus, RuleSeverity

def import_rules():
    db = SessionLocal()
    # Use absolute path to be safe
    rules_dir = Path(os.path.join(os.path.dirname(__file__), "../data/rules")).resolve()
    
    print(f"Importing rules from {rules_dir}...")
    
    count = 0
    for rule_file in rules_dir.glob("*.yar"):
        try:
            content = rule_file.read_text(encoding='utf-8', errors='ignore')
            name = rule_file.stem
            
            # Check if exists
            existing = db.query(YaraRule).filter(YaraRule.name == name).first()
            if existing:
                existing.content = content
                # print(f"Updated {name}")
            else:
                rule = YaraRule(
                    name=name,
                    content=content,
                    category="imported",
                    status=RuleStatus.ACTIVE,
                    severity=RuleSeverity.HIGH
                )
                db.add(rule)
                print(f"Added {name}")
            count += 1
        except Exception as e:
            print(f"Error importing {rule_file}: {e}")
            
    db.commit()
    db.close()
    print(f"Processed {count} rule files.")

if __name__ == "__main__":
    import_rules()
