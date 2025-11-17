from app.db import get_db_session
from app.sql_models import Rule
import yara
import os

# 测试扫描Lab01-01.exe
sample_path = "D:\\gds\\Documents\\Malicious_Code_Analysis\\yara-x-manager\\YARA-X Manager\\data\\cache\\Lab01-01.exe"

print(f"Sample file: {sample_path}")
print(f"Exists: {os.path.exists(sample_path)}")
print(f"Size: {os.path.getsize(sample_path)} bytes\n")

with get_db_session() as db:
    rules = db.query(Rule).filter(Rule.active==True).all()
    print(f"Active rules: {len(rules)}\n")
    
    # 编译规则
    rules_dict = {}
    for idx, rule in enumerate(rules):
        if os.path.exists(rule.path):
            try:
                rules_dict[f'rule_{idx}'] = rule.path
            except Exception as e:
                print(f"Failed to add {rule.name}: {e}")
    
    print(f"Rules to compile: {len(rules_dict)}\n")
    
    # 编译和扫描
    compiled_rules = yara.compile(filepaths=rules_dict)
    print("Rules compiled successfully\n")
    
    matches = compiled_rules.match(sample_path)
    print(f"Matches found: {len(matches)}\n")
    
    for match in matches:
        print(f"Rule: {match.rule}")
        print(f"  Namespace: {match.namespace}")
        print(f"  Tags: {list(match.tags)}")
        print(f"  Meta: {dict(match.meta)}")
        print(f"  Strings: {len(match.strings)} matched")
        for s in match.strings:
            print(f"    - {s.identifier}: {len(s.instances)} instances")
        print()
