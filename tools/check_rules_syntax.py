import sys
import os
import yara
import sqlite3

def check_syntax():
    db_path = "yara_manager.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT name, content FROM yara_rules")
    rules = cursor.fetchall()
    
    externals = {
        'filepath': '',
        'filename': '',
        'extension': '',
        'filetype': '',
        'SharedStrings': '' # Some rules use this?
    }
    
    print(f"Checking syntax for {len(rules)} rules...")
    
    broken_rules = []
    
    for name, content in rules:
        try:
            yara.compile(source=content, externals=externals)
        except yara.SyntaxError as e:
            if "undefined identifier" in str(e):
                # Try to guess missing external
                # But for now, let's assume these are fine if we provide standard externals
                # If it still fails, it might be a custom external I missed
                print(f"⚠️ Potential external issue in '{name}': {e}")
            else:
                print(f"❌ Syntax error in rule '{name}': {e}")
                broken_rules.append(name)
        except Exception as e:
            print(f"❌ Error in rule '{name}': {e}")
            broken_rules.append(name)
            
    if broken_rules:
        print(f"Deleting {len(broken_rules)} broken rules...")
        for name in broken_rules:
            cursor.execute("DELETE FROM yara_rules WHERE name = ?", (name,))
        conn.commit()
        print("Broken rules deleted.")

if __name__ == "__main__":
    check_syntax()
