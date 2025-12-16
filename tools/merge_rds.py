import sqlite3
import os
import time

MAIN_DB = "RDS_2025.03.1_modern_minimal.db"
DELTA_FILES = [
    "RDS_2025.06.1_modern_minimal_delta.sql",
    "RDS_2025.09.1_modern_minimal_delta.sql"
]

def merge_deltas():
    if not os.path.exists(MAIN_DB):
        print(f"Error: Main DB {MAIN_DB} not found.")
        return

    print(f"Connecting to {MAIN_DB}...")
    try:
        conn = sqlite3.connect(MAIN_DB)
        cursor = conn.cursor()
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        return

    for delta_file in DELTA_FILES:
        if not os.path.exists(delta_file):
            print(f"Warning: Delta file {delta_file} not found, skipping.")
            continue

        print(f"Merging {delta_file}...")
        start_time = time.time()
        
        try:
            with open(delta_file, 'r', encoding='utf-8', errors='ignore') as f:
                sql_script = f.read()
                cursor.executescript(sql_script)
                conn.commit()
                print(f"Finished merging {delta_file}. Time: {time.time() - start_time:.2f}s")
                        
        except Exception as e:
            print(f"Failed to merge {delta_file}: {e}")
    
    conn.close()

if __name__ == "__main__":
    merge_deltas()
