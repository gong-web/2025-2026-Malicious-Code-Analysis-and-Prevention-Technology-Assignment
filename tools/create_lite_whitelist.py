import os
import sqlite3
import hashlib
import sys

# Configuration
BENIGN_SAMPLES_DIR = "../sample/benign"
OUTPUT_DB = "../RDS_2025.03.1_modern_minimal.db"

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest().upper()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def create_db(db_path):
    """Create the SQLite database and table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Create table matching the schema expected by backend/app/core/whitelist.py
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS FILE (
            sha256 TEXT PRIMARY KEY,
            md5 TEXT,
            sha1 TEXT,
            file_name TEXT
        )
    ''')
    # Create index for faster lookups
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sha256 ON FILE(sha256)')
    conn.commit()
    return conn

def main():
    # Ensure we are in the tools directory
    tools_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(tools_dir)
    
    # Check if benign samples directory exists
    abs_benign_dir = os.path.abspath(BENIGN_SAMPLES_DIR)
    if not os.path.exists(abs_benign_dir):
        print(f"Error: Benign samples directory not found at {abs_benign_dir}")
        print("Please ensure you have the 'sample/benign' folder in your project root.")
        sys.exit(1)

    print(f"Creating Lite Whitelist DB at {OUTPUT_DB}...")
    print(f"Scanning samples in {abs_benign_dir}...")

    conn = create_db(OUTPUT_DB)
    cursor = conn.cursor()
    
    count = 0
    for root, dirs, files in os.walk(abs_benign_dir):
        for file in files:
            file_path = os.path.join(root, file)
            sha256 = calculate_sha256(file_path)
            
            if sha256:
                try:
                    # Insert into DB
                    cursor.execute(
                        "INSERT OR IGNORE INTO FILE (sha256, file_name) VALUES (?, ?)",
                        (sha256, file)
                    )
                    count += 1
                    if count % 100 == 0:
                        print(f"Processed {count} files...")
                except sqlite3.Error as e:
                    print(f"Database error: {e}")

    conn.commit()
    conn.close()
    
    print(f"Successfully created whitelist database with {count} entries.")
    print(f"Database saved to: {os.path.abspath(OUTPUT_DB)}")
    print("This 'Lite' database contains hashes of all provided benign samples,")
    print("ensuring they are correctly identified as safe during scanning.")

if __name__ == "__main__":
    main()
