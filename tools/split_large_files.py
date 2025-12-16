import os
import sys

# Configuration
CHUNK_SIZE = 90 * 1024 * 1024  # 90MB (GitHub limit is 100MB, keep it safe)
FILES_TO_SPLIT = [
    "RDS_2025.03.1_modern_minimal.db",
    "RDS_2025.06.1_modern_minimal_delta.sql",
    "RDS_2025.09.1_modern_minimal_delta.sql"
]

def split_file(file_path):
    if not os.path.exists(file_path):
        print(f"Skipping {file_path}: File not found.")
        return

    file_size = os.path.getsize(file_path)
    if file_size <= CHUNK_SIZE:
        print(f"Skipping {file_path}: Size ({file_size/1024/1024:.2f}MB) is within limits.")
        return

    print(f"Splitting {file_path} ({file_size/1024/1024:.2f}MB)...")
    
    part_num = 0
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            
            part_filename = f"{file_path}.part{part_num:03d}"
            with open(part_filename, 'wb') as part_file:
                part_file.write(chunk)
            
            print(f"  Created {part_filename}")
            part_num += 1
            
    print(f"Done. Created {part_num} parts. You can now delete the original file and commit the parts.")

def main():
    # Ensure we are in the tools directory
    tools_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(tools_dir)
    
    for filename in FILES_TO_SPLIT:
        split_file(filename)

if __name__ == "__main__":
    main()
