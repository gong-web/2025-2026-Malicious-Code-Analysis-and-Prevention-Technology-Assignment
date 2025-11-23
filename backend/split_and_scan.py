import os
import sys
import shutil
import math
import subprocess
from pathlib import Path

def split_and_scan(source_dir, batch_size=700):
    source_path = Path(source_dir).resolve()
    parent_dir = source_path.parent
    base_name = source_path.name
    
    # Ensure results directory exists
    results_dir = Path("../data/result").resolve()
    results_dir.mkdir(parents=True, exist_ok=True)
    
    # Get all files
    if not source_path.exists():
        print(f"Error: Source directory {source_path} does not exist.")
        return

    all_files = [f for f in source_path.iterdir() if f.is_file()]
    total_files = len(all_files)
    print(f"Found {total_files} files in {source_path}")
    
    if total_files == 0:
        print("No files to process.")
        return

    num_batches = math.ceil(total_files / batch_size)
    print(f"Splitting into {num_batches} batches of {batch_size} files...")
    
    for i in range(num_batches):
        batch_index = i + 1
        new_folder_name = f"{base_name}_{batch_index}"
        new_folder_path = parent_dir / new_folder_name
        new_folder_path.mkdir(exist_ok=True)
        
        start_idx = i * batch_size
        end_idx = min((i + 1) * batch_size, total_files)
        batch_files = all_files[start_idx:end_idx]
        
        print(f"Processing Batch {batch_index}: Moving {len(batch_files)} files to {new_folder_path}...")
        
        # Move files
        for file_path in batch_files:
            try:
                shutil.move(str(file_path), str(new_folder_path / file_path.name))
            except Exception as e:
                print(f"Error moving file {file_path}: {e}")
            
        # Run scan
        print(f"Starting scan for {new_folder_name}...")
        
        report_json_path = results_dir / f"{new_folder_name}.json"
        report_txt_path = results_dir / f"{new_folder_name}.txt"
        
        # Get the path to batch_scan.py relative to this script
        current_script_dir = Path(__file__).parent
        batch_scan_script = current_script_dir / "batch_scan.py"
        
        cmd = [
            sys.executable, str(batch_scan_script), 
            "dir", str(new_folder_path), 
            str(report_json_path)
        ]
        
        try:
            with open(report_txt_path, "w", encoding="utf-8") as log_file:
                # Run in the backend directory to ensure imports work if any (though batch_scan seems standalone)
                subprocess.run(cmd, stdout=log_file, stderr=subprocess.STDOUT, check=True, cwd=current_script_dir)
            print(f"Batch {batch_index} completed. Results in {results_dir}")
        except subprocess.CalledProcessError as e:
            print(f"Error scanning batch {batch_index}: {e}")
        except Exception as e:
            print(f"Unexpected error scanning batch {batch_index}: {e}")

if __name__ == "__main__":
    # Assuming run from backend/ or root
    # Default target, can be overridden or hardcoded as per user request
    # Use absolute path to be safe
    base_dir = Path(__file__).parent.parent
    target_dir = base_dir / "data" / "samples" / "Malware2025_2"
    
    # Check if user provided an argument
    if len(sys.argv) > 1:
        target_dir = Path(sys.argv[1])
        
    split_and_scan(target_dir)
