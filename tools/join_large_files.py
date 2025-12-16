import os
import sys
import glob

def join_files():
    # Ensure we are in the tools directory
    tools_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(tools_dir)
    
    # Find all split files (pattern: *.part000)
    # We look for the base names first
    split_groups = set()
    for part_file in glob.glob("*.part000"):
        base_name = part_file[:-8] # Remove .part000
        split_groups.add(base_name)
        
    if not split_groups:
        print("No split files found to join.")
        return

    for base_name in split_groups:
        if os.path.exists(base_name):
            print(f"Target file {base_name} already exists. Skipping join.")
            continue
            
        print(f"Joining parts for {base_name}...")
        
        parts = sorted(glob.glob(f"{base_name}.part*"))
        if not parts:
            print(f"Error: No parts found for {base_name}")
            continue
            
        try:
            with open(base_name, 'wb') as outfile:
                for part in parts:
                    print(f"  Reading {part}...")
                    with open(part, 'rb') as infile:
                        outfile.write(infile.read())
            print(f"Successfully reconstructed {base_name}")
        except Exception as e:
            print(f"Error joining {base_name}: {e}")

if __name__ == "__main__":
    join_files()
