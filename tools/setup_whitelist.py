import os
import sys
import urllib.request
import subprocess

# Configuration
# TODO: Replace these URLs with the actual download links for your RDS files
RDS_URLS = {
    "RDS_2025.03.1_modern_minimal.db": "https://example.com/path/to/RDS_2025.03.1_modern_minimal.db",
    "RDS_2025.06.1_modern_minimal_delta.sql": "https://example.com/path/to/RDS_2025.06.1_modern_minimal_delta.sql",
    "RDS_2025.09.1_modern_minimal_delta.sql": "https://example.com/path/to/RDS_2025.09.1_modern_minimal_delta.sql"
}

def download_file(url, filename):
    print(f"Downloading {filename}...")
    try:
        urllib.request.urlretrieve(url, filename)
        print(f"Successfully downloaded {filename}")
    except Exception as e:
        print(f"Error downloading {filename}: {e}")
        sys.exit(1)

def main():
    # Ensure we are in the tools directory
    tools_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(tools_dir)
    
    # Download files
    for filename, url in RDS_URLS.items():
        if os.path.exists(filename):
            print(f"{filename} already exists. Skipping download.")
        else:
            download_file(url, filename)
            
    print("All files present. Running merge_rds.py...")
    
    merge_script = "merge_rds.py"
    if not os.path.exists(merge_script):
        print(f"Error: {merge_script} not found in {tools_dir}")
        sys.exit(1)

    try:
        # Run the merge script using the current python interpreter
        subprocess.run([sys.executable, merge_script], check=True)
        print("Whitelist setup complete.")
    except subprocess.CalledProcessError as e:
        print(f"Error running merge_rds.py: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
