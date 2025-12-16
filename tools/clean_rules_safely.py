import os
import plyara
from plyara.utils import rebuild_yara_rule

RULES_DIR = "data/rules"

# Rules to remove (Pure Noise / Metadata / Compiler Signatures)
NOISE_RULES = {
    # === File Format / Compiler (Safe to remove) ===
    "IsPE32", "IsPE64", "IsDLL", "IsWindowsGUI", "IsConsole", 
    "IsNET_EXE", "IsNET_DLL", "HasRichSignature", 
    "Microsoft_Visual_Cpp_80_DLL", "Microsoft_Visual_Cpp_80", 
    "Microsoft_Visual_Cpp_V80_Debug", "Microsoft_Visual_Cpp_80_Debug_",
    "Borland_Delphi_v6_0_v7_0", 
    
    # === Encryption Constants (High FP, Low Value for Static Analysis) ===
    "Big_Numbers0", "Big_Numbers1", "Big_Numbers2", "Big_Numbers3", 
    "Big_Numbers4", "Big_Numbers5", "CRC32_poly_Constant", "CRC32_table", 
    "CRC16_table", "MD5_Constants", "SHA1_Constants", "SHA256_Constants", 
    "SHA512_Constants", "AES_Constants", "BASE64_table",
    
    # === Too Broad ===
    "without_attachments", "without_images"
}

def clean_rules_safely():
    print(f"Cleaning rules in {RULES_DIR} using plyara...")
    parser = plyara.Plyara()
    
    for root, dirs, files in os.walk(RULES_DIR):
        for file in files:
            if not file.endswith(".yar"):
                continue
            
            file_path = os.path.join(root, file)
            # print(f"Processing {file}...")
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            try:
                # Parse rules
                rules = parser.parse_string(content)
                new_rules_content = []
                modified = False
                
                for rule in rules:
                    rule_name = rule['rule_name']
                    
                    # Check if in noise list
                    if rule_name in NOISE_RULES:
                        print(f"  [-] Removing noise rule: {rule_name} from {file}")
                        modified = True
                        continue # Skip adding to new content
                    
                    # Rebuild kept rules
                    new_rules_content.append(rebuild_yara_rule(rule))
                
                # Only write if modified
                if modified:
                    # Backup original (optional, but good practice)
                    # os.rename(file_path, file_path + ".bak")
                    
                    # Write new content
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write("\n\n".join(new_rules_content))
                    print(f"  [+] Updated {file}")
                    
            except Exception as e:
                print(f"  [!] Failed to parse {file}: {e}")

if __name__ == "__main__":
    clean_rules_safely()
