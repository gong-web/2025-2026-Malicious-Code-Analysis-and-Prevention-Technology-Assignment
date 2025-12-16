import os
import sys
import yara
import argparse
import logging
import json
import time
from pathlib import Path
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

COURSE_RULES_DIR = "data/course_rules"

def get_rule_mapping(rules_dir):
    """Indexes all YARA rules in the specified directory by their normalized filename."""
    rule_map = {}
    
    logger.info(f"Indexing rules in {rules_dir}...")
    for root, dirs, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara") or file.endswith(".yal"):
                # Normalize rule filename: lab01_01_exe.yar -> lab01_01_exe
                # Also handle lab01_01exe.yal -> lab01_01_exe (need to insert underscore?)
                
                name_part = file.rsplit('.', 1)[0].lower()
                
                # Special handling for names like lab01_01exe
                if "exe" in name_part and not name_part.endswith("_exe"):
                     name_part = name_part.replace("exe", "_exe")
                if "dll" in name_part and not name_part.endswith("_dll"):
                     name_part = name_part.replace("dll", "_dll")
                
                # Handle cases where . was replaced by nothing or something else in the split
                # If the file was lab01_02.exe.yar, name_part is lab01_02.exe
                # The replace above makes it lab01_02._exe
                # We want lab01_02_exe
                name_part = name_part.replace("._", "_").replace(".", "_")

                key = name_part
                full_path = os.path.join(root, file)
                rule_map[key] = full_path
                
                # logger.info(f"Mapped {key} -> {file}")
    
    logger.info(f"Indexed {len(rule_map)} rule files.")
    return rule_map

def normalize_sample_name(filename):
    """
    Normalizes sample filename to match rule filename format.
    Example: Lab01-01.exe -> lab01_01_exe
    """
    # Remove extension from consideration if it's not part of the rule name pattern?
    # No, the rule names include extensions like _exe, _dll.
    
    name = filename.lower()
    # Replace - and . with _
    name = name.replace('-', '_').replace('.', '_')
    return name

def scan_directory(rule_map, target_dir):
    """Scans a directory, matching each file with its corresponding rule."""
    results = []
    target_path = Path(target_dir)
    
    if not target_path.exists():
        logger.error(f"Target directory {target_dir} does not exist.")
        return results

    files_to_scan = []
    if target_path.is_file():
        files_to_scan.append(target_path)
    else:
        for root, _, files in os.walk(target_path):
            for file in files:
                files_to_scan.append(Path(root) / file)
    
    logger.info(f"Scanning {len(files_to_scan)} files in {target_dir}...")

    for file_path in files_to_scan:
        sample_key = normalize_sample_name(file_path.name)
        rule_path = rule_map.get(sample_key)
        
        result = {
            "file_path": str(file_path),
            "file_name": file_path.name,
            "status": "unknown",
            "matches": [],
            "rule_used": None
        }

        if not rule_path:
            # Try some special cases or fallback?
            # For now, just mark as no rule found
            result["status"] = "no_rule"
            logger.warning(f"No rule found for {file_path.name} (key: {sample_key})")
        else:
            try:
                result["rule_used"] = Path(rule_path).name
                # logger.info(f"Scanning {file_path.name} with {Path(rule_path).name}")
                rules = yara.compile(filepath=rule_path)
                matches = rules.match(str(file_path))
                
                is_malicious = len(matches) > 0
                matched_rules = [m.rule for m in matches]
                
                result["status"] = "malicious" if is_malicious else "clean"
                result["matches"] = matched_rules
                
            except yara.SyntaxError as e:
                logger.error(f"Syntax Error in rule {rule_path}: {e}")
                result["status"] = "rule_error"
                result["error"] = str(e)
            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")
                result["status"] = "scan_error"
                result["error"] = str(e)
        
        results.append(result)
            
    return results

def generate_report(results, output_file):
    """Generates a markdown report."""
    # Filter for binaries (files that we expect to have rules for)
    # Or just filter by status != 'no_rule' if we assume all binaries have rules
    
    # Let's stick to extension filtering to be safe about what is a "binary"
    binary_extensions = {'.exe', '.dll', '.sys', '.bin', '.scr', '.cpl'}
    
    binaries = [r for r in results if Path(r["file_path"]).suffix.lower() in binary_extensions]
    others = [r for r in results if Path(r["file_path"]).suffix.lower() not in binary_extensions]
    
    total_binaries = len(binaries)
    # Only count as detected if status is malicious
    detected_binaries = sum(1 for r in binaries if r["status"] == "malicious")
    # Count missing rules
    no_rule_binaries = sum(1 for r in binaries if r["status"] == "no_rule")
    
    detection_rate = (detected_binaries / total_binaries * 100) if total_binaries > 0 else 0
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"# 课程恶意代码检测报告 (对应规则匹配)\n\n")
        f.write(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"## 1. 摘要\n\n")
        f.write(f"- **扫描模式**: 单样本对应单规则匹配\n")
        f.write(f"- **扫描规则源**: `{COURSE_RULES_DIR}`\n")
        f.write(f"- **扫描目标**: `sample/BinaryCollection`\n")
        f.write(f"- **二进制文件总数**: {total_binaries}\n")
        f.write(f"- **成功检出**: {detected_binaries}\n")
        f.write(f"- **未找到对应规则**: {no_rule_binaries}\n")
        f.write(f"- **检出率**: **{detection_rate:.2f}%**\n")
        
        if detected_binaries == total_binaries:
             f.write(f"- **结果**: ✅ 所有二进制恶意代码均已通过对应规则匹配。\n")
        else:
             f.write(f"- **结果**: ⚠️ 存在未匹配或无规则的文件。\n")
        
        f.write(f"\n## 2. 二进制文件检测详情\n\n")
        f.write(f"| 文件名 | 状态 | 对应规则文件 | 匹配规则名 |\n")
        f.write(f"| :--- | :---: | :--- | :--- |\n")
        
        for r in sorted(binaries, key=lambda x: x['file_name']):
            status = r["status"]
            icon = "✅" if status == "malicious" else "❌" if status == "clean" else "⚠️" if status == "no_rule" else "🚫"
            rule_used = r["rule_used"] if r["rule_used"] else "无对应规则"
            matches_str = ", ".join(r["matches"]) if r["matches"] else "-"
            
            f.write(f"| `{r['file_name']}` | {icon} {status} | `{rule_used}` | {matches_str} |\n")

        if others:
            f.write(f"\n## 3. 其他文件 (非二进制) 检测详情\n\n")
            f.write(f"| 文件名 | 类型 | 状态 | 对应规则文件 |\n")
            f.write(f"| :--- | :--- | :---: | :--- |\n")
            for r in sorted(others, key=lambda x: x['file_name']):
                ext = Path(r['file_path']).suffix
                status = r["status"]
                icon = "✅" if status == "malicious" else "⚪"
                rule_used = r["rule_used"] if r["rule_used"] else "-"
                f.write(f"| `{r['file_name']}` | {ext} | {icon} {status} | {rule_used} |\n")
            
    logger.info(f"Report generated at {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Course Rules Scanner (Corresponding Match)")
    parser.add_argument("--target", default="sample/BinaryCollection", help="Target directory to scan")
    parser.add_argument("--output", default="课程恶意代码检测报告.md", help="Output report file")
    args = parser.parse_args()
    
    rule_map = get_rule_mapping(COURSE_RULES_DIR)
    if rule_map:
        results = scan_directory(rule_map, args.target)
        generate_report(results, args.output)
