import sys
import os
import time
import json
import hashlib
import argparse
import logging
import concurrent.futures
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# 导入必要的模块
import sys
import os
import time
import json
import hashlib
import argparse
import logging
import concurrent.futures
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# 将backend添加到路径以导入核心模块
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../backend")))

try:
    from app.core.database import SessionLocal
    from app.api.scan import get_compiled_rules
    from app.core.whitelist import whitelist_manager
    import yara
except ImportError as e:
    print(f"导入backend模块时出错: {e}")
    print("请确保从项目根目录或tools目录运行此脚本。")
    sys.exit(1)

# 设置日志记录
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Scanner:
    def __init__(self, rules_reload: bool = False):
        self.db = SessionLocal()
        try:
            logger.info("正在加载YARA规则...")
            self.rules = get_compiled_rules(self.db, force_reload=rules_reload)
            logger.info("YARA规则加载成功。")
        except Exception as e:
            logger.error(f"加载规则失败: {e}")
            sys.exit(1)
        finally:
            self.db.close()
        
        # 定义元数据规则（噪声）- 忽略这些
        self.IGNORE_RULES = {
            "IsPE32", "IsPE64", "IsDLL", "IsWindowsGUI", "IsConsole",
            "IsNET_EXE", "IsNET_DLL", "HasRichSignature", "IsELF",
            "Microsoft_Visual_Cpp_80_DLL", "Microsoft_Visual_Cpp_80",
            "Big_Numbers0", "Big_Numbers1", "CRC32_table"
        }

    def get_rule_score(self, match: Any) -> int:
        """
        根据规则的元数据、标签和名称确定规则的分数。
        如果可用，则优先使用元数据中的'score'。
        """
        rule_name = match.rule
        
        # 0. 绝对覆盖（噪声减少）- 首先检查
        upper_name = rule_name.upper()
        if rule_name in self.IGNORE_RULES: return 0
        if upper_name.startswith("PMA_LAB"): return 0
        
        # 降低常见能力规则的分数，这些会导致误报
        # 这些表示功能，不一定表示恶意。
        CAPABILITY_RULES = {
            "contains_base64", "win_mutex", "domain", "url", "IP",
            "create_service", "escalate_priv", "cred_local", 
            "win_registry", "win_token", "win_files_operation",
            "screenshot", "keylogger", "win_hook",
            "network_tcp_socket", "network_dns", "network_tcp_listen", "network_udp_sock",
            "Str_Win32_Winsock2_Library", "Str_Win32_Http_API", "Str_Win32_Internet_API"
        }
        if rule_name in CAPABILITY_RULES: return 6
        
        # 特定可疑指标（分数30-50）
        if rule_name in ["IsPacked", "invalid_trailer_structure", "multiple_versions", "suspicious_packer_section", "invalid_xref_numbers"]: return 50
        if any(upper_name.startswith(p) for p in ["UPX", "BORLAND", "NETEXECUTABLEMICROSOFT", "NETDLLMICROSOFT"]): return 50
        if rule_name == "antisb_threatExpert": return 40
        if rule_name in ["possible_includes_base64_packed_functions", "disable_dep", "powershell"]: return 30
        if rule_name == "Check_OutputDebugStringA_iat": return 15
        
        if rule_name == "anti_dbg": return 10  # 从20/50降至10
        if upper_name.startswith("DEBUGGERCHECK") or upper_name.startswith("DEBUGGERHIDING"): return 1
        
        # 1. 检查元数据中的显式分数
        if 'score' in match.meta:
            try:
                return int(match.meta['score'])
            except (ValueError, TypeError):
                pass

        # 2. 检查标签（高优先级）
        tags = {t.lower() for t in match.tags}
        if 'apt' in tags or 'crime' in tags or 'ransom' in tags:
            return 100
        if 'hacktool' in tags or 'tool' in tags:
            return 80

        # 3. 基于名称的启发式（后备）
        # 精确匹配
        # （移至顶部）
        
        # 前缀匹配
        # upper_name 已计算
        
        # 高置信度类别（分数100）
        if any(upper_name.startswith(p) for p in ["APT", "CRIME", "MAL", "RANSOM", "RAT", "WEBSHELL", "WSHELL", "EXPL", "CVE", "SECURITY"]):
            return 100
            
        # 黑客工具/灰色软件（分数80）
        if any(upper_name.startswith(p) for p in ["HKTL", "HACKTOOL", "TOOLKIT", "TOOL"]):
            return 80
            
        # 通用检测（分数60 -> 55）
        # 降低以允许阈值调整。单个通用匹配不应总是触发。
        if upper_name.startswith("GEN"):
            return 55
            
        # 可疑指标（分数50 -> 45）
        # 需要其他规则或能力的佐证
        if upper_name.startswith("SUSP"):
            return 45
            
        # 较低置信度/潜在不需要（分数40 -> 25）
        if any(upper_name.startswith(p) for p in ["PUA", "PACKER", "CRYPTO", "OBFUSC", "ANTIDEBUG"]):
            return 25
            
        # 能力/信息规则（分数5）
        # 这些通常是小指标，不是完整恶意软件
        if any(upper_name.startswith(p) for p in ["CAPABILITY", "INFO", "CHECK", "HAS", "IS"]):
            return 5
            
        # PEiD规则（打包器识别）- 通常信息性但可疑
        # 如果来自peid.yar，通常有"PEiD"标签或类似名称结构
        if "PEiD" in match.tags or "PEiD" in rule_name:
            return 10

        # 4. 未知规则的默认分数（100 -> 50）
        # 如果规则在数据库中但未分类，假设中等置信度，不是高置信度。
        # 这防止未分类规则的误报，并允许阈值工作。
        return 50

    def classify_threat(self, matches: List[str]) -> str:
        """
        根据匹配的规则对威胁进行分类。
        返回找到的最具体类别。
        """
        upper_matches = [m.upper() for m in matches]
        
        # 优先级1：特定高影响威胁
        if any("RANSOM" in m for m in upper_matches): return "Ransomware"
        if any("APT" in m for m in upper_matches): return "APT"
        if any("WEBSHELL" in m or "WSHELL" in m for m in upper_matches): return "Webshell"
        
        # 优先级2：特定功能
        if any("MINER" in m or "XMRIG" in m for m in upper_matches): return "CoinMiner"
        if any("EXPL" in m or "CVE" in m for m in upper_matches): return "Exploit"
        if any("HKTL" in m or "HACKTOOL" in m or "MIMIKATZ" in m for m in upper_matches): return "HackTool"
        if any("SPY" in m or "STEALER" in m or "KEYLOGGER" in m for m in upper_matches): return "Spyware/Stealer"
        
        # 优先级3：通用恶意软件类型
        if any("RAT" in m or "BACKDOOR" in m for m in upper_matches): return "Backdoor/RAT"
        if any("TROJAN" in m or "MALW" in m or "CRIME" in m for m in upper_matches): return "Trojan"
        if any("VIRUS" in m for m in upper_matches): return "Virus"
        
        # 优先级4：低风险
        if any("PUA" in m or "ADWARE" in m for m in upper_matches): return "PUA/Adware"
        
        return "Generic Malware"

    def scan_file(self, file_path: Path) -> Dict[str, Any]:
        result = {
            "file_path": str(file_path),
            "file_name": file_path.name,
            "status": "error",
            "threat_level": "unknown",
            "category": "unknown",
            "matches": [],
            "score": 0,
            "error": None,
            "hash": None
        }

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            
            file_hash = hashlib.sha256(content).hexdigest()
            result["hash"] = file_hash

            # 白名单检查
            if whitelist_manager.is_whitelisted(file_hash):
                result["status"] = "clean"
                result["threat_level"] = "clean"
                result["category"] = "clean"
                result["reason"] = "whitelisted"
                return result

            # YARA扫描
            matches = self.rules.match(data=content, externals={
                'filepath': str(file_path),
                'filename': file_path.name,
                'extension': file_path.suffix,
                'filetype': ''
            })

            if matches:
                score = 0
                capability_score = 0

                for match in matches:
                    rule_name = match.rule
                    rule_score = self.get_rule_score(match)
                    
                    # 跟踪匹配
                    if rule_score > 0:
                        result["matches"].append(rule_name)
                    
                    # 特殊处理能力/信息分数
                    # 如果分数<=10，则视为能力分数
                    if rule_score <= 10:
                        capability_score += rule_score
                    else:
                        score += rule_score
                
                # 将能力分数上限设为50
                if capability_score > 50:
                    capability_score = 50
                
                score += capability_score
                result["score"] = score
                
                # 阈值：18
                # 根据新评分权重调整：
                # - 关键/高（80-100）：总是检测
                # - 中等/默认（50）：检测
                # - 通用（55）：检测
                # - 可疑（45）：检测
                # - 纯能力（最大50）：如果>3个能力（3*6=18）则检测
                if score >= 18:
                    result["status"] = "malicious"
                    result["threat_level"] = "malicious"
                    result["category"] = self.classify_threat(result["matches"])
                else:
                    result["status"] = "clean"
                    result["threat_level"] = "clean"
                    result["category"] = "clean"
            else:
                result["status"] = "clean"
                result["threat_level"] = "clean"
                result["category"] = "clean"

        except Exception as e:
            result["error"] = str(e)
        
        return result

def run_scan(target_path: str, output_dir: str, sample_type: str, concurrency: int):
    target = Path(target_path)
    if not target.exists():
        logger.error(f"Target path does not exist: {target}")
        return

    # 准备输出目录
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_name = target.name
    report_file = output_path / f"{target_name}_{timestamp}.json"
    summary_file = output_path / f"{target_name}_{timestamp}.txt"

    scanner = Scanner()
    
    files_to_scan = []
    if target.is_file():
        files_to_scan.append(target)
    else:
        for root, _, files in os.walk(target):
            for file in files:
                files_to_scan.append(Path(root) / file)

    total_files = len(files_to_scan)
    logger.info(f"Found {total_files} files to scan.")
    
    results = []
    malicious_count = 0
    clean_count = 0
    error_count = 0
    category_counts = {}
    
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_file = {executor.submit(scanner.scan_file, f): f for f in files_to_scan}
        
        processed = 0
        for future in concurrent.futures.as_completed(future_to_file):
            processed += 1
            if processed % 100 == 0:
                print(f"Progress: {processed}/{total_files}...", end="\r")
                
            res = future.result()
            results.append(res)
            
            if res["status"] == "malicious":
                malicious_count += 1
                cat = res.get("category", "Generic Malware")
                category_counts[cat] = category_counts.get(cat, 0) + 1
            elif res["status"] == "clean":
                clean_count += 1
            else:
                error_count += 1

    duration = time.time() - start_time
    print(f"\nScan completed in {duration:.2f} seconds.")

    # 统计
    avg_time_per_file = duration / total_files if total_files > 0 else 0
    stats = {
        "scan_date": datetime.now().isoformat(),
        "target_path": str(target),
        "total_files": total_files,
        "malicious_count": malicious_count,
        "clean_count": clean_count,
        "error_count": error_count,
        "category_breakdown": category_counts,
        "duration_seconds": duration,
        "avg_time_per_file_seconds": avg_time_per_file,
        "throughput_files_per_sec": total_files / duration if duration > 0 else 0
    }

    # 根据预期类型计算率
    if sample_type == "benign":
        fp_rate = (malicious_count / total_files * 100) if total_files > 0 else 0
        stats["false_positive_rate"] = f"{fp_rate:.2f}%"
        logger.info(f"False Positive Rate: {fp_rate:.2f}%")
    elif sample_type == "malicious":
        detection_rate = (malicious_count / total_files * 100) if total_files > 0 else 0
        stats["detection_rate"] = f"{detection_rate:.2f}%"
        logger.info(f"Detection Rate: {detection_rate:.2f}%")
    # 保存JSON报告
    report_data = {
        "summary": stats,
        "details": results
    }
    
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    logger.info(f"Detailed report saved to {report_file}")

    # 保存摘要文本
    with open(summary_file, "w", encoding="utf-8") as f:
        f.write("=== Scan Summary ===\n")
        for k, v in stats.items():
            if k == "category_breakdown":
                f.write("Category Breakdown:\n")
                for cat, count in v.items():
                    f.write(f"  - {cat}: {count}\n")
            else:
                f.write(f"{k}: {v}\n")
        
        if malicious_count > 0:
            f.write("\n=== Malicious Detections ===\n")
            for r in results:
                if r["status"] == "malicious":
                    f.write(f"[{r.get('category', 'MAL')}] {r['file_path']} -> {r['matches']}\n")

    logger.info(f"Summary saved to {summary_file}")
    
    # 在控制台打印摘要
    print("\n" + "="*30)
    print("       Scan Summary       ")
    print("="*30)
    print(f"Total Files: {total_files}")
    print(f"Malicious:   {malicious_count}")
    print(f"Clean:   {clean_count}")
    print(f"Errors:   {error_count}")
    if "false_positive_rate" in stats:
        print(f"False Positive Rate: {stats['false_positive_rate']}")
    if "detection_rate" in stats:
        print(f"Detection Rate:   {stats['detection_rate']}")
    
    if category_counts:
        print("-" * 30)
        print("Threat Categories:")
        # 按计数降序排序
        for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {cat:<15}: {count}")
            
    print("="*30)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Comprehensive Malware Scanning Tool")
    parser.add_argument("target", help="Path to the file or directory to scan")
    parser.add_argument("--output", default="sample/result", help="Directory to save results")
    parser.add_argument("--type", choices=["benign", "malicious", "unknown"], default="unknown", help="Type of the samples being scanned (for statistics)")
    parser.add_argument("--workers", type=int, default=4, help="Number of concurrent threads")
    
    args = parser.parse_args()
    
    run_scan(args.target, args.output, args.type, args.workers)
