#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量扫描恶意样本的工具脚本
使用后端 API 进行批量文件/目录扫描
"""

import requests
import os
import sys
import time
from pathlib import Path
from typing import List, Dict
import json

# 设置输出编码为UTF-8，并禁用缓冲
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', line_buffering=True)


class YaraScanner:
    """YARA 扫描器客户端"""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url
        self.session = requests.Session()
        self.request_count = 0

    def _refresh_session(self):
        """刷新会话，防止连接池耗尽"""
        try:
            self.session.close()
        except:
            pass
        self.session = requests.Session()
        self.request_count = 0
    
    def check_health(self) -> bool:
        """检查后端服务是否运行"""
        try:
            response = self.session.get(f"{self.api_url}/health")
            return response.status_code == 200
        except Exception as e:
            print(f"❌ 无法连接到后端服务: {e}")
            return False
    
    def scan_file(self, file_path: str, max_retries: int = 3) -> Dict:
        """扫描单个文件 (带重试机制)"""
        self.request_count += 1
        if self.request_count > 100:
            self._refresh_session()

        for attempt in range(max_retries):
            try:
                with open(file_path, 'rb') as f:
                    files = {'file': (os.path.basename(file_path), f)}
                    response = self.session.post(
                        f"{self.api_url}/api/scan/file",
                        files=files,
                        timeout=300  # 增加到300秒超时
                    )
                    
                    if response.status_code == 200:
                        return response.json()
                    
                    # 如果是 5xx 错误，等待后重试
                    if response.status_code >= 500:
                        print(f"   ⚠️  服务器错误 (5xx), 正在重试 ({attempt + 1}/{max_retries})...", flush=True)
                        time.sleep(2 * (attempt + 1))
                        self._refresh_session() # 出错时刷新会话
                        continue
                        
                    return {"error": f"HTTP {response.status_code}: {response.text}"}
                    
            except Exception as e:
                print(f"   ⚠️  连接错误: {str(e)}, 正在重试 ({attempt + 1}/{max_retries})...", flush=True)
                self._refresh_session() # 出错时刷新会话
                if attempt == max_retries - 1:
                    return {"error": str(e)}
                time.sleep(5 * (attempt + 1)) # 增加等待时间
        
        return {"error": "达到最大重试次数"}
    
    def scan_directory(self, directory: str) -> str:
        """扫描整个目录（创建扫描任务）"""
        data = {
            "target_path": directory,
            "scan_type": "full"
        }
        response = self.session.post(
            f"{self.api_url}/api/scan/",
            json=data
        )
        
        if response.status_code == 200:
            result = response.json()
            return result.get("task_id")
        else:
            print(f"❌ 创建扫描任务失败: {response.text}")
            return None
    
    def get_task_status(self, task_id: str) -> Dict:
        """获取扫描任务状态"""
        response = self.session.get(f"{self.api_url}/api/scan/{task_id}")
        if response.status_code == 200:
            return response.json()
        return {}
    
    def get_task_results(self, task_id: str) -> List[Dict]:
        """获取扫描结果"""
        response = self.session.get(f"{self.api_url}/api/scan/{task_id}/results")
        if response.status_code == 200:
            return response.json()
        return []
    
    def get_rules_count(self) -> int:
        """获取规则数量"""
        try:
            response = self.session.get(f"{self.api_url}/api/rules/?limit=10000")
            if response.status_code == 200:
                rules = response.json()
                return len(rules)
        except:
            pass
        return 0


def scan_single_file(scanner: YaraScanner, file_path: str):
    """扫描单个文件并显示结果"""
    print(f"\n🔍 正在扫描文件: {file_path}")
    print("-" * 60)
    
    result = scanner.scan_file(file_path)
    
    if "error" in result:
        print(f"❌ 扫描失败: {result['error']}")
        return
    
    print(f"📄 文件名: {result.get('file_name')}")
    print(f"🔢 SHA256: {result.get('file_hash')}")
    print(f"🛡️  威胁级别: {result.get('threat_level')}")
    print(f"⚠️  是否恶意: {'是 ❌' if result.get('is_malicious') else '否 ✅'}")
    
    matched_rules = result.get('matched_rules', [])
    if matched_rules:
        print(f"📋 匹配的规则 ({len(matched_rules)} 条):")
        for rule in matched_rules:
            print(f"   - {rule}")
    else:
        print("✅ 未检测到恶意特征")
    
    print("-" * 60)


from concurrent.futures import ThreadPoolExecutor, as_completed

def batch_scan_directory(scanner: YaraScanner, directory: str, report_path: str = "scan_report.json"):
    """批量扫描目录下的所有文件 (多线程)"""
    print(f"\n📂 批量扫描目录: {directory}")
    print("=" * 60)
    
    # 获取所有文件
    files = []
    for root, dirs, filenames in os.walk(directory):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            files.append(file_path)
    
    print(f"📊 找到 {len(files)} 个文件")
    
    # 扫描每个文件
    results = []
    malicious_count = 0
    max_workers = 4  # 降低并发数到4，提高稳定性
    
    print(f"🚀 启动 {max_workers} 个线程进行扫描...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        future_to_file = {executor.submit(scanner.scan_file, f): f for f in files}
        
        for i, future in enumerate(as_completed(future_to_file), 1):
            file_path = future_to_file[future]
            filename = os.path.basename(file_path)
            
            try:
                result = future.result()
                
                print(f"\n[{i}/{len(files)}] 扫描: {filename}", flush=True)
                
                if "error" not in result:
                    results.append({
                        "file": file_path,
                        "is_malicious": result.get('is_malicious'),
                        "threat_level": result.get('threat_level'),
                        "matched_rules": result.get('matched_rules', [])
                    })
                    
                    if result.get('is_malicious'):
                        malicious_count += 1
                        print(f"   ⚠️  检测到恶意: 匹配 {len(result.get('matched_rules', []))} 条规则", flush=True)
                    else:
                        print(f"   ✅ 安全", flush=True)
                else:
                    print(f"   ❌ 扫描失败: {result.get('error', '未知错误')}", flush=True)
            
            except Exception as e:
                print(f"   ❌ 错误: {str(e)}", flush=True)
                
            # 每100个文件保存一次报告，防止丢失
            if i % 100 == 0:
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
    
    # 输出统计信息
    print("\n" + "=" * 60)
    print("📈 扫描统计:")
    print(f"   总文件数: {len(files)}")
    print(f"   成功扫描: {len(results)}")
    print(f"   检测到恶意: {malicious_count}")
    print(f"   安全文件: {len(results) - malicious_count}")
    print(f"   检出率: {(malicious_count / len(results) * 100):.2f}%" if results else "   检出率: 0%")
    
    # 保存详细报告
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 详细报告已保存到: {report_path}")
    print("=" * 60)


def run_main():
    """主函数"""
    print("=" * 60)
    print("   YARA-X Manager - 批量扫描工具")
    print("=" * 60)
    
    # 创建扫描器实例
    scanner = YaraScanner()
    
    # 检查后端服务
    print("\n🔌 检查后端服务...")
    if not scanner.check_health():
        print("❌ 后端服务未运行！请先启动后端服务：")
        print("   cd backend")
        print("   python main.py")
        return
    
    print("✅ 后端服务正常")
    
    # 检查规则数量
    rules_count = scanner.get_rules_count()
    print(f"📋 已加载规则数: {rules_count} 条")
    
    if rules_count == 0:
        print("⚠️  警告: 没有加载任何规则！请先运行:")
        print("   cd backend")
        print("   python load_all_rules.py")
        return
    
    # 使用说明
    print("\n" + "=" * 60)
    print("使用方法:")
    print("=" * 60)
    print("\n方式一: 扫描单个文件")
    print("   python batch_scan.py file <文件路径>")
    print("\n方式二: 批量扫描目录")
    print("   python batch_scan.py dir <目录路径>")
    print("\n示例:")
    print("   python batch_scan.py file ../data/samples/malware.exe")
    print("   python batch_scan.py dir ../data/samples/")
    print("=" * 60)
    
    # 解析命令行参数
    if len(sys.argv) < 3:
        print("\n💡 请输入扫描目标:")
        print("   1. 扫描单个文件")
        print("   2. 扫描整个目录")
        choice = input("\n请选择 (1/2): ").strip()
        
        if choice == "1":
            file_path = input("请输入文件路径: ").strip()
            if os.path.isfile(file_path):
                scan_single_file(scanner, file_path)
            else:
                print("❌ 文件不存在")
        
        elif choice == "2":
            dir_path = input("请输入目录路径: ").strip()
            if os.path.isdir(dir_path):
                batch_scan_directory(scanner, dir_path)
            else:
                print("❌ 目录不存在")
        
        return
    
    # 命令行参数模式
    mode = sys.argv[1]
    target = sys.argv[2]
    report_path = "scan_report.json"
    if len(sys.argv) > 3:
        report_path = sys.argv[3]
    
    if mode == "file":
        if os.path.isfile(target):
            scan_single_file(scanner, target)
        else:
            print(f"❌ 文件不存在: {target}")
    
    elif mode == "dir":
        if os.path.isdir(target):
            batch_scan_directory(scanner, target, report_path)
        else:
            print(f"❌ 目录不存在: {target}")
    
    else:
        print(f"❌ 未知模式: {mode}")
        print("   请使用 'file' 或 'dir'")


if __name__ == "__main__":
    run_main()
