#!/usr/bin/env python3
"""
Project structure cleanup and organization script
清理和组织项目结构
"""
import os
import shutil
from pathlib import Path
from datetime import datetime

# 项目根目录
ROOT = Path(".")

# 需要保留的关键文件夹
KEEP_DIRS = {
    "backend",
    "frontend", 
    "db",
    "tools",
    ".git",
    ".gitignore"
}

# 需要保留的关键文件
KEEP_FILES = {
    "README.md",
    ".gitignore",
    ".env.example",
    "docker-compose.yml",
    "requirements.txt"
}

# 需要清理的文件模式
CLEANUP_PATTERNS = [
    "*.md",  # 所有markdown报告文件
    "*.ps1",  # 所有powershell脚本
    "*.yar",  # 根目录下的yara文件
    "*.txt",  # 根目录下的txt文件
    "*.py",  # 根目录下的python文件
]

# 需要备份和清理的文件夹
BACKUP_DIRS = [
    "BinaryCollection",
    "YARA-X Manager", 
    "yara-rules-By-LYT",
    "yara_rules_By_FWX",
    "yararules"
]

def main():
    print("=" * 60)
    print("🧹 项目结构清理工具")
    print("=" * 60)
    
    # 创建备份
    backup_dir = Path(f"docs/backups/{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    backup_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n📦 备份目录: {backup_dir}")
    
    # 备份要删除的文件夹
    for dir_name in BACKUP_DIRS:
        dir_path = ROOT / dir_name
        if dir_path.exists():
            print(f"  备份 {dir_name}...")
            shutil.move(str(dir_path), str(backup_dir / dir_name))
    
    # 清理根目录文件
    print("\n🗑️  清理根目录文件...")
    cleanup_count = 0
    
    # 清理markdown文件（除了重要的）
    important_md = {"README.md"}
    for md_file in ROOT.glob("*.md"):
        if md_file.name not in important_md:
            print(f"  删除 {md_file.name}")
            md_file.unlink()
            cleanup_count += 1
    
    # 清理powershell脚本（保留start-backend.ps1）
    keep_ps = {"start-backend.ps1"}
    for ps_file in ROOT.glob("*.ps1"):
        if ps_file.name not in keep_ps:
            print(f"  删除 {ps_file.name}")
            ps_file.unlink()
            cleanup_count += 1
    
    # 清理根目录test和sample文件
    for pattern in ["test*.py", "test*.yar", "test*.txt"]:
        for file in ROOT.glob(pattern):
            if file.is_file():
                print(f"  删除 {file.name}")
                file.unlink()
                cleanup_count += 1
    
    print(f"\n✅ 清理完成: {cleanup_count} 个文件")
    
    # 创建docs目录结构
    print("\n📚 创建文档目录结构...")
    docs_dirs = [
        "docs",
        "docs/backups",
        "docs/guides",
        "docs/api"
    ]
    for doc_dir in docs_dirs:
        Path(doc_dir).mkdir(parents=True, exist_ok=True)
    
    # 创建scripts目录
    scripts_dir = Path("scripts")
    scripts_dir.mkdir(exist_ok=True)
    print("  created scripts/")
    
    # 整理启动脚本
    if Path("start-backend.ps1").exists():
        shutil.move("start-backend.ps1", "scripts/start-backend.ps1")
        print("  moved start-backend.ps1 -> scripts/")
    
    print("\n" + "=" * 60)
    print("✨ 项目结构清理完成!")
    print("=" * 60)
    print("\n📁 最终结构:")
    print("  ├── backend/         (后端代码)")
    print("  ├── frontend/        (前端代码)")
    print("  ├── db/              (数据库)")
    print("  ├── docs/            (文档和备份)")
    print("  ├── scripts/         (脚本)")
    print("  ├── tools/           (工具)")
    print("  ├── README.md        (主文档)")
    print("  ├── docker-compose.yml")
    print("  └── .gitignore")

if __name__ == "__main__":
    main()
