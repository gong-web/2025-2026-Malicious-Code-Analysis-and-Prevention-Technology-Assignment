"""
测试 Sigma 规则路径是否正确配置
"""
import sys
from pathlib import Path

# 添加 backend 到 Python 路径
sys.path.insert(0, str(Path(__file__).parent))

from app.api.sigma_rules import SIGMA_RULES_DIR, CUSTOM_RULES_DIR
from app.services.sigma_service import get_sigma_engine
from app.core.config import settings

def test_paths():
    print("=== Sigma 规则路径测试 ===\n")
    
    # 1. 检查 API 中的路径
    print(f"1. API SIGMA_RULES_DIR: {SIGMA_RULES_DIR}")
    print(f"   是否存在: {SIGMA_RULES_DIR.exists()}")
    print(f"   是否是目录: {SIGMA_RULES_DIR.is_dir()}")
    
    if SIGMA_RULES_DIR.exists():
        yml_files = list(SIGMA_RULES_DIR.rglob("*.yml"))
        print(f"   找到 .yml 文件数量: {len(yml_files)}")
        if yml_files:
            print(f"   示例文件: {yml_files[0].name}")
    print()
    
    # 2. 检查自定义规则目录
    print(f"2. CUSTOM_RULES_DIR: {CUSTOM_RULES_DIR}")
    print(f"   是否存在: {CUSTOM_RULES_DIR.exists()}")
    print()
    
    # 3. 检查配置文件中的路径
    print(f"3. Config SIGMA_COMPILED_PATH: {settings.SIGMA_COMPILED_PATH}")
    print()
    
    # 4. 检查 Sigma Engine
    print("4. 测试 Sigma Engine 初始化...")
    try:
        engine = get_sigma_engine()
        print(f"   Engine rules_dir: {engine.rules_dir}")
        print(f"   加载的规则数量: {len(engine.rules)}")
        if engine.rules:
            print(f"   示例规则标题: {engine.rules[0].title}")
    except Exception as e:
        print(f"   ❌ 初始化失败: {e}")
    
    print("\n=== 测试完成 ===")

if __name__ == "__main__":
    test_paths()
