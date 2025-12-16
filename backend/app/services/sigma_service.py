from app.core.sigma_engine import SigmaEngine
import os
from pathlib import Path

# Global singleton
_sigma_engine = None

def get_sigma_engine() -> SigmaEngine:
    global _sigma_engine
    if _sigma_engine is None:
        # 获取项目根目录
        # 当前文件在 backend/app/services/sigma_service.py
        # 需要向上4级到达项目根目录
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent.parent
        rules_dir = os.getenv("SIGMA_RULES_DIR", str(project_root / "data" / "sigma_rules"))
        
        print(f"Initializing Sigma Engine with rules from: {rules_dir}")
        _sigma_engine = SigmaEngine(rules_dir)
        
    return _sigma_engine
