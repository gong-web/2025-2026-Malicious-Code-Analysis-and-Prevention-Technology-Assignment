import subprocess
import json
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Tuple
import os

# 获取项目根目录中的 yr 命令路径
PROJECT_ROOT = Path(__file__).parent.parent
YR_CMD = str(PROJECT_ROOT / "yr") if (PROJECT_ROOT / "yr").exists() else "yr"

def validate_yara(rule_content: str) -> Tuple[bool, str]:
    """
    验证YARA规则语法是否正确
    返回: (是否有效, 错误信息)
    """
    try:
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False, encoding='utf-8') as tmp:
            tmp.write(rule_content)
            tmp_path = Path(tmp.name)
        
        try:
            # 尝试编译规则
            cmd = [YR_CMD, "check", str(tmp_path)]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5, cwd=str(PROJECT_ROOT))
            
            if r.returncode == 0:
                return (True, "")
            else:
                return (False, r.stderr.strip() or r.stdout.strip())
        finally:
            tmp_path.unlink(missing_ok=True)
    except subprocess.TimeoutExpired:
        return (False, "Validation timeout")
    except Exception as e:
        return (False, str(e))

# Compile YARA-X rules into a single binary rules file
def _compile_rules(rule_paths: List[Path]) -> Path:
    if not rule_paths:
        raise ValueError("rule_paths empty")
    tmp = tempfile.NamedTemporaryFile(suffix=".yarc", delete=False)
    tmp.close()
    out = Path(tmp.name)
    cmd = [YR_CMD, "compile", "-o", str(out)] + [str(p) for p in rule_paths]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        out.unlink(missing_ok=True)
        raise RuntimeError(r.stderr.strip())
    return out
# Run YARA-X and process output results
def run_yara_json(rule_paths: List[Path], target: Path) -> Dict[str, Any]:
    arc = _compile_rules(rule_paths)
    try:
        cmd = [YR_CMD, "scan", "-C", "--output-format", "json", str(arc), str(target)]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode not in (0, 1):
            raise RuntimeError(r.stderr.strip())
        raw = r.stdout.strip()
        if not raw:
            return {"matches": []}
        j = json.loads(raw)
        out = []
        for m in j.get("matches", []):
            out.append({
                "rule": m.get("rule"),
                "file": m.get("file")
            })

        return {"matches": out}
    finally:
        arc.unlink(missing_ok=True)

def scan_sample(sample_path: str, rule_paths: List[str]) -> Dict[str, Any]:
    """
    扫描单个样本文件
    """
    try:
        rule_path_objs = [Path(p) for p in rule_paths]
        sample_path_obj = Path(sample_path)
        
        if not sample_path_obj.exists():
            return {"matches": [], "error": f"Sample file not found: {sample_path}"}
        
        result = run_yara_json(rule_path_objs, sample_path_obj)
        return result
    except Exception as e:
        return {"matches": [], "error": str(e)}
