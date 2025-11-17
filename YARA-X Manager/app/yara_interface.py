import subprocess
import json
import tempfile
from pathlib import Path
from typing import List, Dict, Any
# Compile YARA-X rules into a single binary rules file
def _compile_rules(rule_paths: List[Path]) -> Path:
    if not rule_paths:
        raise ValueError("rule_paths empty")
    tmp = tempfile.NamedTemporaryFile(suffix=".yarc", delete=False)
    tmp.close()
    out = Path(tmp.name)
    cmd = ["yara-x", "compile", "-o", str(out)] + [str(p) for p in rule_paths]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        out.unlink(missing_ok=True)
        raise RuntimeError(r.stderr.strip())
    return out
# Run YARA-X and process output results
def run_yara_json(rule_paths: List[Path], target: Path) -> Dict[str, Any]:
    arc = _compile_rules(rule_paths)
    try:
        cmd = ["yara-x", "scan", "-C", "--output-format", "json", str(arc), str(target)]
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
