import yaml
import re
import json
import yara
from typing import Dict, Any
from datetime import datetime
from app.core.yara_ext import get_default_externals


class RuleValidator:
    def validate_yara_rule(self, content: str) -> Dict[str, Any]:
        try:
            start = datetime.now()
            yara.compile(source=content, externals=get_default_externals())
            ms = int((datetime.now() - start).total_seconds() * 1000)
            complexity = content.count("$") + content.count("regex") * 3 + content.count("pe.")
            return {"valid": True, "compile_time_ms": ms, "complexity_score": complexity}
        except yara.SyntaxError as e:
            return {"valid": False, "error": str(e)}
        except Exception as e:
            return {"valid": False, "error": f"未知错误: {str(e)}"}

    def validate_sigma_rule(self, content: str) -> Dict[str, Any]:
        try:
            d = yaml.safe_load(content)
            if not isinstance(d, dict):
                return {"valid": False, "error": "无效的YAML格式"}
            req = ["title","id","status","description","logsource","detection"]
            miss = [f for f in req if f not in d or not d[f]]
            if miss:
                return {"valid": False, "error": "缺少必需字段: " + ", ".join(miss)}
            det = d.get("detection", {})
            cond = det.get("condition", "")
            if not isinstance(cond, str):
                return {"valid": False, "error": "detection.condition 类型错误"}
            if cond.count("(") != cond.count(")"):
                return {"valid": False, "error": "condition 括号不匹配"}
            refs = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", cond)
            sel = {k for k in det.keys() if k != "condition"}
            for r in refs:
                if r not in sel and r not in {"and","or","not","all","1","of","them"}:
                    return {"valid": False, "error": "condition 引用了未定义字段: " + r}
            status = str(d.get("status","")).lower()
            if status and status not in {"experimental","test","stable"}:
                return {"valid": False, "error": "无效状态: " + status}
            level = str(d.get("level","")).lower()
            if level and level not in {"low","medium","high","critical"}:
                return {"valid": False, "error": "无效级别: " + level}
            info = self.extract_sigma_info(d)
            complexity = len(cond.split())
            return {"valid": True, "rule_info": info, "complexity_score": complexity}
        except yaml.YAMLError as e:
            return {"valid": False, "error": "YAML解析错误: " + str(e)}
        except Exception as e:
            return {"valid": False, "error": f"验证失败: {str(e)}"}

    def extract_sigma_info(self, d: Dict[str, Any]) -> Dict[str, Any]:
        log = d.get("logsource", {})
        det = d.get("detection", {})
        return {
            "title": d.get("title",""),
            "rule_id": d.get("id",""),
            "description": d.get("description",""),
            "status": d.get("status","experimental"),
            "level": d.get("level","medium"),
            "author": d.get("author",""),
            "date": d.get("date",""),
            "modified": d.get("modified",""),
            "logsource_product": log.get("product",""),
            "logsource_service": log.get("service",""),
            "logsource_category": log.get("category",""),
            "detection_condition": det.get("condition",""),
            "references": json.dumps(d.get("references", [])),
            "tags": json.dumps(d.get("tags", [])),
            "falsepositives": json.dumps(d.get("falsepositives", [])),
        }