import json
import re


def parse_line_kv(line):
    kv = {}
    for m in re.finditer(r"(\w[\w\.:]+)=\"([^\"]*)\"|(\w[\w\.:]+)=([^\s]+)", line):
        key = m.group(1) or m.group(3)
        val = m.group(2) or m.group(4)
        kv[key] = val
    if not kv:
        kv["message"] = line.strip()
    return kv


def parse_text_to_events(text):
    t = text.strip()
    if not t:
        return []
    if t.startswith("["):
        try:
            arr = json.loads(t)
            if isinstance(arr, list):
                return [e if isinstance(e, dict) else {"message": str(e)} for e in arr]
        except Exception:
            pass
    lines = [ln for ln in t.splitlines() if ln.strip()]
    evs = []
    for ln in lines:
        s = ln.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                obj = json.loads(s)
                if isinstance(obj, dict):
                    evs.append(obj)
                    continue
            except Exception:
                pass
        evs.append(parse_line_kv(s))
    return evs