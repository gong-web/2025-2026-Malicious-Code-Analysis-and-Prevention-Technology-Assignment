import yaml
import re
import fnmatch


class CompiledSigmaRule:
    def __init__(self, name, rule_id, selections, condition_expr, keywords=None):
        self.name = name
        self.rule_id = rule_id
        self.selections = selections
        self.condition_expr = condition_expr
        self.keywords = keywords or []

    def match_event(self, event):
        def sel(name):
            if name == "keywords":
                msg = str(event.get("message", ""))
                low = msg.lower()
                return any(k.lower() in low for k in self.keywords)
            if name not in self.selections:
                return False
            for field, expect in self.selections[name].items():
                val = event.get(field)
                ok = False
                for m in expect:
                    t, p = m
                    if val is None:
                        ok = False
                    elif t == "eq":
                        ok = str(val) == p
                    elif t == "glob":
                        ok = fnmatch.fnmatch(str(val), p)
                    elif t == "regex":
                        ok = re.search(p, str(val)) is not None
                    elif t == "contains":
                        ok = p in str(val)
                    if ok:
                        break
                if not ok:
                    return False
            return True

        names = list(self.selections.keys())

        def match_names(pattern):
            if pattern == "them":
                return names
            return [n for n in names if fnmatch.fnmatch(n, pattern)]

        def one_of(pattern, n):
            c = 0
            for nm in match_names(pattern):
                if sel(nm):
                    c += 1
                    if c >= n:
                        return True
            return False

        def all_of(pattern):
            for nm in match_names(pattern):
                if not sel(nm):
                    return False
            return True

        try:
            return bool(eval(self.condition_expr, {}, {"sel": sel, "one_of": one_of, "all_of": all_of}))
        except Exception:
            return False


def _compile_matchers(value):
    matchers = []
    if isinstance(value, list):
        for v in value:
            matchers += _compile_matchers(v)
        return matchers
    if isinstance(value, str):
        s = value
        if len(s) >= 2 and s[0] == "/" and s[-1] == "/":
            return [("regex", s[1:-1])]
        if "*" in s or "?" in s:
            return [("glob", s)]
        return [("eq", s)]
    return [("eq", str(value))]


def _transform_condition(cond, selection_names):
    expr = cond
    expr = re.sub(r"\bAND\b", "and", expr, flags=re.I)
    expr = re.sub(r"\bOR\b", "or", expr, flags=re.I)
    expr = re.sub(r"\bNOT\b", "not", expr, flags=re.I)

    def repl_one_of(m):
        num = int(m.group(1))
        pat = m.group(2)
        return f"one_of(\"{pat}\", {num})"

    expr = re.sub(r"(\d+)\s+of\s+([\w\-*]+|them)", repl_one_of, expr, flags=re.I)

    def repl_all_of(m):
        pat = m.group(1)
        return f"all_of(\"{pat}\")"

    expr = re.sub(r"all\s+of\s+([\w\-*]+|them)", repl_all_of, expr, flags=re.I)

    def wrap_sel(m):
        ident = m.group(0)
        if ident.lower() in {"and", "or", "not", "them"}:
            return ident
        if ident in selection_names or ident == "keywords":
            return f"sel(\"{ident}\")"
        return ident

    expr = re.sub(r"\b[\w\-]+\b", wrap_sel, expr)
    return expr


def compile_sigma_rule(content):
    d = yaml.safe_load(content)
    title = str(d.get("title", "")).strip() or str(d.get("id", "")).strip() or "sigma_rule"
    rule_id = str(d.get("id", "")).strip()
    det = d.get("detection", {})

    selections = {}
    keywords = None
    for k, v in det.items():
        if k == "condition":
            continue
        if k == "keywords":
            if isinstance(v, list):
                keywords = [str(x) for x in v]
            elif isinstance(v, str):
                keywords = [v]
            continue
        if isinstance(v, dict):
            compiled = {}
            for field, expect in v.items():
                ms = []
                if isinstance(expect, list):
                    for it in expect:
                        ms += _compile_matchers(it)
                else:
                    ms = _compile_matchers(expect)
                compiled[field] = ms
            selections[k] = compiled

    cond = str(det.get("condition", "")) or ("keywords" if keywords else "")
    condition_expr = _transform_condition(cond, list(selections.keys()))

    return CompiledSigmaRule(title, rule_id, selections, condition_expr, keywords)