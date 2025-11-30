import yaml
import os
import re
from typing import List, Dict, Any, Union
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class SigmaRule:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.data = self._load_rule()
        self.id = self.data.get("id", "")
        self.title = self.data.get("title", "")
        self.level = self.data.get("level", "medium")
        self.logsource = self.data.get("logsource", {})
        self.detection = self.data.get("detection", {})
        self.condition = self.detection.get("condition", "")
        # Regex cache for this rule
        self.regex_cache = {}
        
    def _load_rule(self) -> Dict:
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load rule {self.file_path}: {e}")
            return {}

    def match(self, event: Dict[str, Any]) -> bool:
        """
        Check if the event matches this rule.
        """
        # 1. Check logsource (optional, simplistic check)
        if not self._match_logsource(event):
            return False

        # 2. Evaluate detection logic
        try:
            return self._evaluate_condition(event)
        except Exception as e:
            # logger.debug(f"Rule {self.title} evaluation error: {e}")
            return False

    def _match_logsource(self, event: Dict[str, Any]) -> bool:
        # Basic check: if rule specifies product/service, event should match
        # This depends heavily on event format. 
        # Assuming event has 'product', 'service', 'category' fields if available.
        # If event doesn't have them, we skip logsource check or be permissive.
        
        product = self.logsource.get("product")
        service = self.logsource.get("service")
        category = self.logsource.get("category")
        
        # If event has metadata, check it.
        # For now, we assume permissive matching if event lacks metadata
        return True

    def _evaluate_condition(self, event: Dict[str, Any]) -> bool:
        # This is a simplified condition evaluator.
        # It handles:
        # - selection names
        # - '1 of ...'
        # - 'all of ...'
        # - logical operators (and, or, not) - via simple evaluation or heuristics
        
        condition = str(self.condition).strip()
        
        # Pre-calculate all selections
        selections = {}
        for key, value in self.detection.items():
            if key == "condition":
                continue
            selections[key] = self._check_selection(value, event)
            
        # Handle "1 of ..."
        if condition.startswith("1 of"):
            pattern = condition.replace("1 of", "").strip()
            return self._check_x_of(pattern, selections, 1)
            
        # Handle "all of ..."
        if condition.startswith("all of"):
            pattern = condition.replace("all of", "").strip()
            return self._check_x_of(pattern, selections, len(selections))
            
        # Handle simple boolean logic (VERY BASIC)
        # We replace selection names with their boolean result (True/False) and eval
        # This is dangerous but we are in a controlled backend environment
        # To make it safer, we only allow known tokens
        
        # specific keywords
        keywords = set(selections.keys())
        
        # Replace keywords with results
        # Sort by length desc to avoid partial replacements
        sorted_keys = sorted(keywords, key=len, reverse=True)
        
        eval_string = condition.lower()
        
        # Map for safety
        mapping = {}
        for i, key in enumerate(sorted_keys):
            placeholder = f"__VAR_{i}__"
            mapping[placeholder] = str(selections[key])
            # use word boundaries regex
            eval_string = re.sub(r'\b' + re.escape(key.lower()) + r'\b', placeholder, eval_string)
            
        for placeholder, val in mapping.items():
            eval_string = eval_string.replace(placeholder, val)
            
        # Sanitize eval_string
        allowed_chars = set(" abcdefghijklmnopqrstuvwxyz0123456789_().")
        if not set(eval_string).issubset(allowed_chars):
             # If complex stuff remains, fail safe
             return False
             
        try:
            # Python's 'and', 'or', 'not' match Sigma's
            return eval(eval_string, {"__builtins__": {}})
        except:
            return False

    def _check_x_of(self, pattern: str, selections: Dict[str, bool], threshold: int) -> bool:
        # pattern can be "selection*" or "them" (all defined selections)
        count = 0
        targets = []
        
        if pattern == "them":
            targets = selections.keys()
        else:
            # simple wildcard support
            regex = pattern.replace("*", ".*")
            targets = [k for k in selections.keys() if re.match(regex, k)]
            
        for t in targets:
            if selections.get(t, False):
                count += 1
        
        if threshold == len(selections) and pattern == "them": # all of them
             return count == len(selections)
             
        return count >= threshold

    def _check_selection(self, selection: Any, event: Dict[str, Any]) -> bool:
        if isinstance(selection, list):
            # List of strings usually means "keywords" search in entire event
            # Or it's a list of maps (OR logic)
            # Sigma standard says list of maps is OR
            # List of strings is keywords match
            
            is_keyword_search = all(isinstance(x, str) for x in selection)
            if is_keyword_search:
                # Check if ANY string matches ANY value in event
                for keyword in selection:
                    if self._keyword_match(keyword, event):
                        return True
                return False
            else:
                # List of maps -> OR
                for item in selection:
                    if self._check_selection(item, event):
                        return True
                return False
                
        elif isinstance(selection, dict):
            # Map -> AND
            for field, value in selection.items():
                if not self._check_field(field, value, event):
                    return False
            return True
            
        return False

    def _keyword_match(self, keyword: str, event: Dict[str, Any]) -> bool:
        # Recursive search in values
        s_keyword = str(keyword).lower()
        
        stack = [event]
        while stack:
            curr = stack.pop()
            if isinstance(curr, dict):
                stack.extend(curr.values())
            elif isinstance(curr, list):
                stack.extend(curr)
            elif isinstance(curr, str):
                if s_keyword in curr.lower():
                    return True
            else:
                if s_keyword in str(curr).lower():
                    return True
        return False

    def _check_field(self, field: str, value: Any, event: Dict[str, Any]) -> bool:
        # Handle modifiers like |contains, |endswith, |startswith
        modifier = None
        if "|" in field:
            field, modifier = field.split("|", 1)
            
        # Lookup value in event (dot notation)
        event_value = self._get_event_value(field, event)
        if event_value is None:
            return False  # Field not found
            
        # Comparison
        if isinstance(value, list):
            # Value list -> OR (one of the values must match)
            for v in value:
                if self._compare(event_value, v, modifier):
                    return True
            return False
        else:
            return self._compare(event_value, value, modifier)

    def _compare(self, event_val: Any, rule_val: Any, modifier: str) -> bool:
        s_event = str(event_val).lower()
        
        if modifier == "contains":
            # Optimized contains
            return str(rule_val).lower() in s_event
        elif modifier == "startswith":
            return s_event.startswith(str(rule_val).lower())
        elif modifier == "endswith":
            return s_event.endswith(str(rule_val).lower())
        elif modifier == "re":
            pattern_str = str(rule_val)
            try:
                # Check cache first
                regex = self.regex_cache.get(pattern_str)
                if not regex:
                    regex = re.compile(pattern_str, re.IGNORECASE)
                    self.regex_cache[pattern_str] = regex
                
                # Use search (not match, to allow partial unless ^$ specified)
                return bool(regex.search(str(event_val)))
            except Exception as e:
                # logger.debug(f"Regex error: {e}")
                return False
        else:
            # Exact match (with type conversion handling via string)
            return s_event == str(rule_val).lower()

    def _get_event_value(self, field: str, event: Dict[str, Any]) -> Any:
        # Handle nested fields with dot notation
        parts = field.split(".")
        curr = event
        
        for part in parts:
            if isinstance(curr, dict):
                curr = curr.get(part)
                if curr is None:
                    return None
            else:
                return None
        return curr


class SigmaEngine:
    def __init__(self, rules_dir: str = "data/sigma_rules"):
        self.rules_dir = rules_dir
        self.rules: List[SigmaRule] = []
        self.reload_rules()

    def reload_rules(self):
        self.rules = []
        if not os.path.exists(self.rules_dir):
            logger.warning(f"Sigma rules directory {self.rules_dir} does not exist")
            return
            
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith((".yml", ".yaml")):
                    rule_path = os.path.join(root, file)
                    rule = SigmaRule(rule_path)
                    if rule.data:
                        self.rules.append(rule)
        
        logger.info(f"Loaded {len(self.rules)} Sigma rules")

    def scan_event(self, event: Dict[str, Any]) -> List[Dict]:
        matches = []
        for rule in self.rules:
            if rule.match(event):
                matches.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "level": rule.level,
                    "tags": rule.data.get("tags", [])
                })
        return matches

    def scan_events(self, events: List[Dict[str, Any]]) -> List[Dict]:
        results = []
        for i, event in enumerate(events):
            matches = self.scan_event(event)
            if matches:
                results.append({
                    "event_index": i,
                    "event_data": event,  # simplify output?
                    "matches": matches
                })
        return results
