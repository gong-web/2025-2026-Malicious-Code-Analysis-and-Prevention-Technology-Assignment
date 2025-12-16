import yaml
import os
import re
from typing import List, Dict, Any, Union
from pathlib import Path
import logging
import pickle
import time
from app.core.config import settings

logger = logging.getLogger(__name__)

# 常见字段映射表 (Field Normalization)
# 将 Sigma 标准字段名映射到不同日志采集器(Winlogbeat, Sysmon等)的实际路径
FIELD_MAPPINGS = {
    "Image": ["winlog.event_data.Image", "EventData.Image", "ProcessName", "app"],
    "CommandLine": ["winlog.event_data.CommandLine", "EventData.CommandLine", "cmdline"],
    "ParentImage": ["winlog.event_data.ParentImage", "EventData.ParentImage", "p_app"],
    "ParentCommandLine": ["winlog.event_data.ParentCommandLine", "EventData.ParentCommandLine"],
    "User": ["winlog.user.name", "EventData.User", "UserName", "user"],
    "LogonId": ["winlog.logon.id", "EventData.LogonId"],
    "ComputerName": ["host.name", "Computer", "EventData.ComputerName", "host"],
    "OriginalFileName": ["winlog.event_data.OriginalFileName", "EventData.OriginalFileName"],
    "Hashes": ["winlog.event_data.Hashes", "EventData.Hashes"],
    "TargetFilename": ["winlog.event_data.TargetFilename", "EventData.TargetFilename"],
    "DestAddress": ["winlog.event_data.DestAddress", "EventData.DestinationIp", "dst_ip"],
    "DestPort": ["winlog.event_data.DestPort", "EventData.DestinationPort", "dst_port"],
    "SourceAddress": ["winlog.event_data.SourceAddress", "EventData.SourceIp", "src_ip"],
    "SourcePort": ["winlog.event_data.SourcePort", "EventData.SourcePort", "src_port"],
    "EventID": ["winlog.event_id", "EventData.EventID", "event_id"],
}

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
        # Analysis triggers for indexing
        self.trigger_event_ids = set()
        self._analyze_triggers()
        
        # Optimization: Pre-compile condition
        self.compiled_condition = None
        self.x_of_pattern = None
        self.x_of_threshold = 0
        self._precompile_condition()
        
    def __getstate__(self):
        """
        Pickle 序列化控制：剔除 regex_cache，因为它包含无法序列化的已编译正则对象（或避免大体积）
        """
        state = self.__dict__.copy()
        state['regex_cache'] = {}
        state['compiled_condition'] = None # Code objects can be pickled but safe to recompile
        return state

    def __setstate__(self, state):
        """
        Pickle 反序列化控制：恢复 regex_cache
        """
        self.__dict__.update(state)
        self.regex_cache = {}
        self._precompile_condition()

    def _precompile_condition(self):
        raw_cond = str(self.condition).strip()
        if not raw_cond:
            return

        # Handle "1 of ..." / "all of ..."
        if raw_cond.startswith("1 of"):
            self.x_of_pattern = raw_cond.replace("1 of", "").strip()
            self.x_of_threshold = 1
            return
        if raw_cond.startswith("all of"):
            self.x_of_pattern = raw_cond.replace("all of", "").strip()
            # Count defined selections (excluding 'condition' itself)
            count = len([k for k in self.detection if k != "condition"])
            self.x_of_threshold = count
            return

        # Boolean logic
        # Replace selection names with s['name']
        # 1. Get all selection keys
        keys = [k for k in self.detection.keys() if k != "condition"]
        # 2. Sort by length desc to avoid partial replacements
        keys.sort(key=len, reverse=True)
        
        escaped_cond = raw_cond.lower()
        
        for key in keys:
            # Replace 'key' with "s['key']"
            # Use word boundaries to avoid replacing substrings
            pattern = r'\b' + re.escape(key.lower()) + r'\b'
            escaped_cond = re.sub(pattern, f"s['{key}']", escaped_cond)
            
        try:
            self.compiled_condition = compile(escaped_cond, '<string>', 'eval')
        except Exception as e:
            # logger.warning(f"Failed to compile condition for {self.file_path}: {e}")
            pass

    def _analyze_triggers(self):
        """
        Analyze the rule content to find specific triggers like EventID.
        This helps in indexing the rules for faster lookup.
        """
        try:
            # Check selections in detection
            for key, value in self.detection.items():
                if key == "condition":
                    continue
                
                if isinstance(value, dict):
                    # Check for EventID or EventId or event_id
                    for field, val in value.items():
                        field_lower = field.lower()
                        if field_lower in ["eventid", "event_id"] or field_lower.endswith(".eventid") or field_lower.endswith(".event_id"):
                            if isinstance(val, list):
                                for v in val:
                                    self.trigger_event_ids.add(str(v))
                            else:
                                self.trigger_event_ids.add(str(val))
        except Exception as e:
            logger.warning(f"Failed to analyze triggers for rule {self.file_path}: {e}")

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
        # - logical operators (and, or, not) - via pre-compiled python code
        
        # Pre-calculate all selections
        selections = {}
        for key, value in self.detection.items():
            if key == "condition":
                continue
            selections[key] = self._check_selection(value, event)
            
        # Handle "1 of ..." / "all of ..."
        if self.x_of_pattern:
            return self._check_x_of(self.x_of_pattern, selections, self.x_of_threshold)
            
        # Handle boolean logic via pre-compiled code
        if self.compiled_condition:
            try:
                return eval(self.compiled_condition, {"s": selections})
            except:
                return False
        
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
        # 1. Try direct lookup (including dot notation)
        val = self._lookup_path(field, event)
        if val is not None:
            return val
            
        # 2. Try mapped fields (Field Normalization)
        # If the exact field is not found, check if we have known mappings for it
        if field in FIELD_MAPPINGS:
            for mapped_path in FIELD_MAPPINGS[field]:
                val = self._lookup_path(mapped_path, event)
                if val is not None:
                    return val
                    
        return None

    def _lookup_path(self, path: str, event: Dict[str, Any]) -> Any:
        """
        Helper to look up a value in a nested dictionary using dot notation
        """
        parts = path.split(".")
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
        
        # Indexing structures
        self.rules_by_event_id: Dict[str, List[SigmaRule]] = {}
        self.common_rules: List[SigmaRule] = []
        
        # 尝试加载缓存
        if not self.load_cache():
            self.reload_rules()
        else:
            # If loaded from cache, we still need to build the index
            # The cache stores the rules list, but not the index
            self._build_index()

    def _build_index(self):
        """
        Build inverted index for fast rule lookup based on EventID
        """
        self.rules_by_event_id = {}
        self.common_rules = []
        
        for rule in self.rules:
            if rule.trigger_event_ids:
                for eid in rule.trigger_event_ids:
                    if eid not in self.rules_by_event_id:
                        self.rules_by_event_id[eid] = []
                    self.rules_by_event_id[eid].append(rule)
            else:
                self.common_rules.append(rule)
        
        logger.info(f"Index built: {len(self.rules_by_event_id)} EventIDs indexed, {len(self.common_rules)} common rules")

    def load_cache(self) -> bool:
        """
        尝试加载持久化的编译缓存
        """
        cache_path = settings.SIGMA_COMPILED_PATH
        if not os.path.exists(cache_path):
            return False
            
        try:
            start_time = time.time()
            with open(cache_path, 'rb') as f:
                self.rules = pickle.load(f)
            
            duration = time.time() - start_time
            logger.info(f"Loaded {len(self.rules)} Sigma rules from cache in {duration:.2f}s")
            return True
        except Exception as e:
            logger.warning(f"Failed to load Sigma cache: {e}")
            return False

    def save_cache(self):
        """
        保存编译后的规则到磁盘
        """
        cache_path = settings.SIGMA_COMPILED_PATH
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            
            with open(cache_path, 'wb') as f:
                pickle.dump(self.rules, f)
            logger.info(f"Saved {len(self.rules)} compiled Sigma rules to {cache_path}")
        except Exception as e:
            logger.error(f"Failed to save Sigma cache: {e}")

    def reload_rules(self):
        """
        重新加载规则源文件并更新缓存
        """
        self.rules = []
        if not os.path.exists(self.rules_dir):
            logger.warning(f"Sigma rules directory {self.rules_dir} does not exist")
            return
            
        start_time = time.time()
        count = 0
        
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith((".yml", ".yaml")):
                    rule_path = os.path.join(root, file)
                    rule = SigmaRule(rule_path)
                    if rule.data:
                        self.rules.append(rule)
                        count += 1
        
        duration = time.time() - start_time
        logger.info(f"Loaded {len(self.rules)} Sigma rules from source in {duration:.2f}s")
        
        # 更新缓存
        self.save_cache()
        
        # Rebuild index
        self._build_index()

    def scan_event(self, event: Dict[str, Any]) -> List[Dict]:
        matches = []
        
        # Extract EventID from event to filter rules
        # Try common fields for EventID
        event_id = None
        # Check root level
        if "EventID" in event:
            event_id = str(event["EventID"])
        elif "EventId" in event:
            event_id = str(event["EventId"])
        elif "event_id" in event:
            event_id = str(event["event_id"])
        # Check winlogbeat format
        elif "winlog" in event and isinstance(event["winlog"], dict) and "event_id" in event["winlog"]:
            event_id = str(event["winlog"]["event_id"])
            
        # Select candidate rules
        candidate_rules = self.common_rules
        if event_id and event_id in self.rules_by_event_id:
            # Add specific rules for this EventID
            candidate_rules = candidate_rules + self.rules_by_event_id[event_id]
        elif not event_id:
            # If no EventID found, we might need to check all rules if we want to be safe
            # But for performance optimization, we usually rely on EventID
            # If strict safety is needed, uncomment next line:
            # candidate_rules = self.rules
            pass
            
        for rule in candidate_rules:
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
