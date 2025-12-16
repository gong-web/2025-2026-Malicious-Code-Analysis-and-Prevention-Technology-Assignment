import logging
import os
import re
import random
from datetime import datetime
from typing import List, Dict, Any
from app.core.config import settings

logger = logging.getLogger(__name__)

class DynamicAnalyzer:
    """
    Safe dynamic analyzer that only performs static string extraction.
    Real execution mode has been removed for security reasons.
    """
    def __init__(self):
        pass

    async def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Analyzes the file using safe static string extraction.
        This method does NOT execute files - it only extracts strings and generates simulated events.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        return self._simulate_sandbox_analysis(file_path)

    def _simulate_sandbox_analysis(self, file_path: str) -> List[Dict[str, Any]]:
        """
        SAFE MODE: Extracts strings from the executable and generates pseudo-events.
        This allows detecting 'intent' without execution.
        """
        logger.info(f"Running in safe simulated sandbox mode for {file_path}")
        captured_events = []
        # Use basename to prevent path traversal attacks
        filename = os.path.basename(file_path)
        # Sanitize filename to prevent injection
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        # 1. Extract strings from file
        try:
            strings = self._extract_strings(file_path)
            
            # 2. Heuristic generation of events based on strings
            # If we find "powershell", we generate a Process Creation event for PowerShell
            
            # Common suspicious strings to map to events
            suspicious_indicators = {
                "powershell": {"EventID": 4688, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -enc <PAYLOAD>"},
                "cmd.exe": {"EventID": 4688, "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c <COMMAND>"},
                "whoami": {"EventID": 4688, "CommandLine": "whoami /all"},
                "net user": {"EventID": 4688, "CommandLine": "net user admin /add"},
                "reg add": {"EventID": 4688, "CommandLine": "reg add HKLM\\Software\\..."},
                "bitsadmin": {"EventID": 4688, "CommandLine": "bitsadmin /transfer ..."},
                "certutil": {"EventID": 4688, "CommandLine": "certutil -urlcache ..."},
                "schtasks": {"EventID": 4688, "CommandLine": "schtasks /create ..."}
            }
            
            # Add a default execution event for the file itself
            captured_events.append({
                "EventID": 4688,
                "Image": f"C:\\Users\\User\\Downloads\\{filename}",
                "CommandLine": f".\\{filename}",
                "ProcessId": str(random.randint(1000, 9999)),
                "ParentProcessId": str(random.randint(1000, 9999)),
                "TimeCreated": datetime.now().isoformat()
            })
            
            # Scan extracted strings against indicators
            # Combine all strings for faster search
            full_content = " ".join(strings).lower()
            
            for indicator, event_template in suspicious_indicators.items():
                if indicator in full_content:
                    # Create a new event based on template
                    evt = event_template.copy()
                    evt["TimeCreated"] = datetime.now().isoformat()
                    evt["ProcessId"] = str(random.randint(1000, 9999))
                    
                    # Inject found context if possible (simple simulation)
                    if "<COMMAND>" in evt.get("CommandLine", ""):
                        evt["CommandLine"] = evt["CommandLine"].replace("<COMMAND>", "detected_command")
                        
                    captured_events.append(evt)
            
            # If we found encoded strings or base64, maybe add a generic suspicious event
            if "base64" in full_content:
                captured_events.append({
                    "EventID": 4104, # PowerShell Script Block
                    "ScriptBlockText": "FromBase64String",
                    "TimeCreated": datetime.now().isoformat()
                })

        except Exception as e:
            logger.error(f"Simulation failed: {e}")
            
        return captured_events

    def _extract_strings(self, file_path: str, min_len=4) -> List[str]:
        """
        Extract printable strings from binary file.
        Limits file size to prevent memory issues.
        """
        strings = []
        try:
            # Check file size before reading
            file_size = os.path.getsize(file_path)
            if file_size > settings.MAX_FILE_SIZE:
                logger.warning(f"File {file_path} exceeds size limit ({file_size} > {settings.MAX_FILE_SIZE})")
                raise ValueError(f"File too large: {file_size} bytes (max: {settings.MAX_FILE_SIZE} bytes)")
            
            with open(file_path, "rb") as f:
                content = f.read()
                
                # Double-check content size
                if len(content) > settings.MAX_FILE_SIZE:
                    raise ValueError(f"File content too large: {len(content)} bytes")
                
                # Limit string extraction to prevent memory issues
                MAX_STRING_LENGTH = 10000  # Maximum length for a single string
                MAX_TOTAL_STRINGS = 100000  # Maximum total strings to extract
                
                # Regex to find ASCII and Unicode strings
                # ASCII
                ascii_strings = re.findall(b"[\x20-\x7e]{" + str(min_len).encode() + b",}", content)
                # Unicode (Basic)
                unicode_strings = re.findall(b"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + b",}", content)
                
                # Process ASCII strings
                for s in ascii_strings[:MAX_TOTAL_STRINGS]:
                    if len(s) <= MAX_STRING_LENGTH:
                        try:
                            strings.append(s.decode('ascii', errors='ignore'))
                        except Exception:
                            pass
                
                # Process Unicode strings
                for s in unicode_strings[:MAX_TOTAL_STRINGS]:
                    if len(s) <= MAX_STRING_LENGTH:
                        try:
                            strings.append(s.decode('utf-16le', errors='ignore'))
                        except Exception:
                            pass
                
                # Limit total strings
                if len(strings) > MAX_TOTAL_STRINGS:
                    strings = strings[:MAX_TOTAL_STRINGS]
                    logger.warning(f"Limited string extraction to {MAX_TOTAL_STRINGS} strings")
                    
        except ValueError as e:
            logger.error(f"String extraction validation error: {e}")
            raise
        except Exception as e:
            logger.error(f"String extraction error: {e}", exc_info=True)
            raise
            
        return strings
