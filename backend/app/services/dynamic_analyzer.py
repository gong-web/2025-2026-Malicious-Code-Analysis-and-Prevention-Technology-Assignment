import subprocess
import time
import logging
import json
import psutil
import os
import re
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class DynamicAnalyzer:
    def __init__(self):
        self.sandbox_mode = True  # Default to safe mode for physical machines

    async def analyze_file(self, file_path: str, duration: int = 10, sandbox_mode: bool = True) -> List[Dict[str, Any]]:
        """
        Analyzes the file.
        If sandbox_mode is True: Performs static string extraction to simulate events (SAFE).
        If sandbox_mode is False: Executes the file on host system (DANGEROUS).
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        self.sandbox_mode = sandbox_mode
        
        if self.sandbox_mode:
            return self._simulate_sandbox_analysis(file_path)
        else:
            return self._execute_real_analysis(file_path, duration)

    def _simulate_sandbox_analysis(self, file_path: str) -> List[Dict[str, Any]]:
        """
        SAFE MODE: Extracts strings from the executable and generates pseudo-events.
        This allows detecting 'intent' without execution.
        """
        logger.info(f"Running in SIMULATED SANDBOX mode for {file_path}")
        captured_events = []
        filename = os.path.basename(file_path)
        
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
        Extract printable strings from binary file
        """
        strings = []
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                # Regex to find ASCII and Unicode strings
                # ASCII
                ascii_strings = re.findall(b"[\x20-\x7e]{" + str(min_len).encode() + b",}", content)
                # Unicode (Basic)
                unicode_strings = re.findall(b"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + b",}", content)
                
                for s in ascii_strings:
                    strings.append(s.decode('ascii'))
                for s in unicode_strings:
                    strings.append(s.decode('utf-16le'))
                    
        except Exception as e:
            logger.error(f"String extraction error: {e}")
            
        return strings

    def _execute_real_analysis(self, file_path: str, duration: int) -> List[Dict[str, Any]]:
        """
        DANGEROUS: Real execution on host.
        """
        # 1. Mark start time
        start_time = datetime.now() - timedelta(seconds=1) # Buffer
        
        proc = None
        captured_events = []
        filename = os.path.basename(file_path)
        
        try:
            # 2. Execute the file
            logger.warning(f"Starting REAL dynamic analysis for {file_path}")
            proc = subprocess.Popen(
                [file_path], 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NEW_CONSOLE # Create in new window/console
            )
            
            pid = proc.pid
            
            # 3. Wait for behavior to occur
            logger.info(f"Process {pid} started. Waiting {duration} seconds...")
            time.sleep(duration)
            
        except Exception as e:
            logger.error(f"Execution failed: {e}")
        finally:
            # 4. Terminate process
            if proc:
                try:
                    parent = psutil.Process(proc.pid)
                    for child in parent.children(recursive=True):
                        child.kill()
                    parent.kill()
                    logger.info(f"Process {proc.pid} terminated.")
                except psutil.NoSuchProcess:
                    pass
                except Exception as e:
                    logger.error(f"Failed to kill process: {e}")

        # 5. Collect Logs
        captured_events = self._fetch_windows_events(start_time, filename)
        
        return captured_events

    def _fetch_windows_events(self, start_time: datetime, filename: str) -> List[Dict[str, Any]]:
        """
        Uses PowerShell to fetch relevant logs (Sysmon or Security)
        """
        events = []
        
        ps_script = f"""
        $StartTime = (Get-Date).AddSeconds(-{ (datetime.now() - start_time).seconds + 10 })
        
        # Try Sysmon
        try {{
            $events = Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$StartTime}} -ErrorAction Stop
            foreach ($evt in $events) {{
                $xml = [xml]$evt.ToXml()
                $data = @{{}}
                foreach ($d in $xml.Event.EventData.Data) {{
                    $data[$d.Name] = $d.'#text'
                }}
                $data['EventID'] = $evt.Id
                $data['TimeCreated'] = $evt.TimeCreated
                $data['Provider'] = $evt.ProviderName
                
                if ($data['Image'] -like "*{filename}*" -or $data['CommandLine'] -like "*{filename}*") {{
                    Write-Output ($data | ConvertTo-Json -Compress)
                }}
            }}
        }} catch {{
            # Fallback to Security Log
            try {{
                $events = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4688; StartTime=$StartTime}} -ErrorAction Stop
                foreach ($evt in $events) {{
                    $xml = [xml]$evt.ToXml()
                    $data = @{{}}
                    foreach ($d in $xml.Event.EventData.Data) {{
                        $data[$d.Name] = $d.'#text'
                    }}
                    $data['EventID'] = $evt.Id
                    
                    if ($data['NewProcessName'] -like "*{filename}*" -or $data['CommandLine'] -like "*{filename}*") {{
                        Write-Output ($data | ConvertTo-Json -Compress)
                    }}
                }}
            }} catch {{}}
        }}
        """
        
        try:
            cmd = ["powershell", "-Command", ps_script]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            for line in result.stdout.splitlines():
                if line.strip():
                    try:
                        evt = json.loads(line)
                        normalized = self._normalize_event(evt)
                        events.append(normalized)
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logger.error(f"Log collection failed: {e}")
            
        return events

    def _normalize_event(self, raw_event: Dict) -> Dict:
        evt = raw_event.copy()
        if 'NewProcessName' in evt:
            evt['Image'] = evt['NewProcessName']
        if 'ProcessId' not in evt and 'NewProcessId' in evt:
            evt['ProcessId'] = evt['NewProcessId']
        if 'CommandLine' not in evt:
            evt['CommandLine'] = ""
        return evt
