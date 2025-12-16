import logging
import time
from typing import Any, Dict, List, Optional

import requests

from app.core.config import settings

logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)


class VirusTotalClient:
    """
    Minimal wrapper for VirusTotal Public API v3.

    Focuses on fetching sandbox behaviour_summary and normalizing it into
    Sigma-like event dicts so they can be scanned by the SigmaEngine.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = settings.VT_API_BASE_URL,
        max_calls_per_minute: int = 4,
        max_cache_size: int = 1000,  # Limit cache size
    ):
        self.api_key = api_key or settings.VT_API_KEY
        self.base_url = base_url.rstrip("/")
        self.max_calls_per_minute = max_calls_per_minute
        self.max_cache_size = max_cache_size
        self._call_timestamps: List[float] = []
        self._cache: Dict[str, Dict[str, Any]] = {}

        if not self.api_key or not self.api_key.strip():
            logger.warning("VirusTotal API key is not configured; VT features disabled.")

        self.session = requests.Session()
        self.session.headers.update(
            {
                "x-apikey": self.api_key or "",
                "User-Agent": "local-av-sigma/0.1",
            }
        )

    def _throttle(self):
        """
        Enforce VT public rate limit (4 req/min). Sleep if needed.
        """
        now = time.time()
        # Drop old timestamps
        self._call_timestamps = [t for t in self._call_timestamps if now - t < 60]
        if len(self._call_timestamps) >= self.max_calls_per_minute:
            sleep_for = 60 - (now - self._call_timestamps[0])
            logger.info(f"VT rate limit reached; sleeping {sleep_for:.1f}s")
            time.sleep(max(0, sleep_for))
        self._call_timestamps.append(time.time())

    def fetch_behaviour_summary(self, file_hash: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Get behaviour summary for a file hash (sha256/sha1/md5).
        Returns {} if not found or errors.
        """
        if not self.api_key or not self.api_key.strip():
            raise RuntimeError("VT API key is missing. Set VT_API_KEY in environment.")
        
        # Normalize hash to lowercase
        file_hash = file_hash.lower().strip()
        
        # Validate hash format
        if not file_hash or len(file_hash) < 32:
            raise ValueError(f"Invalid hash format: {file_hash}")

        if use_cache and file_hash in self._cache:
            logger.debug(f"Using cached VT data for {file_hash}")
            return self._cache[file_hash]

        url = f"{self.base_url}/files/{file_hash}/behaviour_summary"
        try:
            self._throttle()
            resp = self.session.get(url, timeout=20)
            if resp.status_code == 404:
                logger.warning(f"VT behaviour not found for {file_hash}")
                return {}
            if resp.status_code == 401 or resp.status_code == 403:
                raise RuntimeError(
                    f"VirusTotal authentication failed ({resp.status_code}). Check API key/quotas."
                )
            if resp.status_code == 429:
                raise RuntimeError(
                    "VirusTotal rate limit exceeded. Please wait before retrying."
                )
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict) and isinstance(data.get("data"), dict):
                attributes = data["data"].get("attributes", {}) or {}
                if use_cache and attributes:
                    # Limit cache size
                    if len(self._cache) >= self.max_cache_size:
                        # Remove oldest entry (simple FIFO)
                        oldest_key = next(iter(self._cache))
                        del self._cache[oldest_key]
                    self._cache[file_hash] = attributes
                return attributes
            return {}
        except requests.exceptions.Timeout:
            logger.error(f"VT API timeout for {file_hash}")
            raise RuntimeError("VirusTotal API request timed out")
        except requests.exceptions.RequestException as e:
            logger.error(f"VT API request failed for {file_hash}: {e}")
            raise RuntimeError(f"VirusTotal API request failed: {str(e)}")
        except Exception as e:
            logger.error(f"VT fetch failed for {file_hash}: {e}", exc_info=True)
            raise

    def normalize_behaviour(self, behaviour: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert VT behaviour summary into Sigma-friendly events.
        Uses Sysmon-like EventIDs to align with common Sigma rules.
        """
        if not behaviour:
            return []

        events: List[Dict[str, Any]] = []
        source = "vt_sandbox"

        # Processes -> Sysmon EventID 1 (Process Create)
        for proc in behaviour.get("processes", []) or []:
            events.append(
                {
                    "EventID": 1,
                    "Image": proc.get("image") or proc.get("process_path"),
                    "CommandLine": proc.get("command_line"),
                    "ProcessId": proc.get("pid"),
                    "ParentProcessId": proc.get("parent_pid"),
                    "CurrentDirectory": proc.get("current_directory"),
                    "User": proc.get("user"),
                    "IntegrityLevel": proc.get("integrity_level"),
                    "Source": source,
                }
            )

        # Registry -> Sysmon EventID 13
        for reg in behaviour.get("registry", []) or []:
            events.append(
                {
                    "EventID": 13,
                    "Image": reg.get("process") or reg.get("process_path"),
                    "ProcessId": reg.get("pid"),
                    "TargetObject": reg.get("key") or reg.get("path"),
                    "Details": reg.get("value") or reg.get("data"),
                    "Action": reg.get("operation"),
                    "Source": source,
                }
            )

        # Files -> Sysmon EventID 11
        for fop in behaviour.get("files", []) or []:
            events.append(
                {
                    "EventID": 11,
                    "Image": fop.get("process_path") or fop.get("process"),
                    "ProcessId": fop.get("pid"),
                    "TargetFilename": fop.get("path"),
                    "Action": fop.get("operation"),
                    "Status": fop.get("status"),
                    "Source": source,
                }
            )

        network = behaviour.get("network") or {}

        # TCP/UDP connections -> Sysmon EventID 3
        for conn in (
            network.get("connections")
            or network.get("tcp")
            or network.get("udp")
            or []
        ):
            events.append(
                {
                    "EventID": 3,
                    "Image": conn.get("process_path") or conn.get("process"),
                    "ProcessId": conn.get("pid"),
                    "SourceAddress": conn.get("src") or conn.get("src_ip"),
                    "SourcePort": conn.get("src_port"),
                    "DestAddress": conn.get("dst") or conn.get("dst_ip"),
                    "DestPort": conn.get("dst_port"),
                    "Protocol": conn.get("protocol"),
                    "Direction": conn.get("direction"),
                    "Source": source,
                }
            )

        # DNS -> EventID 22 (Sysmon DNS event)
        for dns in network.get("dns", []) or []:
            events.append(
                {
                    "EventID": 22,
                    "Image": dns.get("process_path") or dns.get("process"),
                    "ProcessId": dns.get("pid"),
                    "QueryName": dns.get("hostname") or dns.get("request"),
                    "DestAddress": dns.get("resolved_ips") or dns.get("answers"),
                    "Source": source,
                }
            )

        # HTTP(s) -> treat as network EventID 3 with URL context
        for http in network.get("http", []) or []:
            events.append(
                {
                    "EventID": 3,
                    "Image": http.get("process_path") or http.get("process"),
                    "ProcessId": http.get("pid"),
                    "DestAddress": http.get("host") or http.get("dst_ip"),
                    "DestPort": http.get("port") or http.get("dst_port"),
                    "Url": http.get("url"),
                    "UserAgent": http.get("user_agent"),
                    "Method": http.get("method"),
                    "Source": source,
                }
            )

        # Drop None-only events
        cleaned = []
        for evt in events:
            # Keep if it has any non-null value besides EventID/Source
            if any(v for k, v in evt.items() if k not in ["EventID", "Source"]):
                cleaned.append(evt)

        return cleaned


# Singleton helper
_vt_client: Optional[VirusTotalClient] = None


def get_vt_client() -> VirusTotalClient:
    global _vt_client
    if _vt_client is None:
        _vt_client = VirusTotalClient()
    return _vt_client

