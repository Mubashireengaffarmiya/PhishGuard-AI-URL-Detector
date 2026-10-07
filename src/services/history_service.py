"""
History Service for PhishGuard AI.
Wraps persistent SQLite scan database, applies configurable privacy redaction,
supports filtering and searching, and generates CSV/JSON data exports.
"""

from typing import List, Dict, Any, Optional
import io
import json
import pandas as pd
from urllib.parse import urlparse

from src.database import ScanDatabase
from src.services.prediction_service import get_database
from src.utils import setup_logger

logger = setup_logger("HistoryService")


class HistoryService:
    """
    Manages scan audit logs, privacy redaction, and dataset exports.
    """

    def __init__(self, db: Optional[ScanDatabase] = None):
        self.db = db or get_database()

    def get_history(
        self,
        limit: int = 100,
        classification_filter: Optional[str] = None,
        search_query: Optional[str] = None,
        privacy_mode: str = "SHOW_ALL"
    ) -> List[Dict[str, Any]]:
        """
        Retrieves scan records and applies privacy redactions.
        """
        scans = self.db.get_scans(
            limit=limit,
            classification_filter=classification_filter,
            search_query=search_query
        )
        return [self._apply_privacy_mask(scan, privacy_mode) for scan in scans]

    def get_scan(self, scan_id: int, privacy_mode: str = "SHOW_ALL") -> Optional[Dict[str, Any]]:
        """Retrieves a single scan by ID with privacy masking applied."""
        scan = self.db.get_scan_by_id(scan_id)
        if scan:
            return self._apply_privacy_mask(scan, privacy_mode)
        return None

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Returns database-derived aggregate statistics for dashboard visualization."""
        return self.db.get_dashboard_metrics()

    def clear_all_history(self) -> int:
        """Deletes all saved scan records."""
        return self.db.clear_history()

    def export_csv(self, privacy_mode: str = "SHOW_ALL") -> str:
        """Generates a CSV string of all scan audit logs."""
        scans = self.get_history(limit=5000, privacy_mode=privacy_mode)
        if not scans:
            return "id,timestamp,classification,risk_score,display_url\n"
        df = pd.DataFrame(scans)
        # Drop raw JSON string to keep CSV clean
        if "features_json" in df.columns:
            df = df.drop(columns=["features_json"])
        if "features" in df.columns:
            df = df.drop(columns=["features"])
        return df.to_csv(index=False)

    def export_json(self, privacy_mode: str = "SHOW_ALL") -> str:
        """Generates an audit JSON dump of all scan records."""
        scans = self.get_history(limit=5000, privacy_mode=privacy_mode)
        return json.dumps(scans, indent=2, default=str)

    def _apply_privacy_mask(self, scan: Dict[str, Any], privacy_mode: str) -> Dict[str, Any]:
        """Redacts sensitive URL components according to user privacy preference."""
        record = dict(scan)
        raw_url = record.get("url", "")
        norm_url = record.get("normalized_url", "")

        record["display_url"] = self.mask_url(raw_url, privacy_mode)
        record["display_normalized_url"] = self.mask_url(norm_url, privacy_mode)
        return record

    @staticmethod
    def mask_url(url_str: str, privacy_mode: str) -> str:
        """Helper to redact URL strings based on selected privacy mode."""
        if not url_str or privacy_mode == "SHOW_ALL":
            return url_str

        parsed = urlparse(url_str)
        if privacy_mode == "MASK_QUERY":
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.netloc else url_str
        elif privacy_mode == "MASK_PATH":
            return f"{parsed.scheme}://{parsed.netloc}/***" if parsed.netloc else url_str
        elif privacy_mode == "MASK_ALL":
            host = parsed.hostname or "domain"
            masked_host = host[:3] + "****" + host[-3:] if len(host) > 6 else "****"
            return f"{parsed.scheme}://{masked_host}/***"
        return url_str
