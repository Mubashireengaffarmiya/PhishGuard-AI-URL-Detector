"""
Database module for PhishGuard AI.
Manages persistent SQLite scan history, parameterized queries,
search and filtering, aggregate dashboard analytics, and history cleanup.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from src.config import DATABASE_PATH
from src.utils import setup_logger

logger = setup_logger("Database")


class ScanDatabase:
    """
    Thread-safe SQLite manager for URL scan audit logs and aggregate analytics.
    """

    def __init__(self, db_path: Path = DATABASE_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """
        Returns a SQLite connection with row_factory enabled.
        """
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """
        Creates required tables and indexes if they do not exist.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    normalized_url TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    lr_prediction TEXT NOT NULL,
                    dt_prediction TEXT NOT NULL,
                    rf_prediction TEXT NOT NULL,
                    ensemble_prob REAL NOT NULL,
                    reason_summary TEXT,
                    features_json TEXT
                );
            """)
            # Create indexes for fast filtering and searching
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_classification ON scans(classification);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk_score ON scans(risk_score);")
            conn.commit()
            logger.info(f"Database initialized at: {self.db_path}")

    def save_scan(
        self,
        url: str,
        normalized_url: str,
        classification: str,
        risk_score: float,
        lr_prediction: str,
        dt_prediction: str,
        rf_prediction: str,
        ensemble_prob: float,
        reason_summary: str,
        features: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Saves a scan record and returns the newly generated scan ID.
        """
        now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        feat_str = json.dumps(features) if features else "{}"

        query = """
            INSERT INTO scans (
                url, normalized_url, timestamp, classification, risk_score,
                lr_prediction, dt_prediction, rf_prediction, ensemble_prob,
                reason_summary, features_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (
                url, normalized_url, now_iso, classification, risk_score,
                lr_prediction, dt_prediction, rf_prediction, ensemble_prob,
                reason_summary, feat_str
            ))
            conn.commit()
            scan_id = cursor.lastrowid
            assert scan_id is not None
            logger.info(f"Saved scan record #{scan_id} for URL: {url[:50]}")
            return scan_id

    def get_scan_by_id(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieves a single scan record by ID.
        """
        query = "SELECT * FROM scans WHERE id = ?;"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (scan_id,))
            row = cursor.fetchone()
            if row:
                d = dict(row)
                d["features"] = json.loads(d.get("features_json") or "{}")
                return d
            return None

    def get_scans(
        self,
        limit: int = 100,
        offset: int = 0,
        classification_filter: Optional[str] = None,
        search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieves scan records with optional search and classification filtering.
        """
        conditions = []
        params: List[Any] = []

        if classification_filter and classification_filter.upper() != "ALL":
            conditions.append("classification = ?")
            params.append(classification_filter.upper())

        if search_query:
            conditions.append("(url LIKE ? OR normalized_url LIKE ? OR reason_summary LIKE ?)")
            pattern = f"%{search_query.strip()}%"
            params.extend([pattern, pattern, pattern])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM scans {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["features"] = json.loads(d.get("features_json") or "{}")
                results.append(d)
            return results

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """
        Computes real database-derived summary metrics for the dashboard.
        Never returns hardcoded or fake statistics.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Total scans
            cursor.execute("SELECT COUNT(*) FROM scans;")
            total_scans = cursor.fetchone()[0]

            if total_scans == 0:
                return {
                    "total_scans": 0,
                    "safe_count": 0,
                    "suspicious_count": 0,
                    "phishing_count": 0,
                    "average_risk_score": 0.0,
                    "classification_distribution": {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING": 0},
                    "risk_distribution": {"0-29 (Safe)": 0, "30-69 (Suspicious)": 0, "70-100 (Phishing)": 0},
                    "recent_activity": []
                }

            # Counts by classification
            cursor.execute("SELECT classification, COUNT(*) FROM scans GROUP BY classification;")
            class_counts = dict(cursor.fetchall())
            safe_count = class_counts.get("SAFE", 0)
            suspicious_count = class_counts.get("SUSPICIOUS", 0)
            phishing_count = class_counts.get("PHISHING", 0)

            # Model Divergences (lr != dt or dt != rf or lr != rf)
            cursor.execute("""
                SELECT COUNT(*) FROM scans 
                WHERE (lr_prediction != dt_prediction OR dt_prediction != rf_prediction OR lr_prediction != rf_prediction);
            """)
            disagreement_count = cursor.fetchone()[0]

            # Average Phishing Probability (ensemble_prob)
            cursor.execute("SELECT AVG(ensemble_prob) FROM scans;")
            avg_prob_val = cursor.fetchone()[0]
            avg_phishing_prob = round(float(avg_prob_val or 0.0), 4)

            # Average risk score
            cursor.execute("SELECT AVG(risk_score) FROM scans;")
            avg_score = round(float(cursor.fetchone()[0] or 0.0), 1)

            # Risk buckets
            cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_score < 30;")
            bucket_safe = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_score >= 30 AND risk_score < 70;")
            bucket_suspicious = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_score >= 70;")
            bucket_phishing = cursor.fetchone()[0]

            # Recent scans (last 10)
            cursor.execute("SELECT id, url, classification, risk_score, timestamp FROM scans ORDER BY id DESC LIMIT 10;")
            recent = [dict(r) for r in cursor.fetchall()]

            return {
                "total_scans": total_scans,
                "safe_count": safe_count,
                "suspicious_count": suspicious_count,
                "phishing_count": phishing_count,
                "disagreement_count": disagreement_count,
                "avg_phishing_prob": avg_phishing_prob,
                "average_risk_score": avg_score,
                "classification_distribution": {
                    "SAFE": safe_count,
                    "SUSPICIOUS": suspicious_count,
                    "PHISHING": phishing_count
                },
                "risk_distribution": {
                    "0-29 (Safe)": bucket_safe,
                    "30-69 (Suspicious)": bucket_suspicious,
                    "70-100 (Phishing)": bucket_phishing
                },
                "recent_activity": recent
            }

    def clear_history(self) -> int:
        """
        Deletes all scan records from the database.
        Returns the number of deleted records.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM scans;")
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM scans;")
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='scans';")
            conn.commit()
            logger.info(f"Cleared {count} records from scan history.")
            return count
