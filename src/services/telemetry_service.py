"""
Telemetry Service for PhishGuard AI.
Tracks real-time session telemetry: URL scans, classification outcomes,
model divergences, average phishing probabilities, and multi-modal intake events.
Grounds all dashboard metrics strictly in actual application activity.
"""

from typing import Dict, Any, List, Optional
import copy

from src.utils import setup_logger

logger = setup_logger("TelemetryService")

DEFAULT_SESSION_STATS: Dict[str, Any] = {
    "total_scans": 0,
    "safe_count": 0,
    "phishing_count": 0,
    "warning_count": 0,
    "disagreement_count": 0,
    "avg_phishing_prob": 0.0,
    "image_scans": 0,
    "qr_scans": 0,
    "demo_scans": 0,
}

_TELEMETRY_INSTANCE: Optional["TelemetryService"] = None


def get_telemetry_service() -> "TelemetryService":
    """Returns singleton TelemetryService instance."""
    global _TELEMETRY_INSTANCE
    if _TELEMETRY_INSTANCE is None:
        _TELEMETRY_INSTANCE = TelemetryService()
    return _TELEMETRY_INSTANCE


class TelemetryService:
    """
    Thread-safe session telemetry coordinator.
    Interfaces seamlessly with Streamlit session_state during live app execution
    and supports in-memory testing for unit tests.
    """

    def __init__(self, session_stats: Optional[Dict[str, Any]] = None):
        self._stats = session_stats if session_stats is not None else dict(DEFAULT_SESSION_STATS)
        self._phishing_probs: List[float] = []
        self._session_scans: List[Dict[str, Any]] = []
        self._recorded_scan_ids: set = set()

    @staticmethod
    def _is_streamlit_running() -> bool:
        """Checks if Streamlit runtime is active without triggering scriptrunner warnings."""
        try:
            from streamlit.runtime import exists
            return exists()
        except Exception:
            return False

    def _get_target_stats(self, session_stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Resolves target session_stats dictionary from argument, streamlit session_state, or internal dict."""
        if session_stats is not None:
            return session_stats
        if self._is_streamlit_running():
            try:
                import streamlit as st
                if "session_stats" not in st.session_state:
                    st.session_state["session_stats"] = dict(DEFAULT_SESSION_STATS)
                return st.session_state["session_stats"]
            except Exception:
                pass
        return self._stats

    def _get_session_probs(self) -> List[float]:
        if self._is_streamlit_running():
            try:
                import streamlit as st
                if "_session_phish_probs" not in st.session_state:
                    st.session_state["_session_phish_probs"] = []
                return st.session_state["_session_phish_probs"]
            except Exception:
                pass
        return self._phishing_probs

    def _get_session_scans(self) -> List[Dict[str, Any]]:
        if self._is_streamlit_running():
            try:
                import streamlit as st
                if "_session_scans" not in st.session_state:
                    st.session_state["_session_scans"] = []
                return st.session_state["_session_scans"]
            except Exception:
                pass
        return self._session_scans

    def _get_recorded_scan_ids(self) -> set:
        if self._is_streamlit_running():
            try:
                import streamlit as st
                if "_recorded_scan_ids" not in st.session_state:
                    st.session_state["_recorded_scan_ids"] = set()
                return st.session_state["_recorded_scan_ids"]
            except Exception:
                pass
        return self._recorded_scan_ids

    def sync_with_database(self, db_or_history: Any, session_stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Synchronizes telemetry state with real scan records from the persistent database.
        Ensures telemetry accurately reflects all actual completed scans upon startup or refresh.
        """
        stats = self._get_target_stats(session_stats)
        if hasattr(db_or_history, "get_dashboard_metrics"):
            metrics = db_or_history.get_dashboard_metrics()
        elif hasattr(db_or_history, "get_summary_metrics"):
            metrics = db_or_history.get_summary_metrics()
        else:
            return stats

        total_db = metrics.get("total_scans", 0)
        # If database has scans and session is currently at 0 (or behind), synchronize
        if total_db > 0 and stats.get("total_scans", 0) < total_db:
            stats["total_scans"] = total_db
            stats["safe_count"] = metrics.get("safe_count", 0)
            stats["phishing_count"] = metrics.get("phishing_count", 0)
            stats["warning_count"] = metrics.get("suspicious_count", 0)
            stats["disagreement_count"] = metrics.get("disagreement_count", 0)
            stats["avg_phishing_prob"] = metrics.get("avg_phishing_prob", 0.0)

            # Record any existing IDs to prevent double counting
            recorded_ids = self._get_recorded_scan_ids()
            recent = metrics.get("recent_activity", [])
            for r in recent:
                if isinstance(r, dict) and "id" in r:
                    recorded_ids.add(r["id"])

            logger.info(f"Synchronized telemetry with database ({total_db} total real scans).")
        return stats

    def record_url_scan(
        self,
        scan_result: Dict[str, Any],
        session_stats: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Records a successfully completed URL scan event in telemetry.
        Updates URLs Scanned (Session), Safe/Phishing/Warning counts,
        Model Divergences, and Average Phishing Probability.
        Strictly prevents double-counting by scan ID deduplication.

        Args:
            scan_result: Result dictionary returned by PredictionService.analyze_url
            session_stats: Optional dictionary to update directly

        Returns:
            Updated session statistics dictionary
        """
        if not isinstance(scan_result, dict):
            logger.warning("record_url_scan called with invalid scan_result; ignored.")
            return self._get_target_stats(session_stats)

        classification = scan_result.get("classification")
        if not classification:
            logger.warning("scan_result missing classification; scan not successfully completed.")
            return self._get_target_stats(session_stats)

        stats = self._get_target_stats(session_stats)
        session_scans = self._get_session_scans()
        probs = self._get_session_probs()
        recorded_ids = self._get_recorded_scan_ids()

        scan_id = scan_result.get("scan_id")
        # Idempotency check: if this specific persistent scan ID was already recorded, do not duplicate
        if scan_id and isinstance(scan_id, int) and scan_id > 0:
            if scan_id in recorded_ids:
                return stats
            recorded_ids.add(scan_id)

        # 1. Increment URLs Scanned (Session) exactly once
        stats["total_scans"] = stats.get("total_scans", 0) + 1

        # 2 & 3. Safe Classifications / Phishing Alerts / Suspicious
        cls_upper = str(classification).upper()
        if cls_upper == "SAFE":
            stats["safe_count"] = stats.get("safe_count", 0) + 1
        elif cls_upper == "PHISHING":
            stats["phishing_count"] = stats.get("phishing_count", 0) + 1
        elif cls_upper == "SUSPICIOUS":
            stats["warning_count"] = stats.get("warning_count", 0) + 1

        # 4. Model Divergences (using existing model-disagreement condition)
        ensemble = scan_result.get("ensemble", {})
        has_disagreement = False
        if isinstance(ensemble, dict) and "has_disagreement" in ensemble:
            has_disagreement = bool(ensemble["has_disagreement"])
        elif "individual_predictions" in scan_result:
            indiv = scan_result["individual_predictions"]
            labels = {
                p.get("label") for p in indiv.values()
                if isinstance(p, dict) and "label" in p
            }
            has_disagreement = len(labels) > 1

        if has_disagreement:
            stats["disagreement_count"] = stats.get("disagreement_count", 0) + 1

        # 5. Average Phish Probability
        phish_prob = float(ensemble.get("phishing_probability", 0.0)) if isinstance(ensemble, dict) else 0.0
        probs.append(phish_prob)
        if probs:
            stats["avg_phishing_prob"] = sum(probs) / len(probs)
        else:
            stats["avg_phishing_prob"] = phish_prob

        # Track scan record
        session_scans.append(scan_result)

        logger.info(
            f"Recorded URL scan #{stats['total_scans']} ({cls_upper}) | "
            f"Safe: {stats['safe_count']}, Phish: {stats['phishing_count']}, "
            f"Divergences: {stats['disagreement_count']}, AvgProb: {stats['avg_phishing_prob']:.4f}"
        )

        return stats

    def record_image_scan(self, session_stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Increments OCR / Image Scans counter exactly once for a successfully completed image scan.
        """
        stats = self._get_target_stats(session_stats)
        stats["image_scans"] = stats.get("image_scans", 0) + 1
        logger.info(f"Recorded image/OCR scan event. Total: {stats['image_scans']}")
        return stats

    def record_qr_scan(self, session_stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Increments QR Decodings counter exactly once for a successfully completed QR decode.
        """
        stats = self._get_target_stats(session_stats)
        stats["qr_scans"] = stats.get("qr_scans", 0) + 1
        logger.info(f"Recorded QR decode event. Total: {stats['qr_scans']}")
        return stats

    def record_demo_scan(self, session_stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Increments Faculty Demos Loaded counter exactly once when a demo scenario is loaded and evaluated.
        """
        stats = self._get_target_stats(session_stats)
        stats["demo_scans"] = stats.get("demo_scans", 0) + 1
        logger.info(f"Recorded faculty demo load event. Total: {stats['demo_scans']}")
        return stats

    def get_session_stats(self, session_stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Returns the current session statistics dictionary."""
        return self._get_target_stats(session_stats)

    def reset_session(self, session_stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Resets all session statistics to zero."""
        stats = self._get_target_stats(session_stats)
        for k, v in DEFAULT_SESSION_STATS.items():
            stats[k] = copy.deepcopy(v)
        self._phishing_probs.clear()
        self._session_scans.clear()
        self._recorded_scan_ids.clear()
        if self._is_streamlit_running():
            try:
                import streamlit as st
                if "_session_phish_probs" in st.session_state:
                    st.session_state["_session_phish_probs"] = []
                if "_session_scans" in st.session_state:
                    st.session_state["_session_scans"] = []
                if "_recorded_scan_ids" in st.session_state:
                    st.session_state["_recorded_scan_ids"] = set()
            except Exception:
                pass
        logger.info("Reset session telemetry statistics.")
        return stats
